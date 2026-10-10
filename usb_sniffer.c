// SPDX-License-Identifier: BSD-3-Clause
// USB Sniffer capture library (ataradov FX2LP).
//
// The frame parser and the FX2LP transport (EP0 vendor control + EP 0x82 raw
// frame stream) live in this one file; the usbpv capture-plugin ABI is at the
// bottom.
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L   /* nanosleep / clock_gettime */
#endif
#include "usb_sniffer.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif
#include <libusb.h>
#include <pthread.h>

/*- Frame format constants ---------------------------------------------------*/
#define LINKTYPE_USB_2_0             288
#define LINKTYPE_USB_2_0_LOW_SPEED   293
#define LINKTYPE_USB_2_0_FULL_SPEED  294
#define LINKTYPE_USB_2_0_HIGH_SPEED  295

#define TIME_US                        1000
#define TIME_MS                        (1000 * TIME_US)
#define UPDATE_INTERVAL                (2000 * TIME_MS)

#define DATA_HEADER_SIZE               7
#define STATUS_HEADER_SIZE             4
#define DATA_BUF_SIZE                  2048
#define FOLD_BUF_SIZE                  256
#define MAX_DATA_SIZE                  1280

#define HEADER_STATUS                  0x80
#define HEADER_TOGGLE                  0x40
#define HEADER_ZERO                    0x20
#define HEADER_TS_OVERFLOW             0x10

#define HEADER_OVERFLOW                0x08   /* byte 3, data frames  */
#define HEADER_CRC_ERROR               0x10
#define HEADER_DATA_ERROR              0x20

#define HEADER_LS_OFFS                 0      /* byte 3, status frames */
#define HEADER_LS_MASK                 0x0f
#define HEADER_VBUS                    0x10
#define HEADER_TRIGGER                 0x20
#define HEADER_SPEED_OFFS              6
#define HEADER_SPEED_MASK              0x03

#define PID_SOF                        0xa5
#define PID_IN                         0x69
#define PID_NAK                        0x5a

#define FOLD_LIMIT_LS_FS               1000
#define FOLD_LIMIT_HS                  8000

#define MIN_KEEPALIVE_DURATION         1000   /* 1 us */
#define MAX_KEEPALIVE_DURATION         2000   /* 2 us */

#define LS_INVALID                     -1
#define LS_SE0                         0
#define LS_J3                          12
#define LS_DELTA_THRESHOLD             (10 * TIME_MS)

#define CAPTURE_SPEED_RESET            3      /* status frame "reset" speed */

#define SPEED_LS                       0
#define SPEED_FS                       1
#define SPEED_HS                       2

/*- Product string (device identification) ----------------------------------*/
#define SNIFFER_PRODUCT                "USB Sniffer"

/*- sniffer (FX2LP) transport ------------------------------------------------*/
#define SNIFFER_DATA_ENDPOINT             0x82
#define SNIFFER_DATA_EP_SIZE              512
#define SNIFFER_TRANSFER_SIZE             (SNIFFER_DATA_EP_SIZE * 2000)
#define SNIFFER_TRANSFER_COUNT            16
#define SNIFFER_TIMEOUT_MS                250

#define CMD_CTRL                       0xd0
#define CTRL_REG_SIZE                  4

#define SNIFFER_CTRL_RESET                0
#define SNIFFER_CTRL_ENABLE               1
#define SNIFFER_CTRL_SPEED0               2
#define SNIFFER_CTRL_SPEED1               3
#define SNIFFER_CTRL_TEST                 4

#define XFER_MAX                       16   /* max async transfers in flight */

/* Raw byte queue: decouple block framing/parsing from the libusb callback so a
 * slow usbpv consumer does not stall URB reaping (device-side FIFO overflow).
 * Sized for ~50 MB/s sustained with jitter tolerance. */
#define RAWQ_SLOTS                     32
#define RAWQ_CHUNK                     (256 * 1024)

/*- Types -------------------------------------------------------------------*/
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct
{
  u64 ts;
  int size;                 /* negative = keep-alive marker (-duration) */
  u8  data[DATA_BUF_SIZE];
} fold_frame;

struct usb_sniffer
{
  usb_sniffer_speed     speed;         /* requested */
  bool                  fold_empty;
  bool                  exclude_line_state;

  usb_sniffer_packet_fn on_packet;
  usb_sniffer_event_fn  on_event;
  usb_sniffer_info_fn   on_info;
  void                 *user;
  usb_sniffer_log_fn    log;
  void                 *log_user;

  /* parser state */
  u8   data[DATA_BUF_SIZE];
  int  data_ptr;
  int  size;
  bool header;
  bool status;
  int  toggle;
  int  ls;
  int  vbus;
  int  speed_in;               /* detected speed (0..3), -1 unknown */
  bool enabled;
  u64  ts_int;
  u64  ts;
  u64  last_ts;
  bool overflow;
  bool crc_error;
  bool data_error;
  int  duration;
  int  link_type;

  fold_frame fold[FOLD_BUF_SIZE];
  int        fold_ptr;
  int        fold_count;
  int        saved_ls;
  u64        saved_ts;

  volatile int stop_requested;

  /* transport state (libusb) */
  libusb_device_handle *handle;
  struct libusb_transfer *xfer[XFER_MAX];
  u8                   *xbuf[XFER_MAX];
  int                   xfer_count;
  volatile int          closing;
  int                   xfer_pending;

  /* raw byte queue (worker thread) */
  pthread_mutex_t q_mu;
  pthread_cond_t  q_ne, q_nf;
  u8  *q_buf[RAWQ_SLOTS];
  int  q_len[RAWQ_SLOTS];
  int  q_head, q_tail, q_count;
  u8  *q_free[RAWQ_SLOTS];
  int  q_fcount;
  int  q_stop;
  int  q_running;
  pthread_t q_th;

  char err[256];
};

/*----------------------------------------------------------------------------*/
static void slog(usb_sniffer *s, const char *fmt, ...)
{
  char buf[256];
  va_list ap;

  if (!s->log)
    return;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  s->log(s->log_user, buf);
}

static void emit_packet(usb_sniffer *s, u64 ts, const u8 *data, int size)
{
  if (s->on_packet)
    s->on_packet(s->user, ts, data, size, s->link_type);
  s->last_ts = ts;
}

static void emit_info(usb_sniffer *s, u64 ts, const char *str, int size)
{
  if (s->on_info)
    s->on_info(s->user, ts, str, size);
  s->last_ts = ts;
}

static void emit_event(usb_sniffer *s, u64 ts, int type)
{
  if (s->on_event)
    s->on_event(s->user, ts, type);
}

/* The operator's explicit FS/HS selection overrides a stuck LS detector. */
static int effective_speed(const usb_sniffer *s)
{
  if ((USB_SNIFFER_SPEED_FS == s->speed || USB_SNIFFER_SPEED_HS == s->speed) &&
      SPEED_LS == s->speed_in)
    return (int)s->speed;
  return s->speed_in;
}

static int fold_limit(const usb_sniffer *s)
{
  return (SPEED_HS == effective_speed(s)) ? FOLD_LIMIT_HS : FOLD_LIMIT_LS_FS;
}

/*----------------------------------------------------------------------------*/
static void line_state_event(usb_sniffer *s);
static void stop_folding(usb_sniffer *s);
static void keepalive_event(usb_sniffer *s, u64 ts, int delta);

static void info(usb_sniffer *s, u64 ts, const char *fmt, ...)
{
  char str[512];
  va_list args;

  va_start(args, fmt);
  int len = vsnprintf(str, sizeof(str), fmt, args);
  va_end(args);

  if (len < 0) len = 0;
  if (len > (int)sizeof(str) - 1) len = (int)sizeof(str) - 1;

  line_state_event(s);
  stop_folding(s);

  emit_info(s, ts, str, len);
}

static void write_keepalive(usb_sniffer *s, u64 ts)
{
  info(s, ts, "Keep-alive");
}

static void timeout_event(usb_sniffer *s)
{
  if (s->enabled)
    info(s, s->ts, "Periodic update");
}

/*----------------------------------------------------------------------------*/
static void line_state_event(usb_sniffer *s)
{
  int dp = (s->saved_ls >> 0) & 3;
  int dm = (s->saved_ls >> 2) & 3;
  int delta = (int)(s->ts - s->saved_ts);
  char str[256];

  if (LS_INVALID == s->saved_ls)
    return;

  s->saved_ls = LS_INVALID;

  if (s->exclude_line_state)
    return;

  sprintf(str, "Line state: ");

  if (dp == 0 && dm == 0)
    strcat(str, "SE0");
  else if (dp == 0)
    strcat(str, (SPEED_LS == effective_speed(s)) ? "J" : "K");
  else if (dm == 0)
    strcat(str, (SPEED_LS == effective_speed(s)) ? "K" : "J");
  else
  {
    char buf[64];
    snprintf(buf, sizeof(buf), "Undefined (DP=%d / DM=%d)", dp, dm);
    strcat(str, buf);
  }

  if (delta < LS_DELTA_THRESHOLD)
  {
    char buf[64];

    if (delta < TIME_US)
      snprintf(buf, sizeof(buf), " (%.2f ns)", (float)delta);
    else if (delta < TIME_MS)
      snprintf(buf, sizeof(buf), " (%.2f us)", (float)delta / TIME_US);
    else
      snprintf(buf, sizeof(buf), " (%.2f ms)", (float)delta / TIME_MS);

    strcat(str, buf);
  }

  info(s, s->saved_ts, "%s", str);
}

/*----------------------------------------------------------------------------*/
static void status_event(usb_sniffer *s, int ls, int vbus, int speed)
{
  if (s->vbus != vbus)
  {
    s->vbus = vbus;
    info(s, s->ts, "VBUS %s", s->vbus ? "ON" : "OFF");
  }

  if (s->speed_in != speed)
  {
    static const char *str[] = { "Low-Speed", "Full-Speed", "High-Speed", "" };
    int prev = s->speed_in;
    s->speed_in = speed;

    s->link_type = (SPEED_LS == speed) ? LINKTYPE_USB_2_0_LOW_SPEED :
                   (SPEED_FS == speed) ? LINKTYPE_USB_2_0_FULL_SPEED :
                   (SPEED_HS == speed) ? LINKTYPE_USB_2_0_HIGH_SPEED :
                                         LINKTYPE_USB_2_0;

    if (s->enabled)
    {
      if (CAPTURE_SPEED_RESET == speed)
      {
        info(s, s->ts, "--- Bus Reset ---");
        emit_event(s, s->ts, USB_SNIFFER_EV_RESET_BEGIN);
      }
      else
      {
        info(s, s->ts, "Detected speed: %s", str[s->speed_in]);
        if (CAPTURE_SPEED_RESET == prev)
          emit_event(s, s->ts, USB_SNIFFER_EV_RESET_END);
      }
    }
  }

  if (s->ls != ls)
  {
    u64 delta = s->ts - s->saved_ts;
    bool handle = true;

    s->ls = ls;

    if (SPEED_LS == effective_speed(s) && LS_SE0 == s->saved_ls && LS_J3 == ls &&
        (MIN_KEEPALIVE_DURATION < (int)delta && (int)delta < MAX_KEEPALIVE_DURATION))
    {
      s->saved_ls = LS_INVALID;
      keepalive_event(s, s->saved_ts, (int)delta);
      handle = false;
    }

    if (handle)
    {
      line_state_event(s);
      s->saved_ls = ls;
      s->saved_ts = s->ts;
    }
  }
}

/*----------------------------------------------------------------------------*/
static void stop_folding(usb_sniffer *s)
{
  int count = s->fold_count;
  int ptr   = s->fold_ptr;

  if (0 == count && 0 == ptr)
    return;

  s->fold_count = 0;
  s->fold_ptr   = 0;

  if (count == 1)
    info(s, s->ts, "Folded empty frame");
  else if (count > 1)
    info(s, s->ts, "Folded %d empty frames", count);

  for (int i = 0; i < ptr; i++)
  {
    if (s->fold[i].size < 0)
      write_keepalive(s, s->fold[i].ts);
    else
      emit_packet(s, s->fold[i].ts, s->fold[i].data, s->fold[i].size);
  }
}

static void fold_packet(usb_sniffer *s, u64 ts, const u8 *data, int size)
{
  s->fold[s->fold_ptr].ts = ts;
  s->fold[s->fold_ptr].size = size;
  memcpy(s->fold[s->fold_ptr].data, data, size);
  s->fold_ptr++;
}

static void fold_keepalive(usb_sniffer *s, u64 ts, int delta)
{
  s->fold[s->fold_ptr].ts = ts;
  s->fold[s->fold_ptr].size = -delta;
  s->fold_ptr++;
}

/*----------------------------------------------------------------------------*/
static void keepalive_event(usb_sniffer *s, u64 ts, int delta)
{
  if (!s->enabled)
    return;

  if (!s->fold_empty)
  {
    write_keepalive(s, ts);
  }
  else if (s->fold_ptr)
  {
    s->fold_count++;
    s->fold_ptr = 0;

    if (s->fold_count == fold_limit(s))
      stop_folding(s);

    fold_keepalive(s, ts, delta);
  }
  else
  {
    fold_keepalive(s, ts, delta);
  }
}

/*----------------------------------------------------------------------------*/
static void write_packet(usb_sniffer *s, u64 ts, u8 *data, int size)
{
  emit_packet(s, ts, data, size);
}

static void data_event(usb_sniffer *s)
{
  bool data_error = s->crc_error || s->data_error;
  bool allow_sof  = (SPEED_LS != effective_speed(s));
  int pid = s->data[0];

  if (!s->enabled)
    return;

  line_state_event(s);

  if (s->overflow || data_error || FOLD_BUF_SIZE == s->fold_ptr)
    stop_folding(s);

  if (s->overflow)
  {
    info(s, s->ts, "Hardware buffer overflow");
    emit_event(s, s->ts, USB_SNIFFER_EV_OVERFLOW);
  }

  if (s->data_error)
    info(s, s->ts, "USB PHY error");

  if (data_error || !s->fold_empty)
  {
    write_packet(s, s->ts, s->data, s->size);
  }
  else if (s->fold_ptr)
  {
    if (PID_IN == pid || PID_NAK == pid)
    {
      fold_packet(s, s->ts, s->data, s->size);
    }
    else if (PID_SOF == pid && allow_sof)
    {
      s->fold_count++;
      s->fold_ptr = 0;

      if (s->fold_count == fold_limit(s))
        stop_folding(s);

      fold_packet(s, s->ts, s->data, s->size);
    }
    else
    {
      stop_folding(s);
      write_packet(s, s->ts, s->data, s->size);
    }
  }
  else
  {
    if (PID_SOF == pid && allow_sof)
      fold_packet(s, s->ts, s->data, s->size);
    else
      write_packet(s, s->ts, s->data, s->size);
  }
}

/*----------------------------------------------------------------------------*/
static void desync_error(usb_sniffer *s)
{
  info(s, s->ts, "Error: protocol desynchronization, stopping the capture");
  s->stop_requested = true;
}

static void check_header(usb_sniffer *s, int toggle, int zero)
{
  if (toggle == s->toggle && 0 == zero)
    return;

  if (toggle != s->toggle)
    info(s, s->ts, "Error: received toggle value %d, expected %d", toggle, s->toggle);

  if (zero)
    info(s, s->ts, "Error: zero bit in the header is not zero");

  desync_error(s);
}

static void check_data_size(usb_sniffer *s, int size)
{
  if (DATA_HEADER_SIZE <= size && size <= MAX_DATA_SIZE)
    return;

  info(s, s->ts, "Error: invalid data size (%d)", size);
  desync_error(s);
}

/*----------------------------------------------------------------------------*/
static void capture_sm(usb_sniffer *s, u8 byte)
{
  if (s->header && 0 == s->data_ptr)
  {
    s->status = (0 == (byte & HEADER_STATUS));
    s->size   = s->status ? STATUS_HEADER_SIZE : DATA_HEADER_SIZE;
  }

  s->data[s->data_ptr++] = byte;

  if (s->data_ptr < s->size)
    return;

  if (s->header)
  {
    int ts     = ((s->data[0] & 0xf) << 16) | (s->data[1] << 8) | s->data[2];
    int toggle = (s->data[0] & HEADER_TOGGLE) ? 1 : 0;
    int zero   = (s->data[0] & HEADER_ZERO) ? 1 : 0;

    check_header(s, toggle, zero);

    if (s->data[0] & HEADER_TS_OVERFLOW)
      s->ts_int += 0x100000;

    s->ts = ((s->ts_int | (u64)ts) * 100) / 6;   // 60 MHz ticks -> ns
    s->toggle = 1 - toggle;

    if ((s->ts - s->last_ts) > UPDATE_INTERVAL)
      timeout_event(s);

    if (s->status)
    {
      int ls    = (s->data[3] >> HEADER_LS_OFFS) & HEADER_LS_MASK;
      int vbus  = (s->data[3] & HEADER_VBUS) ? 1 : 0;
      int speed = (s->data[3] >> HEADER_SPEED_OFFS) & HEADER_SPEED_MASK;

      status_event(s, ls, vbus, speed);
    }
    else
    {
      int size = (((int)s->data[3] & 0x7) << 8) | s->data[4];

      if (size < DATA_HEADER_SIZE || size > MAX_DATA_SIZE)
      {
        // Out of range: a negative/oversized length must never reach
        // data_event()/fold_packet() (huge size_t memcpy).  check_data_size()
        // reports it and stops the capture.
        check_data_size(s, size);
        s->data_ptr = 0;
        s->header   = true;
        return;
      }

      s->size       = size - DATA_HEADER_SIZE;
      s->overflow   = (s->data[3] & HEADER_OVERFLOW)   ? true : false;
      s->crc_error  = (s->data[3] & HEADER_CRC_ERROR)  ? true : false;
      s->data_error = (s->data[3] & HEADER_DATA_ERROR) ? true : false;
      s->duration   = ((int)s->data[5] << 8) | s->data[6];
      s->header     = (0 == s->size);
    }
  }
  else
  {
    s->header = true;
    data_event(s);
  }

  s->data_ptr = 0;
}

/*----------------------------------------------------------------------------*/
void usb_sniffer_reset(usb_sniffer *s)
{
  s->data_ptr     = 0;
  s->size         = 0;
  s->header       = true;
  s->status       = false;
  s->toggle       = 0;
  s->ls           = -1;
  s->vbus         = -1;
  s->speed_in     = -1;
  s->enabled      = true;
  s->ts_int       = 0;
  s->ts           = 0;
  s->last_ts      = 0;
  s->overflow     = false;
  s->crc_error    = false;
  s->data_error   = false;
  s->duration     = 0;
  s->fold_ptr     = 0;
  s->fold_count   = 0;
  s->saved_ls     = LS_INVALID;
  s->saved_ts     = 0;
  s->link_type    = (SPEED_LS == s->speed) ? LINKTYPE_USB_2_0_LOW_SPEED :
                    (SPEED_FS == s->speed) ? LINKTYPE_USB_2_0_FULL_SPEED :
                    (SPEED_HS == s->speed) ? LINKTYPE_USB_2_0_HIGH_SPEED :
                                             LINKTYPE_USB_2_0;
  s->stop_requested = false;
}

void usb_sniffer_feed(usb_sniffer *s, const uint8_t *data, int size)
{
  for (int i = 0; i < size; i++)
  {
    if (s->stop_requested)
      break;
    capture_sm(s, data[i]);
  }
}

bool usb_sniffer_should_stop(const usb_sniffer *s)
{
  return s->stop_requested;
}

/*----------------------------------------------------------------------------*/
void usb_sniffer_set_log(usb_sniffer *s, usb_sniffer_log_fn fn, void *user)
{
  if (s)
  {
    s->log = fn;
    s->log_user = user;
  }
}

usb_sniffer *usb_sniffer_new(usb_sniffer_speed speed,
                             bool fold_empty,
                             usb_sniffer_packet_fn on_packet,
                             usb_sniffer_event_fn on_event,
                             usb_sniffer_info_fn on_info,
                             void *user)
{
  usb_sniffer *s = (usb_sniffer *)calloc(1, sizeof(usb_sniffer));
  if (!s)
    return NULL;

  s->speed             = speed;
  s->fold_empty        = fold_empty;
  s->exclude_line_state = true;
  s->on_packet         = on_packet;
  s->on_event          = on_event;
  s->on_info           = on_info;
  s->user              = user;

  usb_sniffer_reset(s);
  return s;
}

void usb_sniffer_delete(usb_sniffer *s)
{
  free(s);
}

/*============================================================================*/
/* Device identification by product string                                    */
/*============================================================================*/
static bool read_product(libusb_device *dev, char *buf, int buflen)
{
  struct libusb_device_descriptor desc;
  libusb_device_handle *h = NULL;
  int r;

  if (buflen <= 0)
    return false;

  buf[0] = 0;
  if (libusb_get_device_descriptor(dev, &desc) < 0)
    return false;
  if (desc.iProduct == 0)
    return false;
  if (libusb_open(dev, &h) < 0)
    return false;

  r = libusb_get_string_descriptor_ascii(h, desc.iProduct, (unsigned char *)buf, buflen);
  libusb_close(h);

  if (r <= 0)
    return false;

  buf[buflen - 1] = 0;
  return true;
}

/* True if the device's USB product string identifies it as our sniffer. */
static bool is_sniffer(libusb_device *dev)
{
  char p[128];

  return read_product(dev, p, sizeof(p)) && strcmp(p, SNIFFER_PRODUCT) == 0;
}

/*============================================================================*/
/* Raw byte queue: the libusb callback only memcpy()s here and returns; a      */
/* worker thread does block framing + parsing + the usbpv callback.           */
/*============================================================================*/
#ifdef USB_SNIFFER_NO_RAWQ
/* Bisection build: parse inline in the libusb callback (no worker thread). */
static void rawq_push(usb_sniffer *s, const u8 *d, int n)
{
  usb_sniffer_feed(s, d, n);
}
static bool rawq_start(usb_sniffer *s) { (void)s; return true; }
static void rawq_stop(usb_sniffer *s) { (void)s; }
#else

static void *rawq_thread(void *arg)
{
  usb_sniffer *s = (usb_sniffer *)arg;

  for (;;)
  {
    pthread_mutex_lock(&s->q_mu);
    while (s->q_count == 0 && !s->q_stop)
      pthread_cond_wait(&s->q_ne, &s->q_mu);
    if (s->q_count == 0 && s->q_stop)
    {
      pthread_mutex_unlock(&s->q_mu);
      break;
    }
    u8 *buf = s->q_buf[s->q_head];
    int len = s->q_len[s->q_head];
    s->q_head = (s->q_head + 1) % RAWQ_SLOTS;
    s->q_count--;
    pthread_cond_signal(&s->q_nf);
    pthread_mutex_unlock(&s->q_mu);

    usb_sniffer_feed(s, buf, len);

    pthread_mutex_lock(&s->q_mu);
    s->q_free[s->q_fcount++] = buf;
    pthread_mutex_unlock(&s->q_mu);
  }
  return NULL;
}

static bool rawq_start(usb_sniffer *s)
{
  pthread_mutex_init(&s->q_mu, NULL);
  pthread_cond_init(&s->q_ne, NULL);
  pthread_cond_init(&s->q_nf, NULL);

  for (int i = 0; i < RAWQ_SLOTS; i++)
  {
    s->q_buf[i] = (u8 *)malloc(RAWQ_CHUNK);
    if (!s->q_buf[i])
    {
      snprintf(s->err, sizeof(s->err), "out of memory (raw queue)");
      return false;
    }
    s->q_free[i] = s->q_buf[i];   /* the queue's free list starts with them all */
  }
  s->q_fcount = RAWQ_SLOTS;
  s->q_stop = 0;

  if (pthread_create(&s->q_th, NULL, rawq_thread, s) != 0)
  {
    snprintf(s->err, sizeof(s->err), "pthread_create (raw queue) failed");
    return false;
  }
  s->q_running = 1;
  return true;
}

static void rawq_stop(usb_sniffer *s)
{
  if (!s->q_running)
    return;

  pthread_mutex_lock(&s->q_mu);
  s->q_stop = 1;
  pthread_cond_broadcast(&s->q_ne);
  pthread_cond_broadcast(&s->q_nf);
  pthread_mutex_unlock(&s->q_mu);

  pthread_join(s->q_th, NULL);

  for (int i = 0; i < s->q_fcount; i++)
    free(s->q_free[i]);

  pthread_mutex_destroy(&s->q_mu);
  pthread_cond_destroy(&s->q_ne);
  pthread_cond_destroy(&s->q_nf);
  s->q_running = 0;
}

/* Copy raw bytes into the queue (blocks, giving backpressure, when full). */
static void rawq_push(usb_sniffer *s, const u8 *d, int n)
{
  int off = 0;

  while (off < n)
  {
    int take = n - off;
    if (take > RAWQ_CHUNK)
      take = RAWQ_CHUNK;

    pthread_mutex_lock(&s->q_mu);
    while (s->q_fcount == 0 && !s->q_stop)
      pthread_cond_wait(&s->q_nf, &s->q_mu);
    if (s->q_stop || s->q_fcount == 0)
    {
      pthread_mutex_unlock(&s->q_mu);
      return;
    }
    u8 *b = s->q_free[--s->q_fcount];
    pthread_mutex_unlock(&s->q_mu);

    memcpy(b, d + off, (size_t)take);

    pthread_mutex_lock(&s->q_mu);
    s->q_buf[s->q_tail] = b;
    s->q_len[s->q_tail] = take;
    s->q_tail = (s->q_tail + 1) % RAWQ_SLOTS;
    s->q_count++;
    pthread_cond_signal(&s->q_ne);
    pthread_mutex_unlock(&s->q_mu);

    off += take;
  }
}
#endif /* USB_SNIFFER_NO_RAWQ */

/*============================================================================*/
/* sniffer (FX2LP) transport: EP0 vendor control + EP 0x82 raw frame stream   */
/*============================================================================*/
static void msleep(int ms)
{
#ifdef _WIN32
  Sleep(ms);
#else
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (long)(ms % 1000) * 1000000L;
  nanosleep(&ts, NULL);
#endif
}

static bool sniffer_ctrl(usb_sniffer *s, int index, int value)
{
  int v = index | ((value ? 1 : 0) << CTRL_REG_SIZE);
  int rc = libusb_control_transfer(s->handle,
      LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE,
      CMD_CTRL, (uint16_t)v, 0, NULL, 0, SNIFFER_TIMEOUT_MS);

  if (rc < 0)
  {
    snprintf(s->err, sizeof(s->err), "usb_ctrl(): %s", libusb_error_name(rc));
    return false;
  }
  return true;
}

static void sniffer_flush(usb_sniffer *s)
{
  u8 buf[SNIFFER_DATA_EP_SIZE];
  int size;

  for (int k = 0; k < 100; k++)
  {
    int rc = libusb_bulk_transfer(s->handle, SNIFFER_DATA_ENDPOINT, buf, sizeof(buf), &size, 20);
    if (rc < 0)
      break;   /* TIMEOUT = drained */
  }
}

static void LIBUSB_CALL sniffer_callback(struct libusb_transfer *t)
{
  usb_sniffer *s = (usb_sniffer *)t->user_data;

  if (!s)
    return;

  s->xfer_pending--;

  if (s->closing)
    return;
  if (LIBUSB_TRANSFER_CANCELLED == t->status)
    return;
  if (LIBUSB_TRANSFER_NO_DEVICE == t->status)
  {
    s->stop_requested = true;
    return;
  }
  /* Deliver whatever arrived for any terminal status (the old sniffer backend did
   * this): libusb reports the bytes received before a timeout in
   * actual_length, and dropping them made sparse sniffer traffic disappear. */
  if (t->actual_length > 0)
    rawq_push(s, t->buffer, t->actual_length);

  if (libusb_submit_transfer(t) == 0)
    s->xfer_pending++;
}

static bool sniffer_open(usb_sniffer *s)
{
  libusb_device **list = NULL;
  int count = libusb_get_device_list(NULL, &list);
  bool ok = false;

  if (count < 0)
  {
    snprintf(s->err, sizeof(s->err), "libusb_get_device_list(): %s", libusb_error_name(count));
    return false;
  }

  for (int i = 0; i < count && !ok; i++)
  {
    if (!is_sniffer(list[i]))
      continue;

    libusb_device_handle *h = NULL;
    if (libusb_open(list[i], &h) < 0)
      continue;

    libusb_set_auto_detach_kernel_driver(h, 1);
    if (libusb_claim_interface(h, 0) < 0)
    {
      libusb_close(h);
      continue;
    }

    s->handle = h;
    ok = true;
  }

  libusb_free_device_list(list, 1);

  if (!ok)
    snprintf(s->err, sizeof(s->err), "no '%s' device found", SNIFFER_PRODUCT);
  return ok;
}

static bool sniffer_start_transfers(usb_sniffer *s)
{
  for (int i = 0; i < SNIFFER_TRANSFER_COUNT; i++)
  {
    s->xbuf[i] = (u8 *)malloc(SNIFFER_TRANSFER_SIZE);
    s->xfer[i] = libusb_alloc_transfer(0);

    if (!s->xbuf[i] || !s->xfer[i])
    {
      snprintf(s->err, sizeof(s->err), "libusb_alloc_transfer() failed");
      return false;
    }

    libusb_fill_bulk_transfer(s->xfer[i], s->handle, SNIFFER_DATA_ENDPOINT,
        s->xbuf[i], SNIFFER_TRANSFER_SIZE, sniffer_callback, s, SNIFFER_TIMEOUT_MS);

    if (libusb_submit_transfer(s->xfer[i]) < 0)
    {
      snprintf(s->err, sizeof(s->err), "libusb_submit_transfer() failed");
      return false;
    }
    s->xfer_pending++;
  }
  s->xfer_count = SNIFFER_TRANSFER_COUNT;
  return true;
}

/* Cancel/drain/free the async transfer pool. */
static void usb_cancel_pool(usb_sniffer *s)
{
  if (!s->handle)
    return;

  int n = s->xfer_count ? s->xfer_count : SNIFFER_TRANSFER_COUNT;

  s->closing = 1;

  for (int i = 0; i < n; i++)
    if (s->xfer[i])
      libusb_cancel_transfer(s->xfer[i]);

  for (int spins = 0; s->xfer_pending > 0 && spins < 500; spins++)
  {
    struct timeval tv = { 0, 20000 };
    libusb_handle_events_timeout_completed(NULL, &tv, NULL);
  }

  for (int i = 0; i < n; i++)
  {
    if (s->xfer[i]) { libusb_free_transfer(s->xfer[i]); s->xfer[i] = NULL; }
    if (s->xbuf[i]) { free(s->xbuf[i]); s->xbuf[i] = NULL; }
  }

  s->xfer_count   = 0;
  s->xfer_pending = 0;
  s->closing      = 0;
}

static void usb_close_handle(usb_sniffer *s)
{
  if (s->handle)
  {
    libusb_release_interface(s->handle, 0);
    libusb_close(s->handle);
    s->handle = NULL;
  }
}

static void usb_teardown(usb_sniffer *s)
{
  usb_cancel_pool(s);
  rawq_stop(s);
  usb_close_handle(s);
}

static int sniffer_run(usb_sniffer *s)
{
  int rc = libusb_init(NULL);

  if (rc < 0)
  {
    snprintf(s->err, sizeof(s->err), "libusb_init(): %s", libusb_error_name(rc));
    return 1;
  }

  if (!sniffer_open(s))
  {
    libusb_exit(NULL);
    return 1;
  }

  /* sniffer init sequence (control register) */
  sniffer_ctrl(s, SNIFFER_CTRL_RESET, 1);
  sniffer_ctrl(s, SNIFFER_CTRL_ENABLE, 0);
  sniffer_ctrl(s, SNIFFER_CTRL_TEST, 0);
  sniffer_ctrl(s, SNIFFER_CTRL_SPEED0, 1);
  sniffer_ctrl(s, SNIFFER_CTRL_SPEED0, 0);
  sniffer_ctrl(s, SNIFFER_CTRL_SPEED1, 1);
  sniffer_ctrl(s, SNIFFER_CTRL_SPEED1, 0);

  sniffer_ctrl(s, SNIFFER_CTRL_ENABLE, 0);
  sniffer_ctrl(s, SNIFFER_CTRL_RESET, 1);
  sniffer_flush(s);
  sniffer_ctrl(s, SNIFFER_CTRL_SPEED0, s->speed & 1);
  sniffer_ctrl(s, SNIFFER_CTRL_SPEED1, s->speed & 2);
  sniffer_ctrl(s, SNIFFER_CTRL_RESET, 0);
  sniffer_ctrl(s, SNIFFER_CTRL_ENABLE, 1);

  slog(s, "sniffer: init done, speed=%d", (int)s->speed);
  usb_sniffer_reset(s);

  if (!rawq_start(s))
  {
    usb_teardown(s);
    libusb_exit(NULL);
    return 1;
  }

  if (!sniffer_start_transfers(s))
  {
    usb_teardown(s);
    libusb_exit(NULL);
    return 1;
  }
  slog(s, "sniffer: streaming");

  while (!s->stop_requested)
  {
    struct timeval tv = { 0, 200000 };
    libusb_handle_events_timeout_completed(NULL, &tv, NULL);
  }

  sniffer_ctrl(s, SNIFFER_CTRL_ENABLE, 0);   /* stop capturing */
  msleep(20);
  usb_teardown(s);
  libusb_exit(NULL);
  return 0;
}

int usb_sniffer_run(usb_sniffer *s)
{
  if (!s)
    return -1;

  return sniffer_run(s);
}

void usb_sniffer_stop(usb_sniffer *s)
{
  if (s)
    s->stop_requested = true;
}

const char *usb_sniffer_error(const usb_sniffer *s)
{
  return s ? s->err : "";
}

/*============================================================================*/
/* usbpv capture-plugin ABI                                                   */
/*                                                                            */
/* Confirmed against the reference plugin ZiSan.dll:                          */
/*   int   usbpv_get_option(char* buf, int buf_size);                         */
/*   void* usbpv_open(const char* option, void* ctx, usbpv_packet_handler cb);*/
/*   int   usbpv_close(void* handle);                                         */
/*============================================================================*/
#if defined(_WIN32)
#  define USBPV_PLUGIN_API __declspec(dllexport)
#else
#  define USBPV_PLUGIN_API __attribute__((visibility("default")))
#endif

typedef long (*usbpv_packet_handler)(void *context, unsigned long ts,
                                     unsigned long nano, const void *data,
                                     unsigned long len, long status);

static FILE *g_log = NULL;
static volatile int g_active = 0;   /* one capture at a time */

static void plog(const char *fmt, ...)
{
  /* No log file by default.  Set USB_SNIFFER_LOG=<path> to enable logging. */
  if (!g_log)
  {
    const char *path = getenv("USB_SNIFFER_LOG");
    if (!path || !path[0])
      return;
    g_log = fopen(path, "a");
    if (!g_log)
      return;
  }
  va_list ap;
  va_start(ap, fmt);
  vfprintf(g_log, fmt, ap);
  va_end(ap);
  fputc('\n', g_log);
  fflush(g_log);
}

static bool opt_has(const char *option, const char *token)
{
  return option && strstr(option, token) != NULL;
}

static void plugin_log(void *user, const char *msg)
{
  (void)user;
  plog("    [sniffer] %s", msg);
}

typedef struct
{
  usb_sniffer         *snf;
  pthread_t            thread;
  usbpv_packet_handler cb;
  void                *ctx;
} plugin_instance;

static int dlt_to_upv_speed(int link_type)
{
  switch (link_type)
  {
    case USB_SNIFFER_DLT_LS: return 1;
    case USB_SNIFFER_DLT_FS: return 2;
    case USB_SNIFFER_DLT_HS: return 3;
    default:                 return 0;
  }
}

static void on_packet(void *user, uint64_t ts_ns, const uint8_t *data, int size, int link_type)
{
  plugin_instance *pi = (plugin_instance *)user;
  if (!pi || !pi->cb || size <= 0)
    return;
  unsigned long ts   = (unsigned long)(ts_ns / 1000000000ull);
  unsigned long nano = (unsigned long)(ts_ns % 1000000000ull);
  long status = (long)dlt_to_upv_speed(link_type);   /* type 0 = data packet */
  pi->cb(pi->ctx, ts, nano, data, (unsigned long)size, status);
}

static void on_event(void *user, uint64_t ts_ns, int type)
{
  plugin_instance *pi = (plugin_instance *)user;
  if (!pi || !pi->cb)
    return;
  unsigned long ts   = (unsigned long)(ts_ns / 1000000000ull);
  unsigned long nano = (unsigned long)(ts_ns % 1000000000ull);
  long status = (long)(type << 4);
  pi->cb(pi->ctx, ts, nano, NULL, 0, status);
}

static void *worker_main(void *arg)
{
  plugin_instance *pi = (plugin_instance *)arg;
  int r = usb_sniffer_run(pi->snf);
  plog("    usb_sniffer_run -> %d (%s)", r, r ? usb_sniffer_error(pi->snf) : "clean stop");
  return NULL;
}

/*----------------------------------------------------------------------------*/
/* Last-used capture parameters are remembered in a small file next to the     */
/* plugin (plugins\usb_sniffer.cfg), so the next capture dialog reopens with   */
/* the previous selection instead of always resetting to the first choice.     */
/*----------------------------------------------------------------------------*/
#if defined(_WIN32)
static HINSTANCE g_hinst = NULL;

/* Directory holding the plugin DLL (the usbpv "plugins" folder). */
static bool plugin_dir(char *buf, size_t n)
{
  DWORD r = GetModuleFileNameA(g_hinst, buf, (DWORD)n);
  char *slash;

  if (r == 0 || r >= (DWORD)n)
    return false;
  slash = strrchr(buf, '\\');
  if (!slash)
    return false;
  *slash = '\0';
  return true;
}
#endif

static void config_path(char *buf, size_t n)
{
#if defined(_WIN32)
  char dir[1024];
  if (plugin_dir(dir, sizeof(dir)))
  {
    snprintf(buf, n, "%s\\usb_sniffer.cfg", dir);
    return;
  }
#endif
  snprintf(buf, n, "usb_sniffer.cfg");
}

static void trim_ws(char *s)
{
  char *p = s;
  size_t len;

  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
    p++;
  if (p != s)
    memmove(s, p, strlen(p) + 1);
  len = strlen(s);
  while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' ||
                     s[len - 1] == '\r' || s[len - 1] == '\n'))
    s[--len] = '\0';
}

static const char *const kSpeedChoices[] = { "HS", "FS", "LS" };
static const int kSpeedChoiceCount = 3;

/* Load speed/fold from the cfg file; fall back to HS / fold-off. */
static void load_config(char *speed, size_t sn, bool *fold)
{
  char path[1200];
  char line[256];
  FILE *f;

  snprintf(speed, sn, "HS");
  *fold = false;

  config_path(path, sizeof(path));
  f = fopen(path, "r");
  if (!f)
    return;

  while (fgets(line, sizeof(line), f))
  {
    char *eq = strchr(line, '=');
    char *k, *v;

    if (!eq)
      continue;
    *eq = '\0';
    k = line;
    v = eq + 1;
    trim_ws(k);
    trim_ws(v);

    if (strcmp(k, "speed") == 0)
    {
      for (int i = 0; i < kSpeedChoiceCount; i++)
        if (strcmp(v, kSpeedChoices[i]) == 0)
          snprintf(speed, sn, "%s", v);
    }
    else if (strcmp(k, "fold") == 0)
    {
      *fold = (v[0] == 'Y' || v[0] == 'y' || v[0] == '1');
    }
  }
  fclose(f);
}

static void save_config(const char *speed, bool fold)
{
  char path[1200];
  FILE *f;

  config_path(path, sizeof(path));
  f = fopen(path, "w");
  if (!f)
  {
    plog("    could not write config %s", path);
    return;
  }
  fprintf(f, "speed=%s\nfold=%s\n", speed, fold ? "Yes" : "No");
  fclose(f);
  plog("    saved config: %s (speed=%s fold=%s)", path, speed, fold ? "Yes" : "No");
}

/* Build the UI template, moving the saved choice to the front of each list
 * (usbpv renders the first choice as the default selection). */
static int build_option(char *buf, int buf_size)
{
  char speed[8];
  bool fold;
  char t[256];
  int n = 0;

  load_config(speed, sizeof(speed), &fold);

  n += snprintf(t + n, sizeof(t) - (size_t)n, "<select,Speed,%s", speed);
  for (int i = 0; i < kSpeedChoiceCount; i++)
    if (strcmp(kSpeedChoices[i], speed) != 0)
      n += snprintf(t + n, sizeof(t) - (size_t)n, ",%s", kSpeedChoices[i]);
  n += snprintf(t + n, sizeof(t) - (size_t)n, ">");
  n += snprintf(t + n, sizeof(t) - (size_t)n, "<select,Fold empty,%s,%s>",
                fold ? "Yes" : "No", fold ? "No" : "Yes");

  if (buf && buf_size > 0)
  {
    int copy = (n + 1 <= buf_size) ? (n + 1) : buf_size;
    memcpy(buf, t, (size_t)(copy - 1));
    buf[copy - 1] = '\0';
  }
  return n;
}

USBPV_PLUGIN_API int usbpv_get_option(char *buf, int buf_size)
{
  int len = build_option(buf, buf_size);
  plog("[usbpv_get_option] size=%d -> len=%d", buf_size, len);
  return len;
}

USBPV_PLUGIN_API void *usbpv_open(const char *option, void *ctx, usbpv_packet_handler cb)
{
  plog("================ [usbpv_open] option=%s", option ? option : "(null)");

  if (g_active)
  {
    plog("    already capturing; refusing a second open");
    return NULL;
  }

  /* No AUTO on this hardware: the UI only offers HS/FS/LS; default HS. */
  usb_sniffer_speed speed = opt_has(option, ",FS") ? USB_SNIFFER_SPEED_FS :
                            opt_has(option, ",LS") ? USB_SNIFFER_SPEED_LS :
                                                     USB_SNIFFER_SPEED_HS;
  bool fold = opt_has(option, ",Yes");   /* fold is off unless explicitly enabled */
  plog("    speed=%d fold=%d", (int)speed, fold ? 1 : 0);

  /* Remember this selection for the next time the dialog opens. */
  save_config(speed == USB_SNIFFER_SPEED_FS ? "FS" :
              speed == USB_SNIFFER_SPEED_LS ? "LS" : "HS",
              fold);

  plugin_instance *pi = (plugin_instance *)calloc(1, sizeof(*pi));
  if (!pi)
    return NULL;
  pi->cb  = cb;
  pi->ctx = ctx;

  /* Bus events (reset begin/end, overflow) are delivered through the same
   * packet callback (data=NULL, len=0).  Build with -DUSB_SNIFFER_NO_EVENTS
   * to disable them. */
#ifdef USB_SNIFFER_NO_EVENTS
  usb_sniffer_event_fn evt = NULL;
#else
  usb_sniffer_event_fn evt = on_event;
#endif

  /* The device is opened inside usb_sniffer_run() (the worker thread), so
   * usbpv_open() never performs libusb work and always returns a valid
   * handle (like the reference/validated plugin). */
  pi->snf = usb_sniffer_new(speed, fold, on_packet, evt, NULL, pi);
  if (!pi->snf)
  {
    free(pi);
    return NULL;
  }
  usb_sniffer_set_log(pi->snf, plugin_log, NULL);

  if (pthread_create(&pi->thread, NULL, worker_main, pi) != 0)
  {
    plog("    pthread_create failed");
    usb_sniffer_delete(pi->snf);
    free(pi);
    return NULL;
  }

  g_active = 1;
  return (void *)pi;
}

USBPV_PLUGIN_API int usbpv_close(void *handle)
{
  plugin_instance *pi = (plugin_instance *)handle;
  plog("[usbpv_close] handle=%p", handle);
  if (!pi)
    return 0;

  usb_sniffer_stop(pi->snf);
  pthread_join(pi->thread, NULL);
  usb_sniffer_delete(pi->snf);
  free(pi);
  g_active = 0;
  return 0;
}

#ifdef _WIN32
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH)
  {
    g_hinst = inst;
    DisableThreadLibraryCalls(inst);
  }
  return TRUE;
}
#endif
