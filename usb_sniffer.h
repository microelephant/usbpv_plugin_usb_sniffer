/*
 * usb_sniffer.h - USB Sniffer capture library (ataradov FX2LP)
 *
 *   usb_sniffer_new(speed, fold_empty, ...)   -> session
 *   usb_sniffer_run(session)                   -> open device + capture loop
 *   usb_sniffer_stop(session)                  -> request stop
 *   usb_sniffer_delete(session)
 */
#ifndef USB_SNIFFER_H
#define USB_SNIFFER_H

#include <stdint.h>
#include <stdbool.h>

/* Capture speed (the FX2LP capture-control speed bits: 0=LS 1=FS 2=HS). */
typedef enum
{
  USB_SNIFFER_SPEED_LS = 0,
  USB_SNIFFER_SPEED_FS = 1,
  USB_SNIFFER_SPEED_HS = 2,
} usb_sniffer_speed;

/* Bus-event types (the usbpv status nibble). */
#define USB_SNIFFER_EV_RESET_BEGIN   1
#define USB_SNIFFER_EV_RESET_END     2
#define USB_SNIFFER_EV_SUSPEND_BEGIN 3
#define USB_SNIFFER_EV_SUSPEND_END   4
#define USB_SNIFFER_EV_OVERFLOW      15

/* Link types (DLT) reported with each captured packet. */
#define USB_SNIFFER_DLT_USB 288
#define USB_SNIFFER_DLT_LS  293
#define USB_SNIFFER_DLT_FS  294
#define USB_SNIFFER_DLT_HS  295

typedef struct usb_sniffer usb_sniffer;

/* Captured USB packet: data = PID..CRC; link_type = USB_SNIFFER_DLT_*. */
typedef void (*usb_sniffer_packet_fn)(void *user, uint64_t ts_ns,
                                      const uint8_t *data, int size, int link_type);

/* Bus event: type = USB_SNIFFER_EV_*. */
typedef void (*usb_sniffer_event_fn)(void *user, uint64_t ts_ns, int type);

/* Out-of-band text (debug/status); may be NULL. */
typedef void (*usb_sniffer_info_fn)(void *user, uint64_t ts_ns, const char *str, int size);

/* Optional progress log (may be NULL). */
typedef void (*usb_sniffer_log_fn)(void *user, const char *msg);
void usb_sniffer_set_log(usb_sniffer *s, usb_sniffer_log_fn fn, void *user);

/* Create a session (no hardware is touched yet). */
usb_sniffer *usb_sniffer_new(usb_sniffer_speed speed, bool fold_empty,
                             usb_sniffer_packet_fn on_packet,
                             usb_sniffer_event_fn  on_event,
                             usb_sniffer_info_fn   on_info,
                             void *user);

/* Open the device/build the init sequence and run the capture loop until
 * usb_sniffer_stop().  Blocking.  Returns 0 on a clean stop, non-zero on
 * failure (usb_sniffer_error() has the reason). */
int usb_sniffer_run(usb_sniffer *s);

void usb_sniffer_stop(usb_sniffer *s);
const char *usb_sniffer_error(const usb_sniffer *s);

/* Feed an arbitrary chunk of the capture byte stream (used by the transport
 * and by tests). */
void usb_sniffer_feed(usb_sniffer *s, const uint8_t *data, int size);

/* True once the parser asked to stop (protocol desync). */
bool usb_sniffer_should_stop(const usb_sniffer *s);

void usb_sniffer_delete(usb_sniffer *s);

#endif /* USB_SNIFFER_H */
