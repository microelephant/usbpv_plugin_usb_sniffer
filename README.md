# USB Sniffer plugin for USB Packet Viewer

This project is a capture plugin that makes the **USB Sniffer**
hardware by Alex Taradov (<https://github.com/ataradov/usb-sniffer>) usable
inside **USB Packet Viewer** (<https://www.usbpacketviewer.com/>).

USB Packet Viewer is a Windows application that can load
third-party capture plugins from its `plugins` folder. This repository builds
such a plugin: USB Packet Viewer loads it, the plugin talks to the USB Sniffer
over libusb, and captured traffic is shown in the viewer in real time.

- **Hardware:** USB Sniffer (ataradov FX2LP design).
- **Software:** USB Packet Viewer (Windows, 64-bit).
- **Output:** `./plugins/usb_sniffer.dll`, a self-contained plugin (libusb and the C runtime are statically linked — no extra DLLs to install).

---

## Get the plugin

You can either download a ready-to-use build or build it yourself — both give the same `usb_sniffer.dll`:

- **Download the prebuilt plugin** from the **Releases** page of this repository (`https://github.com/microelephant/usbpv_plugin_usb_sniffer/releases/`). Grab `usb_sniffer.dll` and skip straight to *Install the plugin into USB Packet Viewer*.
- **Build it yourself** on Windows with MSYS2 — follow *Build on Windows (MSYS2 + MinGW-w64)* below.

---

## What you need

- A USB Sniffer hardware that works properly under Wireshark.
- USB Packet Viewer installed on Windows 10/11 (64-bit).
- MSYS2 to build the plugin. MSYS2 is only needed for building; the finished DLL needs nothing else.

---

## Build on Windows (MSYS2 + MinGW-w64)

### Step 1 — Install MSYS2

1. Download the installer from <https://www.msys2.org/> and install it with the default options.
2. After installation, open the **"MSYS2 MINGW64"** shell from the Start menu. Use this shell for all steps below (do **not** use the plain "MSYS2 MSYS" shell).

### Step 2 — Install the toolchain

```
pacman -S --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-libusb mingw-w64-x86_64-pkgconf make git
```

### Step 3 — Get the sources

```
git clone https://github.com/microelephant/usbpv_plugin_usb_sniffer.git
cd usbpv_plugin_usb_sniffer
```

### Step 4 — Build

```
make clean
make PLUGIN_EXT=dll CC=gcc
```

The plugin is written to:

```
plugins\usb_sniffer.dll
```

---

## Install the plugin into USB Packet Viewer

1. Locate the USB Packet Viewer folder — the one that contains `usbpv.exe`.
2. Make sure a `plugins` subfolder exists next to `usbpv.exe`; create it if it is missing.
3. Copy the plugin DLL — either the `usb_sniffer.dll` you downloaded from Releases or the one you just built — into that subfolder. 

The result should look like this:

```
usbpv\
├─ usbpv.exe
└─ plugins\
   └─ usb_sniffer.dll
```

---

## Use

1. Launch usbpv.exe.
2. Click `Capture with plugin..` in the `Tool` menu.
3. Select the capture speed (`HS` / `FS` / `LS`) and whether to fold empty frames, then start capturing. Traffic appears live in the viewer.

The last-used speed / fold settings are remembered in `plugins\usb_sniffer.cfg`
and restored the next time the capture dialog opens.
