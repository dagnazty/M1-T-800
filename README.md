# M1 T-800 Firmware (ESP32-C6 Coprocessor)

[![Companion Firmware](https://img.shields.io/badge/Companion--Firmware-M1__T--1000-blueviolet?style=flat-square&logo=github)](https://github.com/dagnazty/M1_T-1000)
[![License: GPL v3 / MIT](https://img.shields.io/badge/License-GPL%20v3%20%2F%20MIT-blue?style=flat-square)](#licensing)
[![Platform: ESP32-C6](https://img.shields.io/badge/Platform-ESP32--C6-orange?style=flat-square)](https://www.espressif.com/en/products/socs/esp32-c6)

**T-800** is the customized ESP32-C6 SPI AT firmware for the **Monstatek M1** handheld multi-tool. It acts as the dedicated wireless co-processor, providing 2.4 GHz Wi-Fi 6, Bluetooth LE 5.0, and Zigbee/Thread (IEEE 802.15.4) capabilities.

The co-processor communicates with the M1's main system microcontroller over a high-speed SPI bus using a custom RPC (Remote Procedure Call) protocol built on top of Espressif's AT command framework.

---

## ⚡ Companion Firmware

This firmware is designed to run in tandem with the **[M1 T-1000 Firmware](https://github.com/dagnazty/M1_T-1000)**, a community-driven, feature-expanded firmware for the Monstatek M1 main board. 

---

## 🛠️ Custom Features & AT Commands

In addition to standard Espressif AT commands, this firmware implements custom commands specifically designed for offensive security, network analysis, and device emulation on the Monstatek M1.

### 🌐 Wi-Fi & Pentesting Commands

These commands handle promiscuous sniffing, packet injection, and offensive Wi-Fi techniques.

| Command | Type | Description |
| :--- | :--- | :--- |
| `AT+M1WIFISTATS?` | Query | Retrieves current connection status, Wi-Fi mode, RSSI, channel, BSSID, and IP address. |
| `AT+M1MONITOR=<enable>,<channel>` | Setup | Enables (`1`) or disables (`0`) promiscuous monitor mode on channels 1–14. |
| `AT+M1DEAUTH=<bssid>,<channel>[,<client_mac>,<count>]` | Setup | Launches a targeted or broadcast deauthentication flood. `count=0` runs continuously. |
| `AT+M1DEAUTHSTOP` | Exec | Stops any running deauthentication flood. |
| `AT+M1DEAUTHALL` | Exec | Scans the area and broadcasts deauthentication frames to every visible AP using channel hopping. |
| `AT+M1BEACON=<enable>[,<ssid1>,<ssid2>,...]` | Setup | Starts or stops broadcasting fake AP beacons. Supports up to 8 SSIDs. |
| `AT+M1PROBE=<enable>,<channel>,<duration>` | Setup | Sniffs and decodes 802.11 probe requests from clients in range. |
| `AT+M1PMKID=<bssid>,<channel>` | Setup | Solicits and captures WPA2/WPA3 PMKID hashes from a target Access Point. |
| `AT+M1KARMA=<enable>[,<channel>]` | Setup | Runs a Karma attack, automatically responding to client probe requests with fake AP beacons. |
| `AT+M1HSCAP=<enable>,<channel>,<bssid>` | Setup | Monitors and captures 4-way WPA/WPA2 handshakes. |
| `AT+M1EVILTWIN=<enable>[,<ssid>,<channel>]` | Setup | Spawns a rogue Access Point hosting a DNS-hijacking captive portal to harvest credentials. |
| `AT+M1BLESPAM=<enable>[,<vendor>]` | Setup | Floods nearby devices with BLE proximity pairing advertisements. Vendors: `0` (All), `1` (Apple), `2` (Google), `3` (Microsoft). |

### ⌨️ BLE HID Keyboard Emulation

Used for BadUSB/BadBT wireless keystroke injection.

*   **`AT+HIDKBINIT=<enable>`**
    Registers the BLE Human Interface Device (HID) GATT services (GATT DIS, Battery, and HID reports) via the NimBLE stack.
*   **`AT+HIDKBSEND=<modifier>,<key1>,...,<key6>`**
    Sends standard 8-byte keyboard reports over BLE. Key codes follow the USB HID usage tables. Use `AT+HIDKBSEND=0,0,0,0,0,0,0` to release all keys.

### 📡 Zigbee & IEEE 802.15.4 Sniffer

Promiscuous sniffing for IoT networks.

*   **`AT+ZIGSNIFF=<enable>[,<channel>]`**
    Starts or stops promiscuous sniffing on IEEE 802.15.4 channels 11–26.
*   **Unsolicited Event Output:**
    When sniffing, captured frames are output in real time over the AT interface:
    ```text
    +ZIGFRAME:<proto>,<ftype>,<len>,<ch>,<rssi>,<lqi>,<dst_pan>,<dst_addr>,<src_pan>,<src_addr>,<hex_data>
    ```
    *   `proto`: `Z` (Zigbee), `T` (Thread), `U` (Unknown)
    *   `ftype`: `BCN` (Beacon), `DATA`, `ACK`, `CMD`
    *   `hex_data`: Hexadecimal string of the captured frame payload.

---

## 🏗️ Building & Flashing

### Prerequisites

You must set up the Espressif ESP-IDF toolchain. This project uses **ESP-IDF v5.1**.
Make sure submodules are initialized:
```bash
git submodule update --init --recursive
```

### 1. Build the Firmware

A build script wrapper, [build_m1.sh](file:///Users/dag/Documents/GitHub/esp32-at-monstatek-m1/build_m1.sh), is provided to export the correct module flags and target the ESP32-C6:

```bash
chmod +x build_m1.sh
./build_m1.sh
```

### 2. Flashing

You can flash the compiled firmware directly using `idf.py` over serial:
```bash
idf.py -p (PORT) flash
```

Alternatively, you can flash the consolidated factory binary containing the bootloader, partition table, and application merged together:
*   **Factory Binary Path:** `build/factory/factory_ESP32C6-SPI.bin`
*   **Flash Address:** `0x0`
*   **Command:**
    ```bash
    esptool.py -p (PORT) -b 460800 --chip esp32c6 write_flash 0x0 build/factory/factory_ESP32C6-SPI.bin
    ```

---

## ⚖️ Licensing

This repository uses a split licensing model:

1.  **Core ESP-AT Framework:** The underlying AT commands, build systems, and Espressif components are licensed under the **Espressif MIT License** (see [LICENSE](file:///Users/dag/Documents/GitHub/esp32-at-monstatek-m1/LICENSE)).
2.  **Custom M1 T-800 Additions:** All custom AT commands (`main/at_custom_wifi_cmd.c`, `main/at_custom_hid_cmd.c`, `main/at_custom_zigbee_cmd.c`) and SPI RPC components (`main/rpc/*`) are licensed under the **GNU General Public License v3.0 (GPL-3.0)** to align with the companion [M1 T-1000 Firmware](https://github.com/dagnazty/M1_T-1000).

---

## 🤝 Acknowledgments

*   **[Espressif Systems](https://github.com/espressif)** - Developers of the core ESP-AT project and ESP32-C6 hardware platform.
*   **[@bedge117](https://github.com/bedge117)** - Created the initial SPI configuration, Monstatek M1 pin-mappings, BLE HID dynamic service registration, and Zigbee sniffer integration.