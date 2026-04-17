# M1 Binary RPC Protocol Specification

## Overview

Replaces the ESP-AT ASCII command layer with a binary RPC protocol over the
existing SPI HD (half-duplex) transport. The SPI framing (handshake GPIO,
DMA transfers, seq numbers) is unchanged — this spec defines what goes *inside*
the data buffers.

## Design Goals

1. **Binary framing** — no ASCII parsing, no `\r\n` delimiters
2. **Async events** — ESP32 can push data (captured packets, scan results) without polling
3. **Extensible** — new commands don't require parser changes
4. **Compatible** — STM32-side changes limited to replacing AT string construction with binary packing
5. **Low latency** — single SPI transaction per command when possible

## Wire Format

All multi-byte integers are **little-endian**.

### Frame Header (8 bytes)

```
Offset  Size  Field
0       2     magic          0x4D31 ("M1")
2       1     version        0x01
3       1     msg_type       see MsgType enum
4       2     msg_id         command/response/event ID
6       2     payload_len    bytes following this header
```

Total frame size = 8 + payload_len.

### MsgType

| Value | Name    | Direction       | Description                    |
|-------|---------|-----------------|--------------------------------|
| 0x01  | REQ     | STM32 → ESP32   | Command request                |
| 0x02  | RESP    | ESP32 → STM32   | Command response               |
| 0x03  | EVENT   | ESP32 → STM32   | Unsolicited async notification |
| 0x04  | FRAG    | Either          | Continuation fragment          |

### Fragmentation

Max SPI DMA payload = 4092 bytes (existing `SPI_DMA_MAX_LEN`).
Frames larger than 4084 bytes (4092 - 8 header) are fragmented:

- First fragment: normal header with `payload_len` = total payload length
- Subsequent fragments: `msg_type = FRAG`, `msg_id` = same as first fragment,
  `payload_len` = bytes in this fragment
- Receiver reassembles by tracking `(msg_type, msg_id)` pairs

### CRC

After the frame header + payload, a 2-byte CRC16-CCITT follows.
This is **outside** `payload_len` — the SPI DMA transfer length =
8 + payload_len + 2.

```
[8-byte header][payload (payload_len bytes)][CRC16 (2 bytes)]
```

The STM32 side already validates SPI data integrity; this is a defense-in-depth
for payload corruption.

---

## Message IDs

### Request IDs (0x0100 – 0x01FF): WiFi Station

| ID     | Name                      | Payload (REQ)                          | Payload (RESP)                    |
|--------|---------------------------|----------------------------------------|------------------------------------|
| 0x0100 | WIFI_GET_MODE             | —                                      | uint8 mode                         |
| 0x0101 | WIFI_SET_MODE             | uint8 mode                             | uint8 status                       |
| 0x0102 | WIFI_GET_MAC              | uint8 iface (0=sta, 1=ap)             | uint8[6] mac                       |
| 0x0103 | WIFI_SCAN                  | uint8 band (0=2.4G, 1=5G, 2=both)     | uint16 count + scan_entry[]        |
| 0x0104 | WIFI_CONNECT               | connect_req                            | uint8 status                       |
| 0x0105 | WIFI_DISCONNECT            | —                                      | uint8 status                       |
| 0x0106 | WIFI_GET_STATUS            | —                                      | uint8 status, uint8[6] bssid, ...  |

### Request IDs (0x0200 – 0x02FF): WiFi AP

| ID     | Name                      | Payload (REQ)                          | Payload (RESP)                    |
|--------|---------------------------|----------------------------------------|------------------------------------|
| 0x0200 | SOFTAP_START              | softap_config                          | uint8 status                       |
| 0x0201 | SOFTAP_STOP               | —                                      | uint8 status                       |
| 0x0202 | SOFTAP_GET_STA_LIST       | —                                      | uint16 count + sta_entry[]         |

### Request IDs (0x0300 – 0x03FF): Offensive WiFi

| ID     | Name                      | Payload (REQ)                          | Payload (RESP)                    |
|--------|---------------------------|----------------------------------------|------------------------------------|
| 0x0300 | OFF_MONITOR_START         | uint8 channel, uint8 band              | uint8 status                       |
| 0x0301 | OFF_MONITOR_STOP          | —                                      | uint8 status                       |
| 0x0302 | OFF_DEAUTH_START          | deauth_req                             | uint8 status                       |
| 0x0303 | OFF_DEAUTH_STOP           | —                                      | uint8 status                       |
| 0x0304 | OFF_BEACON_START          | beacon_req                             | uint8 status                       |
| 0x0305 | OFF_BEACON_STOP           | —                                      | uint8 status                       |
| 0x0306 | OFF_PROBE_SNIFF_START     | probe_req                              | uint8 status                       |
| 0x0307 | OFF_PROBE_SNIFF_STOP      | —                                      | uint8 status                       |
| 0x0308 | OFF_PMKID_CAPTURE         | pmkid_req                              | uint8 status + result             |
| 0x0309 | OFF_KARMA_START           | karma_req                              | uint8 status                       |
| 0x030A | OFF_KARMA_STOP            | —                                      | uint8 status                       |
| 0x030B | OFF_HANDSHAKE_CAPTURE     | hscap_req                              | uint8 status                       |
| 0x030C | OFF_RAW_TX                | raw_tx_req                             | uint8 status                       |
| 0x030D | OFF_DEAUTH_STATUS         | —                                      | uint32 sent_count, uint8 running   |

### Request IDs (0x0400 – 0x04FF): BLE

| ID     | Name                      | Payload (REQ)                          | Payload (RESP)                    |
|--------|---------------------------|----------------------------------------|------------------------------------|
| 0x0400 | BLE_INIT                  | uint8 mode                             | uint8 status                       |
| 0x0401 | BLE_SCAN_START            | uint8 duration_sec                     | uint8 status                       |
| 0x0402 | BLE_SCAN_RESULTS          | —                                      | uint16 count + ble_scan_entry[]    |
| 0x0403 | BLE_ADVERTISE_START       | adv_config                             | uint8 status                       |
| 0x0404 | BLE_ADVERTISE_STOP        | —                                      | uint8 status                       |
| 0x0405 | BLE_HID_INIT              | uint8 enable                           | uint8 status                       |
| 0x0406 | BLE_HID_KEYPRESS          | hid_keypress                           | uint8 status                       |
| 0x0407 | BLE_CONNECT               | uint8[6] addr, uint8 addr_type        | uint8 status                       |
| 0x0408 | BLE_DISCONNECT            | uint8[6] addr                          | uint8 status                       |

### Request IDs (0x0500 – 0x05FF): Zigbee / 802.15.4

| ID     | Name                      | Payload (REQ)                          | Payload (RESP)                    |
|--------|---------------------------|----------------------------------------|------------------------------------|
| 0x0500 | ZB_INIT                   | uint8 mode                             | uint8 status                       |
| 0x0501 | ZB_SCAN                   | uint8 channel_mask[4]                  | uint16 count + zb_network[]        |
| 0x0502 | ZB_SNIFF_START            | uint8 channel                          | uint8 status                       |
| 0x0503 | ZB_SNIFF_STOP             | —                                      | uint8 status                       |

### Request IDs (0x0600 – 0x06FF): System

| ID     | Name                      | Payload (REQ)                          | Payload (RESP)                    |
|--------|---------------------------|----------------------------------------|------------------------------------|
| 0x0600 | SYS_PING                  | uint8[4] cookie                        | uint8[4] cookie (echo)            |
| 0x0601 | SYS_GET_FW_VERSION        | —                                      | fw_version struct                  |
| 0x0602 | SYS_GET_HEAP               | —                                      | uint32 free_heap, uint32 min_heap  |
| 0x0603 | SYS_RESET                  | uint8 flags                             | — (no response, device resets)     |
| 0x0604 | SYS_OTA_BEGIN             | uint32 image_size                       | uint8 status                       |
| 0x0605 | SYS_OTA_DATA              | uint8[] data                            | uint8 status                       |
| 0x0606 | SYS_OTA_END               | uint8 reboot                            | uint8 status                       |

---

## Event IDs (0xE000 – 0xEFFF)

Events are unsolicited messages from ESP32 → STM32.

| ID     | Name                      | Payload                                |
|--------|---------------------------|----------------------------------------|
| 0xE001 | EVT_WIFI_SCAN_DONE        | uint16 ap_count                         |
| 0xE002 | EVT_WIFI_CONNECTED        | uint8[6] bssid, uint8 channel          |
| 0xE003 | EVT_WIFI_DISCONNECTED     | uint8 reason                            |
| 0xE010 | EVT_MONITOR_PACKET        | uint8 channel, int8 rssi, uint16 len, uint8[] frame |
| 0xE011 | EVT_MONITOR_DEAUTH        | uint8[6] src, uint8[6] dst, uint8 channel |
| 0xE020 | EVT_PMKID_RESULT          | uint8 status, uint8[6] bssid, uint8[] pmkid_data |
| 0xE021 | EVT_HANDSHAKE_RESULT      | uint8 status, uint8[6] bssid, uint8[] handshake_data |
| 0xE030 | EVT_KARMA_PROBE_REQ       | uint8[6] src, uint8[] ssid, uint8 ssid_len |
| 0xE040 | EVT_BLE_SCAN_RESULT       | ble_scan_entry[]                        |
| 0xE050 | EVT_ZB_FRAME              | uint8 channel, uint16 len, uint8[] frame |
| 0xE060 | EVT_STA_CONNECTED         | uint8[6] mac                            |
| 0xE061 | EVT_STA_DISCONNECTED      | uint8[6] mac, uint8 reason              |
| 0xE0FF | EVT_ERROR                 | uint16 error_code, uint8 msg_len, char[] msg |

---

## Struct Definitions

### connect_req (WIFI_CONNECT)
```
uint8   ssid_len        (0-32)
uint8[] ssid            (ssid_len bytes)
uint8   pwd_len         (0-64)
uint8[] pwd             (pwd_len bytes)
uint8[6] bssid          (optional, 00:00:00:00:00:00 = any)
uint8   channel         (0 = auto)
uint8   authmode        (see wifi_auth_mode_e)
```

### scan_entry (WIFI_SCAN response)
```
uint8[6]  bssid
int8      rssi
uint8     channel
uint8     authmode
uint8     ssid_len
uint8[]   ssid
```

### deauth_req (OFF_DEAUTH_START)
```
uint8[6]  bssid
uint8     channel
uint8[6]  station        (ff:ff:ff:ff:ff:ff = broadcast)
uint16    count          (0 = infinite)
uint16    interval_ms    (0 = fastest possible)
```

### beacon_req (OFF_BEACON_START)
```
uint8     channel
uint8     ssid_count
for each ssid:
  uint8   ssid_len
  uint8[] ssid
```

### probe_req (OFF_PROBE_SNIFF_START)
```
uint8     channel
uint16    duration_sec
```

### pmkid_req (OFF_PMKID_CAPTURE)
```
uint8[6]  bssid
uint8     channel
```

### karma_req (OFF_KARMA_START)
```
uint8     channel
```

### hscap_req (OFF_HANDSHAKE_CAPTURE)
```
uint8[6]  bssid
uint8     channel
uint16    deauth_count   (0 = no deauth, just passive)
```

### raw_tx_req (OFF_RAW_TX)
```
uint8     channel
uint8     frame_len_hi
uint8     frame_len_lo
uint8[]   frame           (raw 802.11 frame)
```

### softap_config (SOFTAP_START)
```
uint8     ssid_len
uint8[]   ssid
uint8     pwd_len
uint8[]   pwd
uint8     channel
uint8     authmode
uint8     max_conn
uint8     hidden          (0=visible, 1=hidden)
```

### hid_keypress (BLE_HID_KEYPRESS)
```
uint8     modifier       (bitfield: ctrl/shift/alt/gui)
uint8     key_count
uint8[]   keys            (HID usage IDs, max 6)
```

### fw_version (SYS_GET_FW_VERSION response)
```
uint8     major
uint8     minor
uint8     patch
char[16]  git_hash        (null-terminated, first 16 chars)
```

### ble_scan_entry
```
uint8[6]  addr
uint8     addr_type
int8      rssi
uint8     name_len
uint8[]   name
```

---

## Status Codes

Used in response payloads (uint8 status field).

| Value | Name              | Meaning                           |
|-------|-------------------|-----------------------------------|
| 0x00  | OK                | Success                           |
| 0x01  | ERR_UNKNOWN       | Unknown error                     |
| 0x02  | ERR_INVALID_ARGS  | Invalid arguments                 |
| 0x03  | ERR_BUSY          | Another operation in progress     |
| 0x04  | ERR_TIMEOUT       | Operation timed out               |
| 0x05  | ERR_NO_MEM        | Out of memory                     |
| 0x06  | ERR_NOT_INIT      | Subsystem not initialized         |
| 0x07  | ERR_ALREADY_RUNNING | Operation already active        |
| 0x08  | ERR_NOT_RUNNING   | Operation not active              |
| 0x09  | ERR_HARDWARE      | Hardware failure                  |
| 0x0A  | ERR_UNSUPPORTED   | Command not supported             |
| 0xFF  | ERR_PENDING       | Accepted, result via event        |

---

## Migration Path

### Phase 1: Dual-mode (current)
- ESP32 firmware accepts both AT strings and binary frames
- Frame detection: if first two bytes = 0x4D31, treat as binary; else AT
- STM32 still sends AT for existing features, binary for new ones

### Phase 2: Binary-only
- Remove AT parser, all comms via binary RPC
- STM32 fully converted

### Phase 3: Module system
- ESP32 exposes a partition for loadable modules
- STM32 pushes module blobs via SYS_OTA_DATA or a new MODULE_LOAD command
- Modules register their own msg_ids dynamically

---

## SPI Transport Notes

The existing SPI slave HD transport is reused as-is:
- Handshake GPIO signals data ready
- Master queries slave status register (direction + seq + length)
- DMA transfers carry the framed data
- No changes to SPI configuration, pin assignments, or DMA sizes

The only change: what goes in the stream buffers is binary frames
instead of AT strings.

---

## STM32 Integration

On the STM32 side, the `esp_app_main.c` / `ctrl_api.h` layer needs:
1. Replace `at_spi_send_cmd("AT+M1DEAUTH=...")` with `m1_rpc_send(0x0302, &req, sizeof(req))`
2. Replace response parsing (`m1_at_response_parser.c`) with binary struct reads
3. Event handling via a new `m1_rpc_event_handler()` callback

The existing `Ctrl_cmd_t` / `ctrl_cmd_t` structure can be adapted —
`msg_type`, `msg_id`, and a union of payload structs map cleanly.
