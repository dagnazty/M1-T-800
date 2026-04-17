/*
 * at_custom_hid_cmd.h — BLE HID Keyboard AT Commands
 */

#ifndef AT_CUSTOM_HID_CMD_H
#define AT_CUSTOM_HID_CMD_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

/**
 * Register BLE HID AT commands:
 *   AT+BLEHIDINIT=<mode>          Initialize/deinitialize HID (1=enable, 0=disable)
 *   AT+BLEHIDINIT?                Query HID initialization state
 *   AT+BLEHIDADV=<enable>         Start/stop HID advertising (1=start, 0=stop)
 *   AT+BLEHIDKB=<mod>,<k1>,...    Send keyboard report (modifier + 6 keycodes)
 */
bool esp_at_custom_hid_cmd_register(void);

esp_err_t m1_ble_hid_init(bool enable);
esp_err_t m1_ble_hid_send_keyboard_report(uint8_t modifier,
                                          const uint8_t *keys,
                                          uint8_t key_count);
bool m1_ble_hid_is_ready(void);

#endif /* AT_CUSTOM_HID_CMD_H */
