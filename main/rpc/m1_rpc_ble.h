#pragma once

#include "m1_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

m1_status_t m1_rpc_ble_handler(uint16_t msg_id,
                               const uint8_t *payload,
                               uint16_t payload_len,
                               uint8_t *resp_buf,
                               uint16_t *resp_len);

/* Public entry points so the AT command layer can drive BLE spam directly.
 * mode is a bitmask: 0x01 Apple, 0x02 Google, 0x04 Microsoft (0 = all). */
m1_status_t m1_ble_spam_start(uint8_t mode);
m1_status_t m1_ble_spam_stop(void);

#ifdef __cplusplus
}
#endif
