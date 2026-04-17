/**
 * M1 RPC — System command handler (ping, version, heap, OTA, reset).
 */

#include <string.h>
#include "m1_rpc.h"
#include "m1_rpc_proto.h"
#include "m1_rpc_system.h"

#include "esp_system.h"
#include "esp_ota_ops.h"
#include "esp_log.h"

static const char *TAG = "M1_Sys";

static m1_status_t cmd_ping(const uint8_t *payload, uint16_t len,
                             uint8_t *resp, uint16_t *resp_len)
{
    if (len >= 4) {
        memcpy(resp, payload, 4);
        *resp_len = 4;
    } else {
        *resp_len = 0;
    }
    return M1_OK;
}

static m1_status_t cmd_get_fw_version(const uint8_t *payload, uint16_t len,
                                      uint8_t *resp, uint16_t *resp_len)
{
    resp[0] = 0; /* major */
    resp[1] = 1; /* minor */
    resp[2] = 0; /* patch */
    /* git hash — stub, fill from build */
    memset(resp + 3, 0, 16);
    *resp_len = 19;
    return M1_OK;
}

static m1_status_t cmd_get_heap(const uint8_t *payload, uint16_t len,
                                 uint8_t *resp, uint16_t *resp_len)
{
    uint32_t free = esp_get_free_heap_size();
    uint32_t min  = esp_get_minimum_free_heap_size();
    memcpy(resp, &free, 4);
    memcpy(resp + 4, &min, 4);
    *resp_len = 8;
    return M1_OK;
}

static m1_status_t cmd_reset(const uint8_t *payload, uint16_t len,
                              uint8_t *resp, uint16_t *resp_len)
{
    esp_restart();
    return M1_OK; /* unreachable */
}

static m1_status_t cmd_ota_begin(const uint8_t *payload, uint16_t len,
                                  uint8_t *resp, uint16_t *resp_len)
{
    /* TODO: implement OTA flow */
    return M1_ERR_UNSUPPORTED;
}

static m1_status_t cmd_ota_data(const uint8_t *payload, uint16_t len,
                                uint8_t *resp, uint16_t *resp_len)
{
    return M1_ERR_UNSUPPORTED;
}

static m1_status_t cmd_ota_end(const uint8_t *payload, uint16_t len,
                                uint8_t *resp, uint16_t *resp_len)
{
    return M1_ERR_UNSUPPORTED;
}

m1_status_t m1_rpc_sys_handler(uint16_t msg_id,
                                const uint8_t *payload,
                                uint16_t payload_len,
                                uint8_t *resp_buf,
                                uint16_t *resp_len)
{
    switch (msg_id) {
        case M1_MSG_SYS_PING:           return cmd_ping(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_SYS_GET_FW_VERSION: return cmd_get_fw_version(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_SYS_GET_HEAP:       return cmd_get_heap(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_SYS_RESET:          return cmd_reset(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_SYS_OTA_BEGIN:      return cmd_ota_begin(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_SYS_OTA_DATA:       return cmd_ota_data(payload, payload_len, resp_buf, resp_len);
        case M1_MSG_SYS_OTA_END:        return cmd_ota_end(payload, payload_len, resp_buf, resp_len);
        default:                        return M1_ERR_UNSUPPORTED;
    }
}
