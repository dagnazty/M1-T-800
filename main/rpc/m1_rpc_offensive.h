#pragma once

#include "m1_rpc_proto.h"
#include "m1_rpc.h"

m1_status_t m1_rpc_off_wifi_handler(uint16_t msg_id,
                                     const uint8_t *payload,
                                     uint16_t payload_len,
                                     uint8_t *resp_buf,
                                     uint16_t *resp_len);
