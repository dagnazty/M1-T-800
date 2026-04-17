/*
 * at_custom_zigbee_cmd.h — IEEE 802.15.4 Sniffer AT Commands
 */

#ifndef AT_CUSTOM_ZIGBEE_CMD_H
#define AT_CUSTOM_ZIGBEE_CMD_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

typedef void (*m1_zigbee_frame_callback_t)(const uint8_t *frame,
                                           uint8_t len,
                                           uint8_t channel,
                                           int8_t rssi,
                                           uint8_t lqi,
                                           void *ctx);

/**
 * Register IEEE 802.15.4 sniffer AT commands:
 *   AT+ZIGSNIFF=1,<ch>  Start sniffing on channel 11-26
 *   AT+ZIGSNIFF=0       Stop sniffing
 *   AT+ZIGSNIFF?        Query status
 *
 * Captured frames output as:
 *   +ZIGFRAME:<proto>,<ftype>,<len>,<ch>,<rssi>,<lqi>,<dst_pan>,<dst_addr>,<src_pan>,<src_addr>,<hex>
 *   proto: Z=Zigbee, T=Thread, U=unknown
 *   ftype: BCN, DATA, ACK, CMD
 */
bool esp_at_custom_zigbee_cmd_register(void);

esp_err_t m1_zigbee_init(bool enable);
esp_err_t m1_zigbee_sniffer_start(uint8_t channel);
esp_err_t m1_zigbee_sniffer_stop(void);
bool m1_zigbee_sniffer_is_running(void);
uint8_t m1_zigbee_sniffer_channel(void);
void m1_zigbee_set_frame_callback(m1_zigbee_frame_callback_t callback, void *ctx);

#endif /* AT_CUSTOM_ZIGBEE_CMD_H */
