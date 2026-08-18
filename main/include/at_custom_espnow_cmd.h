/*
 * at_custom_espnow_cmd.h — M1 Link over ESP-NOW (remote trigger) AT commands
 *
 * See docs/ESPNOW_LINK_DESIGN.md for the full design and wire format.
 */

#ifndef AT_CUSTOM_ESPNOW_CMD_H
#define AT_CUSTOM_ESPNOW_CMD_H

#include <stdbool.h>

/* Register the AT+M1ESPNOW* command family. Call once at startup, next to the
 * other esp_at_custom_*_cmd_register() calls in the SPI/UART task. */
bool esp_at_custom_espnow_cmd_register(void);

#endif /* AT_CUSTOM_ESPNOW_CMD_H */
