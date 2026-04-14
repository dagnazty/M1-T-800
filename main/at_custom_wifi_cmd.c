/*
 * at_custom_wifi_cmd.c — M1 SPI Wi-Fi utility AT commands
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_at.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#include "at_custom_wifi_cmd.h"

static uint8_t at_query_cmd_m1wifistats(uint8_t *cmd_name)
{
#define AT_M1WIFISTATS_BUFFER_LEN 160
    uint8_t buffer[AT_M1WIFISTATS_BUFFER_LEN] = {0};
    wifi_mode_t wifi_mode = WIFI_MODE_NULL;
    wifi_ap_record_t ap_info = {0};
    esp_netif_ip_info_t ip_info = {0};
    esp_netif_t *sta_netif = NULL;
    const char *mode_text = "NULL";
    const char *ip_text = "0.0.0.0";
    char bssid[18] = "00:00:00:00:00:00";
    char ip_addr[16] = "0.0.0.0";
    bool connected = false;
    int rssi = 0;
    uint8_t channel = 0;

    if (esp_wifi_get_mode(&wifi_mode) == ESP_OK) {
        switch (wifi_mode) {
        case WIFI_MODE_STA:
            mode_text = "STA";
            break;
        case WIFI_MODE_AP:
            mode_text = "AP";
            break;
        case WIFI_MODE_APSTA:
            mode_text = "APSTA";
            break;
        case WIFI_MODE_NULL:
        default:
            mode_text = "NULL";
            break;
        }
    }

    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        connected = true;
        rssi = ap_info.rssi;
        channel = ap_info.primary;
        snprintf(bssid, sizeof(bssid), "%02x:%02x:%02x:%02x:%02x:%02x",
                 ap_info.bssid[0], ap_info.bssid[1], ap_info.bssid[2],
                 ap_info.bssid[3], ap_info.bssid[4], ap_info.bssid[5]);
    }

    sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta_netif != NULL && esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK) {
        snprintf(ip_addr, sizeof(ip_addr), IPSTR, IP2STR(&ip_info.ip));
        ip_text = ip_addr;
    }

    snprintf((char *)buffer, sizeof(buffer), "%s:%d,%s,%d,%u,\"%s\",\"%s\"\r\n",
             cmd_name, connected ? 1 : 0, mode_text, rssi, channel, bssid, ip_text);
    esp_at_port_write_data(buffer, strlen((char *)buffer));
    return ESP_AT_RESULT_CODE_OK;
}

static const esp_at_cmd_struct s_wifi_cmd_list[] = {
    {"+M1WIFISTATS", NULL, at_query_cmd_m1wifistats, NULL, NULL},
};

bool esp_at_custom_wifi_cmd_register(void)
{
    return esp_at_custom_cmd_array_regist(
        s_wifi_cmd_list,
        sizeof(s_wifi_cmd_list) / sizeof(s_wifi_cmd_list[0]));
}
