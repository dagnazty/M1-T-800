/*
 * at_custom_espnow_cmd.c — M1 Link over ESP-NOW (remote trigger) AT commands
 *
 * Phase 0 spike. Second transport for the M1 remote-trigger feature already
 * proven over the Si4463 sub-GHz radio (M1_T-1000 "M1 Link"). Here the trigger
 * rides the ESP32-C6's 2.4 GHz radio via ESP-NOW: unit A tells its ESP to send
 * an ACK'd trigger to a paired peer, the peer's ESP raises an unsolicited event
 * to its M1, and the M1 runs the named payload (Phase 0 target: BadUSB).
 *
 * Full design, wire format, and safety model: docs/ESPNOW_LINK_DESIGN.md
 *
 * Custom AT commands:
 *   AT+M1ESPNOW=<enable>[,<channel>]     — bring ESP-NOW up/down (channel 1-13)
 *   AT+M1ESPNOW?                         — report state (enabled, channel, MAC)
 *   AT+M1ESPNOWKEY=<passphrase>          — set shared key (encrypted peers)
 *   AT+M1ESPNOWSCAN=<seconds>            — broadcast HELLO, list peers
 *   AT+M1ESPNOWTRIG=<mac>,<ptype>,<name> — send an ACK'd trigger to a peer
 *
 * Unsolicited output (ESP -> M1), the upcall that runs the payload:
 *   +ESPNOWRX:<src_mac>,<ptype>,<enc>,<name>
 *   +ESPNOWPEER:<src_mac>,<name>,<rssi>   (during a scan)
 *
 * Radio note: ESP-NOW shares the 2.4 GHz radio and current channel with the
 * offensive Wi-Fi modes (monitor/deauth/beacon/eviltwin) and BLE. They cannot
 * both own the radio at once; the spike assumes no Wi-Fi attack is running.
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "esp_at.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

#include "at_custom_espnow_cmd.h"

#define TAG "M1ESPNOW"

/* ── Wire format (see design doc §3) ─────────────────────────────── */
/* magic 0x4D31 ("M1", LE) -> on-wire bytes {0x31, 0x4D} */
#define ENOW_MAGIC0        0x31
#define ENOW_MAGIC1        0x4D
#define ENOW_VERSION       0x01
#define ENOW_HDR_LEN       6      /* magic(2) ver(1) type(1) flags(1) seq(1) */

/* PDU types */
#define ENOW_TYPE_DATA     0x01
#define ENOW_TYPE_ACK      0x02
#define ENOW_TYPE_HELLO    0x03

/* flags */
#define ENOW_FLAG_ACKREQ   0x01
#define ENOW_FLAG_ENC      0x02

/* payload types — MUST match M1_LINK_TRIG_* in the M1 firmware (m1_link.h) */
#define ENOW_PTYPE_SUB     1
#define ENOW_PTYPE_BADUSB  2   /* Phase 0 target */
#define ENOW_PTYPE_BADBT   3   /* excluded from PoC (radio contention) */
#define ENOW_PTYPE_IR      4

#define ENOW_DEFAULT_CHANNEL   1
#define ENOW_ACK_TIMEOUT_MS    120
#define ENOW_TRIG_RETRIES      4
#define ENOW_RX_QUEUE_DEPTH    16
#define ENOW_MAX_NAME_LEN      64
#define ENOW_CALLSIGN_LEN      16
#define ENOW_MAX_PAIRS         8
#define ENOW_FILE_CHUNK        32    /* file bytes per fragment. Bounded by the
                                      * ESP-NOW frame (250B): 6 hdr + 16 IV +
                                      * AES-pad(6 + name<=64 + 128) ~= 230 < 250.
                                      * The M1->ESP AT command (name + 2*chunk hex)
                                      * rides the 8KB SPI stream buffer, not a
                                      * small line cap. MUST match the M1 side. */

/* TRIG/FILE body (plaintext, then AES-encrypted):
 *   [magic(2)][ptype(1)][frag(1)][total(1)][namelen(1)][name][data...]
 * data length = body_len - (5 + namelen). datalen 0 = name-only trigger (run an
 * existing file); datalen > 0 = one file fragment (reassemble frag/total). */
#define ENOW_BODY_HDR          6     /* magic(2)+ptype+frag+total+namelen */

/* App-layer AES-256-CBC (mbedTLS). The whole TRIG body is encrypted; ESP-NOW
 * peers stay UNENCRYPTED at the link layer (no native-LMK pairing needed). */
#define ENOW_AES_KEYLEN        32
#define ENOW_AES_BLOCK         16     /* IV size == block size */
/* 2-byte plaintext magic used to detect a wrong/absent key after decrypt. */
#define ENOW_PT_MAGIC0         0x4D
#define ENOW_PT_MAGIC1         0x31

static const uint8_t ENOW_BROADCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

/* ── State ───────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  src[6];
    int8_t   rssi;
    uint8_t  len;
    uint8_t  data[ESP_NOW_MAX_DATA_LEN];
} enow_rx_msg_t;

static bool             s_enabled = false;
static uint8_t          s_channel = ENOW_DEFAULT_CHANNEL;
static uint8_t          s_tx_seq  = 0;
static bool             s_have_key = false;
static uint8_t          s_aes_key[ENOW_AES_KEYLEN];
static char             s_callsign[ENOW_CALLSIGN_LEN] = "M1";

/* Pairing allowlist: if non-empty, triggers are only honored from these MACs. */
static uint8_t          s_pairs[ENOW_MAX_PAIRS][6];
static uint8_t          s_pair_count = 0;

static QueueHandle_t    s_rx_queue = NULL;
static TaskHandle_t     s_rx_task  = NULL;

/* ACK wait state (single outstanding trigger at a time in the spike) */
static SemaphoreHandle_t s_ack_sem = NULL;
static volatile uint8_t  s_ack_wait_seq = 0;
static volatile bool     s_ack_armed = false;

/* dedupe: last seq seen per... (spike: single-slot, last src+seq) */
static uint8_t  s_last_src[6];
static uint8_t  s_last_seq;
static bool     s_last_valid = false;

/* Received-trigger queue. Async +ESPNOWRX URCs get flushed by the M1's SPI-AT
 * response channel (it resets stale data before each command and only returns
 * UID-matched responses), so a one-shot trigger between polls is lost. Instead
 * we BUFFER passed triggers here and hand them to the M1 via the AT+M1ESPNOWRX?
 * query, whose response IS UID-matched and reliably delivered. */
typedef struct {
    char    mac[18];
    uint8_t ptype;
    uint8_t enc;
    uint8_t frag;                       /* fragment index */
    uint8_t total;                      /* total fragments (1 = whole/name-only) */
    char    name[ENOW_MAX_NAME_LEN + 1];
    uint8_t data[ENOW_FILE_CHUNK];      /* file bytes (datalen == 0 => name-only) */
    uint8_t datalen;
} enow_trig_t;
#define ENOW_TRIGQ_DEPTH 32   /* hold a whole small script's fragments until the
                               * M1 drains them (chunk 32 * 32 = 1 KB buffered) */
static enow_trig_t s_trigq[ENOW_TRIGQ_DEPTH];
static uint8_t     s_trigq_head = 0;   /* next to pop */
static uint8_t     s_trigq_count = 0;

static void trigq_push(const char *mac, uint8_t ptype, uint8_t enc,
                       uint8_t frag, uint8_t total, const char *name,
                       const uint8_t *data, uint8_t datalen)
{
    uint8_t slot = (uint8_t)((s_trigq_head + s_trigq_count) % ENOW_TRIGQ_DEPTH);
    if (s_trigq_count == ENOW_TRIGQ_DEPTH) {           /* full: drop oldest */
        s_trigq_head = (uint8_t)((s_trigq_head + 1) % ENOW_TRIGQ_DEPTH);
    } else {
        s_trigq_count++;
    }
    strlcpy(s_trigq[slot].mac, mac, sizeof(s_trigq[slot].mac));
    strlcpy(s_trigq[slot].name, name, sizeof(s_trigq[slot].name));
    s_trigq[slot].ptype = ptype;
    s_trigq[slot].enc   = enc;
    s_trigq[slot].frag  = frag;
    s_trigq[slot].total = total;
    if (datalen > ENOW_FILE_CHUNK) datalen = ENOW_FILE_CHUNK;
    if (data && datalen) memcpy(s_trigq[slot].data, data, datalen);
    s_trigq[slot].datalen = datalen;
}

/* Pop the oldest pending trigger/fragment into *out. Returns false if empty. */
static bool trigq_pop(enow_trig_t *out)
{
    if (s_trigq_count == 0) return false;
    *out = s_trigq[s_trigq_head];
    s_trigq_head = (uint8_t)((s_trigq_head + 1) % ENOW_TRIGQ_DEPTH);
    s_trigq_count--;
    return true;
}

/* hex helpers for carrying file bytes through the AT layer */
static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static uint8_t hex_decode(const char *hex, uint8_t *out, uint8_t out_cap)
{
    uint8_t n = 0;
    while (hex[0] && hex[1] && n < out_cap) {
        int hi = hexval(hex[0]), lo = hexval(hex[1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}
static void hex_encode(const uint8_t *in, uint8_t n, char *out /* >= 2n+1 */)
{
    static const char H[] = "0123456789ABCDEF";
    for (uint8_t i = 0; i < n; i++) { out[2*i] = H[in[i] >> 4]; out[2*i+1] = H[in[i] & 0xF]; }
    out[2*n] = '\0';
}

/* ── Helpers ─────────────────────────────────────────────────────── */

static bool parse_mac(const char *str, uint8_t out[6])
{
    unsigned int a,b,c,d,e,f;
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &a,&b,&c,&d,&e,&f) != 6) return false;
    out[0]=(uint8_t)a; out[1]=(uint8_t)b; out[2]=(uint8_t)c;
    out[3]=(uint8_t)d; out[4]=(uint8_t)e; out[5]=(uint8_t)f;
    return true;
}

static void format_mac(const uint8_t mac[6], char *dst /* >=18 */)
{
    snprintf(dst, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

static void at_send_line(const char *fmt, ...)
{
    char buf[320];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) esp_at_port_write_data((uint8_t *)buf, (uint32_t)n);
}

/* Derive a 32-byte AES-256 key from the passphrase: SHA-256(salt || pass).
 * Both units run this identically, so the same passphrase yields the same key.
 * The salt is a fixed firmware constant (domain separation, not a secret). */
static void derive_key(const char *pass, uint8_t out[ENOW_AES_KEYLEN])
{
    static const char SALT[] = "M1-ESPNOW-v1";
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0 /* SHA-256 */);
    mbedtls_sha256_update(&ctx, (const uint8_t *)SALT, sizeof(SALT) - 1);
    mbedtls_sha256_update(&ctx, (const uint8_t *)pass, strlen(pass));
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
}

/* Encrypt `plain` (plen bytes) into out=[IV(16)][ciphertext]. Zero-pads the
 * plaintext to a block boundary. Returns total length, or 0 on failure. */
static size_t aes_encrypt(const uint8_t *plain, size_t plen, uint8_t *out, size_t out_cap)
{
    size_t padded = ((plen + ENOW_AES_BLOCK - 1) / ENOW_AES_BLOCK) * ENOW_AES_BLOCK;
    if (padded == 0) padded = ENOW_AES_BLOCK;
    if (ENOW_AES_BLOCK + padded > out_cap) return 0;

    uint8_t iv[ENOW_AES_BLOCK];
    esp_fill_random(iv, sizeof(iv));
    memcpy(out, iv, ENOW_AES_BLOCK);         /* IV travels in the clear */

    uint8_t buf[ESP_NOW_MAX_DATA_LEN];
    if (padded > sizeof(buf)) return 0;
    memset(buf, 0, padded);
    memcpy(buf, plain, plen);                /* zero-padding */

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, s_aes_key, 256);
    int rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded, iv,
                                   buf, out + ENOW_AES_BLOCK);
    mbedtls_aes_free(&aes);
    return (rc == 0) ? (ENOW_AES_BLOCK + padded) : 0;
}

/* Decrypt in=[IV(16)][ciphertext] into out. Returns plaintext length, or 0. */
static size_t aes_decrypt(const uint8_t *in, size_t ilen, uint8_t *out, size_t out_cap)
{
    if (ilen <= ENOW_AES_BLOCK || (ilen - ENOW_AES_BLOCK) % ENOW_AES_BLOCK != 0)
        return 0;
    size_t clen = ilen - ENOW_AES_BLOCK;
    if (clen > out_cap) return 0;

    uint8_t iv[ENOW_AES_BLOCK];
    memcpy(iv, in, ENOW_AES_BLOCK);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, s_aes_key, 256);
    int rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, clen, iv,
                                   in + ENOW_AES_BLOCK, out);
    mbedtls_aes_free(&aes);
    return (rc == 0) ? clen : 0;
}

/* Pairing allowlist. Empty list = accept any sender (open); non-empty = only
 * the listed MACs may trigger us. */
static bool is_paired(const uint8_t mac[6])
{
    if (s_pair_count == 0) return true;             /* open until first pair */
    for (uint8_t i = 0; i < s_pair_count; i++)
        if (memcmp(s_pairs[i], mac, 6) == 0) return true;
    return false;
}

static bool add_pair(const uint8_t mac[6])
{
    for (uint8_t i = 0; i < s_pair_count; i++)
        if (memcmp(s_pairs[i], mac, 6) == 0) return true;   /* already paired */
    if (s_pair_count >= ENOW_MAX_PAIRS) return false;
    memcpy(s_pairs[s_pair_count++], mac, 6);
    return true;
}

/* Add a unicast peer for sending. Link-layer encryption is OFF — confidentiality
 * is handled at the app layer (AES above), which avoids ESP-NOW's bidirectional
 * per-peer LMK pairing requirement. */
static esp_err_t ensure_peer(const uint8_t mac[6])
{
    if (esp_now_is_peer_exist(mac)) return ESP_OK;

    esp_now_peer_info_t peer = {0};
    memcpy(peer.peer_addr, mac, 6);
    peer.channel = 0;               /* 0 = use current Wi-Fi channel */
    peer.ifidx   = WIFI_IF_STA;
    peer.encrypt = false;
    return esp_now_add_peer(&peer);
}

/* ── ESP-NOW callbacks (run in the Wi-Fi task; keep them light) ──── */

static void espnow_recv_cb(const esp_now_recv_info_t *info,
                           const uint8_t *data, int len)
{
    if (!s_enabled || !s_rx_queue || len < ENOW_HDR_LEN) return;
    if (data[0] != ENOW_MAGIC0 || data[1] != ENOW_MAGIC1) return;

    /* ACK is latency-critical — resolve it here without a task hop. */
    if (data[3] == ENOW_TYPE_ACK) {
        uint8_t acked = data[5];  /* seq field carries the acked seq */
        if (s_ack_armed && acked == s_ack_wait_seq) {
            s_ack_armed = false;
            xSemaphoreGive(s_ack_sem);
        }
        return;
    }

    enow_rx_msg_t msg;
    memcpy(msg.src, info->src_addr, 6);
    msg.rssi = info->rx_ctrl ? info->rx_ctrl->rssi : 0;
    msg.len  = (len > ESP_NOW_MAX_DATA_LEN) ? ESP_NOW_MAX_DATA_LEN : (uint8_t)len;
    memcpy(msg.data, data, msg.len);

    /* This callback runs in the Wi-Fi task (not an ISR) — use the plain,
     * non-blocking enqueue; drop the frame rather than block the Wi-Fi task. */
    xQueueSend(s_rx_queue, &msg, 0);
}

static void espnow_send_cb(const uint8_t *mac, esp_now_send_status_t status)
{
    (void)mac; (void)status;  /* delivery is confirmed by the app-level ACK */
}

/* Send an ACK PDU echoing `seq` back to `dst`. */
static void send_ack(const uint8_t dst[6], uint8_t seq)
{
    if (ensure_peer(dst) != ESP_OK) return;
    uint8_t f[ENOW_HDR_LEN];
    f[0]=ENOW_MAGIC0; f[1]=ENOW_MAGIC1; f[2]=ENOW_VERSION;
    f[3]=ENOW_TYPE_ACK; f[4]=0; f[5]=seq;
    esp_now_send(dst, f, sizeof(f));
}

/* ── RX task: ACK + dedupe + emit the +ESPNOWRX upcall ──────────── */

static void enow_rx_task(void *arg)
{
    (void)arg;
    enow_rx_msg_t msg;
    char mac_str[18];

    for (;;) {
        if (xQueueReceive(s_rx_queue, &msg, pdMS_TO_TICKS(200)) != pdTRUE) {
            if (!s_enabled) break;
            continue;
        }

        uint8_t type  = msg.data[3];
        uint8_t flags = msg.data[4];
        uint8_t seq   = msg.data[5];
        format_mac(msg.src, mac_str);

        if (type == ENOW_TYPE_HELLO) {
            /* body: [namelen][name] */
            char name[ENOW_CALLSIGN_LEN] = {0};
            if (msg.len > ENOW_HDR_LEN) {
                uint8_t nl = msg.data[ENOW_HDR_LEN];
                if (nl > ENOW_CALLSIGN_LEN - 1) nl = ENOW_CALLSIGN_LEN - 1;
                if (ENOW_HDR_LEN + 1 + nl <= msg.len)
                    memcpy(name, &msg.data[ENOW_HDR_LEN + 1], nl);
            }
            at_send_line("\r\n+ESPNOWPEER:%s,%s,%d\r\n", mac_str, name, msg.rssi);
            continue;
        }

        if (type == ENOW_TYPE_DATA) {
            /* ACK first (before anything else) so a retransmit can't double-fire. */
            if (flags & ENOW_FLAG_ACKREQ) send_ack(msg.src, seq);

            /* Dedupe by (src, seq) — drop retransmits after ACKing them. */
            if (s_last_valid && seq == s_last_seq &&
                memcmp(msg.src, s_last_src, 6) == 0) {
                continue;
            }
            memcpy(s_last_src, msg.src, 6);
            s_last_seq = seq;
            s_last_valid = true;

            /* Pairing gate: once any peer is paired, only paired MACs count. */
            if (!is_paired(msg.src)) continue;

            uint8_t enc = (flags & ENOW_FLAG_ENC) ? 1 : 0;
            uint8_t body[ESP_NOW_MAX_DATA_LEN];
            size_t  blen = 0;

            if (enc) {
                /* Encrypted-only path: need our key + a valid decrypt. */
                if (!s_have_key) continue;                 /* can't decrypt -> drop */
                blen = aes_decrypt(&msg.data[ENOW_HDR_LEN],
                                   msg.len - ENOW_HDR_LEN, body, sizeof(body));
                /* Wrong/absent key -> plaintext magic won't match -> drop. */
                if (blen < ENOW_BODY_HDR || body[0] != ENOW_PT_MAGIC0 || body[1] != ENOW_PT_MAGIC1)
                    continue;
            } else {
                /* Plaintext trigger. Refuse it if we hold a key (encrypted-only
                 * execution): a keyed receiver must not run unencrypted triggers. */
                if (s_have_key) continue;
                if (msg.len < ENOW_HDR_LEN + ENOW_BODY_HDR) continue;
                blen = msg.len - ENOW_HDR_LEN;
                memcpy(body, &msg.data[ENOW_HDR_LEN], blen);
                if (body[0] != ENOW_PT_MAGIC0 || body[1] != ENOW_PT_MAGIC1) continue;
            }

            /* body = [magic(2)][ptype][frag][total][namelen][name][data] */
            uint8_t ptype   = body[2];
            uint8_t frag    = body[3];
            uint8_t total   = body[4];
            uint8_t namelen = body[5];
            if (namelen > ENOW_MAX_NAME_LEN) namelen = ENOW_MAX_NAME_LEN;
            if ((size_t)(ENOW_BODY_HDR + namelen) > blen) continue;
            char name[ENOW_MAX_NAME_LEN + 1] = {0};
            memcpy(name, &body[ENOW_BODY_HDR], namelen);

            const uint8_t *data = &body[ENOW_BODY_HDR + namelen];
            size_t datalen = blen - ENOW_BODY_HDR - namelen;
            if (datalen > ENOW_FILE_CHUNK) datalen = ENOW_FILE_CHUNK;

            /* Buffer for reliable delivery via AT+M1ESPNOWRX? (see trigq). The M1
             * reassembles file fragments (datalen>0) or runs an existing file
             * (datalen==0). Only reached after the pairing + decryption gates. */
            trigq_push(mac_str, ptype, enc, frag, total, name, data, (uint8_t)datalen);
            continue;
        }
    }

    s_rx_task = NULL;
    vTaskDelete(NULL);
}

/* ── Bring-up / teardown ─────────────────────────────────────────── */

static esp_err_t enow_start(uint8_t channel)
{
    if (s_enabled) {  /* already up — just retune */
        s_channel = channel;
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        return ESP_OK;
    }

    /* ESP-NOW needs Wi-Fi started with a station interface. app_main already
     * inits+starts Wi-Fi; ensure a mode that has STA without stomping AP. */
    wifi_mode_t mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_NULL)      esp_wifi_set_mode(WIFI_MODE_STA);
    else if (mode == WIFI_MODE_AP)   esp_wifi_set_mode(WIFI_MODE_APSTA);

    /* Keep the radio always-on. An unassociated STA in power-save sleeps
     * between beacons and misses unicast ESP-NOW frames (broadcast still gets
     * through), so peers hear each other's HELLO but unicast DATA/ACK is lost.
     * WIFI_PS_NONE is required for reliable ESP-NOW here. */
    esp_wifi_set_ps(WIFI_PS_NONE);

    esp_err_t err = esp_now_init();
    if (err != ESP_OK) { ESP_LOGE(TAG, "esp_now_init: %s", esp_err_to_name(err)); return err; }

    esp_now_register_recv_cb(espnow_recv_cb);
    esp_now_register_send_cb(espnow_send_cb);

    /* Broadcast peer for HELLO (always unencrypted). */
    esp_now_peer_info_t bc = {0};
    memcpy(bc.peer_addr, ENOW_BROADCAST, 6);
    bc.channel = 0; bc.ifidx = WIFI_IF_STA; bc.encrypt = false;
    esp_now_add_peer(&bc);

    s_rx_queue = xQueueCreate(ENOW_RX_QUEUE_DEPTH, sizeof(enow_rx_msg_t));
    if (!s_rx_queue) { esp_now_deinit(); return ESP_ERR_NO_MEM; }
    if (!s_ack_sem) s_ack_sem = xSemaphoreCreateBinary();

    s_channel = channel;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    s_enabled = true;

    if (xTaskCreate(enow_rx_task, "enow_rx", 4096, NULL, 5, &s_rx_task) != pdPASS) {
        s_enabled = false;
        vQueueDelete(s_rx_queue); s_rx_queue = NULL;
        esp_now_deinit();
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "ESP-NOW up on channel %u", channel);
    return ESP_OK;
}

static esp_err_t enow_stop(void)
{
    if (!s_enabled) return ESP_OK;
    s_enabled = false;
    /* let the rx task observe s_enabled=false and exit */
    for (int i = 0; i < 25 && s_rx_task; i++) vTaskDelay(pdMS_TO_TICKS(10));
    if (s_rx_task) { vTaskDelete(s_rx_task); s_rx_task = NULL; }
    if (s_rx_queue) { vQueueDelete(s_rx_queue); s_rx_queue = NULL; }
    esp_now_unregister_recv_cb();
    esp_now_deinit();
    s_last_valid = false;
    ESP_LOGI(TAG, "ESP-NOW down");
    return ESP_OK;
}

/* Broadcast a HELLO beacon carrying our callsign. */
static void send_hello(void)
{
    uint8_t f[ENOW_HDR_LEN + 1 + ENOW_CALLSIGN_LEN];
    f[0]=ENOW_MAGIC0; f[1]=ENOW_MAGIC1; f[2]=ENOW_VERSION;
    f[3]=ENOW_TYPE_HELLO; f[4]=0; f[5]=s_tx_seq++;
    uint8_t nl = (uint8_t)strnlen(s_callsign, ENOW_CALLSIGN_LEN - 1);
    f[ENOW_HDR_LEN] = nl;
    memcpy(&f[ENOW_HDR_LEN + 1], s_callsign, nl);
    esp_now_send(ENOW_BROADCAST, f, ENOW_HDR_LEN + 1 + nl);
}

/* Build+send one DATA frame carrying a body fragment, wait for ACK, retry.
 * body = [magic(2)][ptype][frag][total][namelen][name][data]. Encrypted when a
 * passphrase is set (ENC flag), else clear. Returns true once ACKed. */
static bool send_body(const uint8_t mac[6], uint8_t ptype, uint8_t frag, uint8_t total,
                      const char *name, const uint8_t *data, uint8_t datalen)
{
    if (ensure_peer(mac) != ESP_OK) return false;

    uint8_t namelen = (uint8_t)strnlen(name, ENOW_MAX_NAME_LEN);
    if (datalen > ENOW_FILE_CHUNK) datalen = ENOW_FILE_CHUNK;

    uint8_t body[ENOW_BODY_HDR + ENOW_MAX_NAME_LEN + ENOW_FILE_CHUNK];
    body[0]=ENOW_PT_MAGIC0; body[1]=ENOW_PT_MAGIC1;
    body[2]=ptype; body[3]=frag; body[4]=total; body[5]=namelen;
    memcpy(&body[ENOW_BODY_HDR], name, namelen);
    if (data && datalen) memcpy(&body[ENOW_BODY_HDR + namelen], data, datalen);
    size_t blen = ENOW_BODY_HDR + namelen + datalen;

    uint8_t f[ENOW_HDR_LEN + ENOW_AES_BLOCK + sizeof(body) + ENOW_AES_BLOCK];
    uint8_t seq = s_tx_seq++;
    uint8_t flags = ENOW_FLAG_ACKREQ;
    size_t payload_len;

    if (s_have_key) {
        payload_len = aes_encrypt(body, blen, &f[ENOW_HDR_LEN],
                                  sizeof(f) - ENOW_HDR_LEN);
        if (payload_len == 0) return false;
        flags |= ENOW_FLAG_ENC;
    } else {
        memcpy(&f[ENOW_HDR_LEN], body, blen);
        payload_len = blen;
    }

    f[0]=ENOW_MAGIC0; f[1]=ENOW_MAGIC1; f[2]=ENOW_VERSION;
    f[3]=ENOW_TYPE_DATA; f[4]=flags; f[5]=seq;
    uint8_t flen = (uint8_t)(ENOW_HDR_LEN + payload_len);

    for (int attempt = 0; attempt < ENOW_TRIG_RETRIES; attempt++) {
        s_ack_wait_seq = seq;
        s_ack_armed = true;
        xSemaphoreTake(s_ack_sem, 0);  /* drain any stale give */
        if (esp_now_send(mac, f, flen) != ESP_OK) { s_ack_armed = false; continue; }
        if (xSemaphoreTake(s_ack_sem, pdMS_TO_TICKS(ENOW_ACK_TIMEOUT_MS)) == pdTRUE)
            return true;
        s_ack_armed = false;
    }
    return false;
}

/* Name-only trigger (run an existing file on the peer): no data. */
static bool send_trigger(const uint8_t mac[6], uint8_t ptype, const char *name)
{
    return send_body(mac, ptype, 0, 1, name, NULL, 0);
}

/* ── AT command handlers ─────────────────────────────────────────── */

/* AT+M1ESPNOW? */
static uint8_t at_query_espnow(uint8_t *cmd_name)
{
    (void)cmd_name;
    uint8_t mac[6] = {0};
    esp_wifi_get_mac(WIFI_IF_STA, mac);
    char mac_str[18];
    format_mac(mac, mac_str);
    at_send_line("+M1ESPNOW:%d,%u,%s,%d\r\n",
                 s_enabled ? 1 : 0, s_channel, mac_str, s_have_key ? 1 : 0);
    return ESP_AT_RESULT_CODE_OK;
}

/* AT+M1ESPNOW=<enable>[,<channel>] */
static uint8_t at_setup_espnow(uint8_t para_num)
{
    int32_t enable = 0, channel = ENOW_DEFAULT_CHANNEL;
    if (esp_at_get_para_as_digit(0, &enable) != ESP_AT_PARA_PARSE_RESULT_OK)
        return ESP_AT_RESULT_CODE_ERROR;

    if (enable == 0)
        return (enow_stop() == ESP_OK) ? ESP_AT_RESULT_CODE_OK : ESP_AT_RESULT_CODE_ERROR;

    if (para_num >= 2 &&
        esp_at_get_para_as_digit(1, &channel) != ESP_AT_PARA_PARSE_RESULT_OK)
        return ESP_AT_RESULT_CODE_ERROR;
    if (channel < 1 || channel > 13) return ESP_AT_RESULT_CODE_ERROR;

    return (enow_start((uint8_t)channel) == ESP_OK)
        ? ESP_AT_RESULT_CODE_OK : ESP_AT_RESULT_CODE_ERROR;
}

/* AT+M1ESPNOWKEY=<passphrase>  (empty string clears the key) */
static uint8_t at_setup_espnow_key(uint8_t para_num)
{
    uint8_t *pass = NULL;
    if (para_num < 1 ||
        esp_at_get_para_as_str(0, &pass) != ESP_AT_PARA_PARSE_RESULT_OK || !pass)
        return ESP_AT_RESULT_CODE_ERROR;

    if (pass[0] == '\0') {                 /* clear */
        s_have_key = false;
        memset(s_aes_key, 0, sizeof(s_aes_key));
    } else {
        derive_key((const char *)pass, s_aes_key);
        s_have_key = true;
    }
    return ESP_AT_RESULT_CODE_OK;
}

/* AT+M1ESPNOWPAIR=<mac>   add a MAC to the allowlist
 * AT+M1ESPNOWPAIR?        list paired MACs (+ESPNOWPAIRED lines) */
static uint8_t at_setup_espnow_pair(uint8_t para_num)
{
    uint8_t *mac_str = NULL;
    uint8_t mac[6];
    if (para_num < 1 ||
        esp_at_get_para_as_str(0, &mac_str) != ESP_AT_PARA_PARSE_RESULT_OK ||
        !mac_str || !parse_mac((const char *)mac_str, mac))
        return ESP_AT_RESULT_CODE_ERROR;
    return add_pair(mac) ? ESP_AT_RESULT_CODE_OK : ESP_AT_RESULT_CODE_ERROR;
}

static uint8_t at_query_espnow_pair(uint8_t *cmd_name)
{
    (void)cmd_name;
    char mac_str[18];
    for (uint8_t i = 0; i < s_pair_count; i++) {
        format_mac(s_pairs[i], mac_str);
        at_send_line("+ESPNOWPAIRED:%s\r\n", mac_str);
    }
    return ESP_AT_RESULT_CODE_OK;
}

/* AT+M1ESPNOWRX?  — pop one pending received trigger (UID-matched, reliable).
 * Emits +M1ESPNOWRX:<mac>,<ptype>,<enc>,<name> if one is queued, else nothing. */
static uint8_t at_query_espnow_rx(uint8_t *cmd_name)
{
    (void)cmd_name;
    enow_trig_t t;
    if (trigq_pop(&t)) {
        char hex[2 * ENOW_FILE_CHUNK + 1];
        hex_encode(t.data, t.datalen, hex);
        /* +M1ESPNOWRX:<mac>,<ptype>,<frag>,<total>,<enc>,<name>,<hexdata> */
        at_send_line("+M1ESPNOWRX:%s,%u,%u,%u,%u,%s,%s\r\n",
                     t.mac, t.ptype, t.frag, t.total, t.enc, t.name, hex);
    }
    return ESP_AT_RESULT_CODE_OK;
}

/* AT+M1ESPNOWSCAN=<seconds> */
static uint8_t at_setup_espnow_scan(uint8_t para_num)
{
    int32_t secs = 3;
    if (para_num >= 1 &&
        esp_at_get_para_as_digit(0, &secs) != ESP_AT_PARA_PARSE_RESULT_OK)
        return ESP_AT_RESULT_CODE_ERROR;
    if (!s_enabled) return ESP_AT_RESULT_CODE_ERROR;
    if (secs < 1) secs = 1;
    if (secs > 30) secs = 30;

    /* Beacon once per second; peers surface as +ESPNOWPEER via the rx task. */
    for (int32_t i = 0; i < secs; i++) {
        send_hello();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    return ESP_AT_RESULT_CODE_OK;
}

/* AT+M1ESPNOWTRIG=<mac>,<ptype>,<name> */
static uint8_t at_setup_espnow_trig(uint8_t para_num)
{
    uint8_t *mac_str = NULL, *name = NULL;
    int32_t ptype = 0;
    uint8_t mac[6];

    if (para_num < 3) return ESP_AT_RESULT_CODE_ERROR;
    if (esp_at_get_para_as_str(0, &mac_str) != ESP_AT_PARA_PARSE_RESULT_OK ||
        !mac_str || !parse_mac((const char *)mac_str, mac))
        return ESP_AT_RESULT_CODE_ERROR;
    if (esp_at_get_para_as_digit(1, &ptype) != ESP_AT_PARA_PARSE_RESULT_OK)
        return ESP_AT_RESULT_CODE_ERROR;
    if (esp_at_get_para_as_str(2, &name) != ESP_AT_PARA_PARSE_RESULT_OK || !name)
        return ESP_AT_RESULT_CODE_ERROR;
    if (!s_enabled) return ESP_AT_RESULT_CODE_ERROR;

    return send_trigger(mac, (uint8_t)ptype, (const char *)name)
        ? ESP_AT_RESULT_CODE_OK : ESP_AT_RESULT_CODE_ERROR;
}

/* AT+M1ESPNOWSEND=<mac>,<ptype>,<name>,<frag>,<total>,<hexdata>
 * Send one file fragment. The M1 reads the script, splits it into <=160-byte
 * chunks, and calls this once per chunk; the peer reassembles + runs it. */
static uint8_t at_setup_espnow_send(uint8_t para_num)
{
    uint8_t *mac_str = NULL, *name = NULL, *hex = NULL;
    int32_t ptype = 0, frag = 0, total = 1;
    uint8_t mac[6];

    if (para_num < 6) return ESP_AT_RESULT_CODE_ERROR;
    if (esp_at_get_para_as_str(0, &mac_str) != ESP_AT_PARA_PARSE_RESULT_OK ||
        !mac_str || !parse_mac((const char *)mac_str, mac))
        return ESP_AT_RESULT_CODE_ERROR;
    if (esp_at_get_para_as_digit(1, &ptype) != ESP_AT_PARA_PARSE_RESULT_OK)
        return ESP_AT_RESULT_CODE_ERROR;
    if (esp_at_get_para_as_str(2, &name) != ESP_AT_PARA_PARSE_RESULT_OK || !name)
        return ESP_AT_RESULT_CODE_ERROR;
    if (esp_at_get_para_as_digit(3, &frag) != ESP_AT_PARA_PARSE_RESULT_OK)
        return ESP_AT_RESULT_CODE_ERROR;
    if (esp_at_get_para_as_digit(4, &total) != ESP_AT_PARA_PARSE_RESULT_OK)
        return ESP_AT_RESULT_CODE_ERROR;
    if (esp_at_get_para_as_str(5, &hex) != ESP_AT_PARA_PARSE_RESULT_OK || !hex)
        return ESP_AT_RESULT_CODE_ERROR;
    if (!s_enabled) return ESP_AT_RESULT_CODE_ERROR;

    uint8_t data[ENOW_FILE_CHUNK];
    uint8_t datalen = hex_decode((const char *)hex, data, sizeof(data));

    return send_body(mac, (uint8_t)ptype, (uint8_t)frag, (uint8_t)total,
                     (const char *)name, data, datalen)
        ? ESP_AT_RESULT_CODE_OK : ESP_AT_RESULT_CODE_ERROR;
}

/* ── Registration ────────────────────────────────────────────────── */

static const esp_at_cmd_struct s_espnow_cmd_list[] = {
    {"+M1ESPNOW",     NULL, at_query_espnow,      at_setup_espnow,      NULL},
    {"+M1ESPNOWKEY",  NULL, NULL,                 at_setup_espnow_key,  NULL},
    {"+M1ESPNOWSCAN", NULL, NULL,                 at_setup_espnow_scan, NULL},
    {"+M1ESPNOWTRIG", NULL, NULL,                 at_setup_espnow_trig, NULL},
    {"+M1ESPNOWSEND", NULL, NULL,                 at_setup_espnow_send, NULL},
    {"+M1ESPNOWPAIR", NULL, at_query_espnow_pair, at_setup_espnow_pair, NULL},
    {"+M1ESPNOWRX",   NULL, at_query_espnow_rx,   NULL,                 NULL},
};

bool esp_at_custom_espnow_cmd_register(void)
{
    return esp_at_custom_cmd_array_regist(
        s_espnow_cmd_list,
        sizeof(s_espnow_cmd_list) / sizeof(s_espnow_cmd_list[0]));
}
