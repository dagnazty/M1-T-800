/*
 * at_custom_zigbee_cmd.c — IEEE 802.15.4 (Zigbee/Thread) Sniffer AT Commands
 *
 * Custom AT commands:
 *   AT+ZIGSNIFF=1,<channel>  — Start sniffing on channel (11-26)
 *   AT+ZIGSNIFF=0            — Stop sniffing
 *   AT+ZIGSNIFF?             — Query sniff status and channel
 *
 * Captured frames are output as unsolicited responses:
 *   +ZIGFRAME:<proto>,<ftype>,<len>,<ch>,<rssi>,<lqi>,<dst_pan>,<dst_addr>,<src_pan>,<src_addr>,<hex_data>
 *
 * Where:
 *   proto    = Z (Zigbee), T (Thread), U (unknown)
 *   ftype    = BCN (beacon), DATA, ACK, CMD
 *   dst_pan  = 4-hex-digit destination PAN ID (0000 if absent)
 *   dst_addr = 4 or 16 hex-digit destination address (empty if absent)
 *   src_pan  = 4-hex-digit source PAN ID (0000 if absent/compressed)
 *   src_addr = 4 or 16 hex-digit source address (empty if absent)
 *
 * Uses ESP32-C6 native IEEE 802.15.4 radio in promiscuous mode.
 * Coexists with WiFi/BLE via hardware RF arbitration.
 */

#include <string.h>
#include <stdio.h>

#include "esp_at.h"
#include "esp_log.h"
#include "esp_ieee802154.h"
#include "soc/ieee802154_reg.h"
#include "soc/soc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "at_custom_zigbee_cmd.h"

#define TAG "ZIGSNIFF"

/* Max 802.15.4 frame is 127 bytes */
#define MAX_FRAME_LEN 128

/* Queue depth for ISR→task handoff */
#define FRAME_QUEUE_DEPTH 64
#define SNIFFER_STOP_WAIT_MS 500
#define SNIFFER_STOP_POLL_MS 10

/* 802.15.4 Frame Control field bit masks */
#define FCF_FRAME_TYPE_MASK   0x0007
#define FCF_SEC_ENABLED       0x0008
#define FCF_FRAME_PENDING     0x0010
#define FCF_ACK_REQ           0x0020
#define FCF_PAN_COMPRESS      0x0040
#define FCF_DST_ADDR_MASK     0x0C00
#define FCF_FRAME_VER_MASK    0x3000
#define FCF_SRC_ADDR_MASK     0xC000

/* Frame types */
#define FRAME_TYPE_BEACON  0
#define FRAME_TYPE_DATA    1
#define FRAME_TYPE_ACK     2
#define FRAME_TYPE_CMD     3

/* Address modes */
#define ADDR_MODE_NONE     0
#define ADDR_MODE_SHORT    2
#define ADDR_MODE_LONG     3

/* ========================================================================
 * Frame Queue (ISR → task)
 * ======================================================================== */

typedef struct {
    uint8_t  data[MAX_FRAME_LEN];
    uint8_t  len;
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  lqi;
} zigbee_frame_t;

static QueueHandle_t s_frame_queue = NULL;
static TaskHandle_t  s_output_task = NULL;
static bool          s_sniffing = false;
static bool          s_radio_enabled = false;
static uint8_t       s_channel = 0;
static m1_zigbee_frame_callback_t s_frame_callback = NULL;
static void *s_frame_callback_ctx = NULL;

/* ========================================================================
 * IEEE 802.15.4 Receive Callback (called from ISR context)
 * ======================================================================== */

void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info)
{
    if (!s_sniffing || !s_frame_queue) {
        /* Re-arm RX */
        esp_ieee802154_receive();
        return;
    }

    zigbee_frame_t zf;
    zf.len = frame[0];
    if (zf.len > MAX_FRAME_LEN - 1) {
        zf.len = MAX_FRAME_LEN - 1;
    }
    memcpy(zf.data, &frame[1], zf.len);
    zf.channel = frame_info->channel;
    zf.rssi    = frame_info->rssi;
    zf.lqi     = frame_info->lqi;

    /* Non-blocking enqueue from ISR */
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xQueueSendFromISR(s_frame_queue, &zf, &xHigherPriorityTaskWoken);

    /* Re-arm RX for next frame */
    esp_ieee802154_receive();

    if (xHigherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }
}

/* Other required callbacks (stubs) */
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack,
                                   esp_ieee802154_frame_info_t *ack_frame_info)
{
    /* Not used for sniffer */
}

void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error)
{
    /* Not used for sniffer */
}

void esp_ieee802154_receive_sfd_done(void)
{
    /* Not used */
}

void esp_ieee802154_energy_detect_done(int8_t power)
{
    /* Not used */
}

/* ========================================================================
 * Frame Parsing — extract MAC header fields and classify protocol
 * ======================================================================== */

typedef struct {
    uint8_t  frame_type;     /* 0=beacon, 1=data, 2=ack, 3=cmd */
    uint16_t fcf;            /* raw frame control field */
    uint8_t  seq_num;
    uint16_t dst_pan;
    uint8_t  dst_addr[8];
    uint8_t  dst_addr_len;   /* 0, 2, or 8 */
    uint16_t src_pan;
    uint8_t  src_addr[8];
    uint8_t  src_addr_len;   /* 0, 2, or 8 */
    uint8_t  hdr_len;        /* total MAC header length */
    char     proto;          /* 'Z'=Zigbee, 'T'=Thread, 'U'=unknown */
} parsed_frame_t;

static const char *frame_type_str(uint8_t ft)
{
    switch (ft) {
        case FRAME_TYPE_BEACON: return "BCN";
        case FRAME_TYPE_DATA:   return "DATA";
        case FRAME_TYPE_ACK:    return "ACK";
        case FRAME_TYPE_CMD:    return "CMD";
        default:                return "UNK";
    }
}

static void hex_addr(const uint8_t *addr, uint8_t len, char *out)
{
    /* Format address as hex string, MSB first for readability */
    if (len == 0) {
        out[0] = '\0';
        return;
    }
    for (int i = len - 1; i >= 0; i--) {
        snprintf(out + (len - 1 - i) * 2, 3, "%02X", addr[i]);
    }
}

static void parse_frame(const uint8_t *data, uint8_t len, parsed_frame_t *pf)
{
    memset(pf, 0, sizeof(*pf));
    pf->proto = 'U';

    if (len < 2) return;

    /* Frame Control Field (little-endian) */
    pf->fcf = data[0] | ((uint16_t)data[1] << 8);
    pf->frame_type = pf->fcf & FCF_FRAME_TYPE_MASK;

    uint8_t dst_mode = (pf->fcf & FCF_DST_ADDR_MASK) >> 10;
    uint8_t src_mode = (pf->fcf & FCF_SRC_ADDR_MASK) >> 14;
    bool    pan_comp = (pf->fcf & FCF_PAN_COMPRESS) != 0;

    /* ACK frames: only 3 bytes (FCF + seq), no addressing */
    if (pf->frame_type == FRAME_TYPE_ACK) {
        if (len >= 3) pf->seq_num = data[2];
        pf->hdr_len = 3;
        return;
    }

    if (len < 3) return;
    pf->seq_num = data[2];

    uint8_t pos = 3;

    /* Destination PAN ID */
    if (dst_mode != ADDR_MODE_NONE) {
        if (pos + 2 > len) return;
        pf->dst_pan = data[pos] | ((uint16_t)data[pos + 1] << 8);
        pos += 2;

        /* Destination address */
        if (dst_mode == ADDR_MODE_SHORT) {
            if (pos + 2 > len) return;
            memcpy(pf->dst_addr, &data[pos], 2);
            pf->dst_addr_len = 2;
            pos += 2;
        } else if (dst_mode == ADDR_MODE_LONG) {
            if (pos + 8 > len) return;
            memcpy(pf->dst_addr, &data[pos], 8);
            pf->dst_addr_len = 8;
            pos += 8;
        }
    }

    /* Source PAN ID */
    if (src_mode != ADDR_MODE_NONE) {
        if (pan_comp) {
            /* PAN ID compressed — source PAN = destination PAN */
            pf->src_pan = pf->dst_pan;
        } else {
            if (pos + 2 > len) return;
            pf->src_pan = data[pos] | ((uint16_t)data[pos + 1] << 8);
            pos += 2;
        }

        /* Source address */
        if (src_mode == ADDR_MODE_SHORT) {
            if (pos + 2 > len) return;
            memcpy(pf->src_addr, &data[pos], 2);
            pf->src_addr_len = 2;
            pos += 2;
        } else if (src_mode == ADDR_MODE_LONG) {
            if (pos + 8 > len) return;
            memcpy(pf->src_addr, &data[pos], 8);
            pf->src_addr_len = 8;
            pos += 8;
        }
    }

    pf->hdr_len = pos;

    /* === Protocol classification === */
    /* Look at first byte(s) of payload after MAC header */
    if (pos < len) {
        uint8_t payload_first = data[pos];
        uint16_t frame_ver = (pf->fcf & FCF_FRAME_VER_MASK) >> 12;
        bool sec_enabled = (pf->fcf & FCF_SEC_ENABLED) != 0;

        if (pf->frame_type == FRAME_TYPE_BEACON) {
            /* Beacons on 802.15.4 in home networks are almost always Zigbee */
            if (pos + 4 < len) {
                pf->proto = 'Z';
            }
        } else if (pf->frame_type == FRAME_TYPE_DATA) {
            if (sec_enabled && frame_ver >= 2) {
                /* 802.15.4-2015 with security = Thread (uses link-layer encryption) */
                pf->proto = 'T';
            }
            /* Thread/6LoWPAN: IPHC dispatch 011xxxxx (0x60-0x7F) */
            else if ((payload_first & 0xE0) == 0x60) {
                pf->proto = 'T';
            }
            /* Thread/6LoWPAN: mesh header 10xxxxxx (0x80-0xBF) */
            else if ((payload_first & 0xC0) == 0x80) {
                pf->proto = 'T';
            }
            /* Thread/6LoWPAN: fragment header 11000xxx or 11100xxx */
            else if ((payload_first & 0xF8) == 0xC0 || (payload_first & 0xF8) == 0xE0) {
                pf->proto = 'T';
            }
            /* Zigbee NWK: protocol version 2 (Zigbee Pro) in bits 2-5 of NWK FC */
            else if ((payload_first & 0x3C) == 0x08) {
                pf->proto = 'Z';
            }
            /* Zigbee NWK: protocol version 3 (Green Power) */
            else if ((payload_first & 0x3C) == 0x0C) {
                pf->proto = 'Z';
            }
            /* 802.15.4-2003/2006 frame with security — likely Zigbee */
            else if (sec_enabled && frame_ver < 2) {
                pf->proto = 'Z';
            }
        } else if (pf->frame_type == FRAME_TYPE_CMD) {
            /* MAC commands: classify by frame version */
            if (frame_ver >= 2) {
                pf->proto = 'T';  /* Thread uses 802.15.4-2015 */
            } else {
                pf->proto = 'Z';  /* Zigbee uses 802.15.4-2003/2006 */
            }
        }
    } else if (pf->frame_type == FRAME_TYPE_ACK) {
        /* Enhanced ACK (frame version 2) = Thread; legacy ACK = Zigbee */
        uint16_t frame_ver = (pf->fcf & FCF_FRAME_VER_MASK) >> 12;
        if (frame_ver >= 2) {
            pf->proto = 'T';
        } else {
            pf->proto = 'Z';
        }
    }
}

/* ========================================================================
 * Output Task — dequeues frames and sends AT unsolicited responses
 * ======================================================================== */

static void zigbee_output_task(void *arg)
{
    (void)arg;

    zigbee_frame_t zf;
    char hex_buf[256];
    char dst_addr_str[20];
    char src_addr_str[20];

    for (;;) {
        if (xQueueReceive(s_frame_queue, &zf, pdMS_TO_TICKS(100)) == pdTRUE) {
            if (s_frame_callback) {
                s_frame_callback(zf.data, zf.len, zf.channel, zf.rssi, zf.lqi,
                                 s_frame_callback_ctx);
                continue;
            }

            /* Parse the MAC header */
            parsed_frame_t pf;
            parse_frame(zf.data, zf.len, &pf);

            /* Build hex string of full frame */
            for (uint8_t i = 0; i < zf.len && i < 127; i++) {
                snprintf(&hex_buf[i * 2], 3, "%02X", zf.data[i]);
            }
            hex_buf[zf.len * 2] = '\0';

            /* Format addresses */
            hex_addr(pf.dst_addr, pf.dst_addr_len, dst_addr_str);
            hex_addr(pf.src_addr, pf.src_addr_len, src_addr_str);

            /* Output as unsolicited AT response */
            char resp[400];
            int n = snprintf(resp, sizeof(resp),
                             "\r\n+ZIGFRAME:%c,%s,%u,%u,%d,%u,%04X,%s,%04X,%s,%s\r\n",
                             pf.proto,
                             frame_type_str(pf.frame_type),
                             zf.len, zf.channel, zf.rssi, zf.lqi,
                             pf.dst_pan, dst_addr_str,
                             pf.src_pan, src_addr_str,
                             hex_buf);
            esp_at_port_write_data((uint8_t *)resp, n);
        }

        if (!s_sniffing) {
            break;
        }
    }

    s_output_task = NULL;
    vTaskDelete(NULL);
}

/* ========================================================================
 * Shared service helpers
 * ======================================================================== */

void m1_zigbee_set_frame_callback(m1_zigbee_frame_callback_t callback, void *ctx)
{
    s_frame_callback = callback;
    s_frame_callback_ctx = ctx;
}

bool m1_zigbee_sniffer_is_running(void)
{
    return s_sniffing;
}

uint8_t m1_zigbee_sniffer_channel(void)
{
    return s_channel;
}

esp_err_t m1_zigbee_init(bool enable)
{
    if (!enable) {
        if (s_sniffing) {
            esp_err_t err = m1_zigbee_sniffer_stop();
            if (err != ESP_OK) {
                return err;
            }
        }

        if (s_radio_enabled) {
            esp_ieee802154_sleep();
        }
        return ESP_OK;
    }

    if (!s_radio_enabled) {
        esp_err_t ret = esp_ieee802154_enable();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "802154 enable failed: %s", esp_err_to_name(ret));
            return ret;
        }
        s_radio_enabled = true;
    }

    esp_ieee802154_set_promiscuous(true);
    REG_SET_BIT(IEEE802154_CTRL_CFG_REG, IEEE802154_DIS_FRAME_VERSION_RSV_FILTER);
    return ESP_OK;
}

esp_err_t m1_zigbee_sniffer_stop(void)
{
    if (!s_sniffing) {
        return ESP_OK;
    }

    s_sniffing = false;
    esp_ieee802154_sleep();

    if (s_output_task) {
        uint32_t waited_ms = 0;

        while ((s_output_task != NULL) && (waited_ms < SNIFFER_STOP_WAIT_MS)) {
            vTaskDelay(pdMS_TO_TICKS(SNIFFER_STOP_POLL_MS));
            waited_ms += SNIFFER_STOP_POLL_MS;
        }

        if (s_output_task != NULL) {
            ESP_LOGW(TAG, "Output task did not stop cleanly, forcing delete");
            vTaskDelete(s_output_task);
            s_output_task = NULL;
        }
    }

    if (s_frame_queue) {
        vQueueDelete(s_frame_queue);
        s_frame_queue = NULL;
    }

    s_channel = 0;
    ESP_LOGI(TAG, "Sniffer stopped (radio sleeping)");
    return ESP_OK;
}

esp_err_t m1_zigbee_sniffer_start(uint8_t channel)
{
    if (channel < 11 || channel > 26) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = m1_zigbee_init(true);
    if (err != ESP_OK) {
        return err;
    }

    if (s_sniffing) {
        esp_ieee802154_sleep();
        esp_ieee802154_set_channel(channel);
        s_channel = channel;
        esp_ieee802154_receive();
        ESP_LOGI(TAG, "Switched to channel %d", channel);
        return ESP_OK;
    }

    s_frame_queue = xQueueCreate(FRAME_QUEUE_DEPTH, sizeof(zigbee_frame_t));
    if (!s_frame_queue) {
        ESP_LOGE(TAG, "Queue create failed");
        return ESP_ERR_NO_MEM;
    }

    esp_ieee802154_set_channel(channel);
    esp_ieee802154_set_rx_when_idle(true);
    s_channel = channel;

    s_sniffing = true;
    if (xTaskCreate(zigbee_output_task, "zig_out", 4096, NULL, 5, &s_output_task) != pdPASS) {
        ESP_LOGE(TAG, "Output task create failed");
        s_sniffing = false;
        vQueueDelete(s_frame_queue);
        s_frame_queue = NULL;
        s_channel = 0;
        return ESP_ERR_NO_MEM;
    }
    esp_ieee802154_receive();

    ESP_LOGI(TAG, "Sniffer started on channel %d", channel);
    return ESP_OK;
}

/* ========================================================================
 * AT Command Handlers
 * ======================================================================== */

/* AT+ZIGSNIFF? — query status */
static uint8_t at_query_cmd_zigsniff(uint8_t *cmd_name)
{
    char resp[64];
    int n = snprintf(resp, sizeof(resp),
                     "+ZIGSNIFF:%d,%u\r\n",
                     m1_zigbee_sniffer_is_running() ? 1 : 0, m1_zigbee_sniffer_channel());
    esp_at_port_write_data((uint8_t *)resp, n);
    return ESP_AT_RESULT_CODE_OK;
}

/* AT+ZIGSNIFF=<enable>[,<channel>] */
static uint8_t at_setup_cmd_zigsniff(uint8_t para_num)
{
    int32_t enable = 0;
    int32_t channel = 15;  /* default */

    /* Parse enable (required) */
    if (esp_at_get_para_as_digit(0, &enable) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (enable == 0) {
        return (m1_zigbee_sniffer_stop() == ESP_OK)
            ? ESP_AT_RESULT_CODE_OK
            : ESP_AT_RESULT_CODE_ERROR;
    }

    if (enable == 1) {
        if (para_num < 2) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
        if (esp_at_get_para_as_digit(1, &channel) != ESP_AT_PARA_PARSE_RESULT_OK) {
            return ESP_AT_RESULT_CODE_ERROR;
        }
        return (m1_zigbee_sniffer_start((uint8_t)channel) == ESP_OK)
            ? ESP_AT_RESULT_CODE_OK
            : ESP_AT_RESULT_CODE_ERROR;
    }

    return ESP_AT_RESULT_CODE_ERROR;
}

/* ========================================================================
 * AT Command Registration
 * ======================================================================== */

static const esp_at_cmd_struct s_zigbee_cmd_list[] = {
    {"+ZIGSNIFF", NULL, at_query_cmd_zigsniff, at_setup_cmd_zigsniff, NULL},
};

bool esp_at_custom_zigbee_cmd_register(void)
{
    return esp_at_custom_cmd_array_regist(
        s_zigbee_cmd_list,
        sizeof(s_zigbee_cmd_list) / sizeof(s_zigbee_cmd_list[0]));
}
