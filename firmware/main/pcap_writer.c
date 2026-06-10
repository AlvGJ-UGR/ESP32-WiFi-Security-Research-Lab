/**
 * @file pcap_writer.c
 * @brief In-memory PCAP ring buffer implementation.
 *
 * PCAP global header format (libpcap):
 *   magic    : 0xA1B2C3D4
 *   major    : 2
 *   minor    : 4
 *   thiszone : 0
 *   sigfigs  : 0
 *   snaplen  : 65535
 *   network  : 105  (IEEE 802.11 radio)
 */

#include "pcap_writer.h"
#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "pcap_writer";

/* ── PCAP binary structures ────────────────────────────────────────────────── */

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_global_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_record_header_t;
#pragma pack(pop)

/* ── ring buffer ───────────────────────────────────────────────────────────── */

#define BUF_SIZE  (512 * 1024)   /* 512 KB scratch buffer */

static uint8_t  _buf[BUF_SIZE];
static size_t   _pos          = 0;
static uint32_t _frame_count  = 0;
static SemaphoreHandle_t _mutex = NULL;

/* ── helpers ───────────────────────────────────────────────────────────────── */

static void _write_bytes(const void *data, size_t len)
{
    if (_pos + len > BUF_SIZE) {
        /* Wrap: reset to after global header */
        _pos = sizeof(pcap_global_header_t);
    }
    memcpy(_buf + _pos, data, len);
    _pos += len;
}

/* ── public API ────────────────────────────────────────────────────────────── */

void pcap_writer_init(void)
{
    _mutex = xSemaphoreCreateMutex();
    memset(_buf, 0, sizeof(_buf));
    _pos         = 0;
    _frame_count = 0;

    pcap_global_header_t hdr = {
        .magic         = 0xA1B2C3D4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone      = 0,
        .sigfigs       = 0,
        .snaplen       = 65535,
        .network       = 105,   /* DLT_IEEE802_11 */
    };
    _write_bytes(&hdr, sizeof(hdr));
    ESP_LOGI(TAG, "PCAP buffer initialised (%d KB)", BUF_SIZE / 1024);
}

void pcap_writer_write_frame(const uint8_t *data, uint32_t length, uint32_t timestamp)
{
    if (!_mutex) return;
    if (length == 0 || length > 2048) return;

    xSemaphoreTake(_mutex, portMAX_DELAY);

    pcap_record_header_t rec = {
        .ts_sec   = timestamp / 1000000,
        .ts_usec  = timestamp % 1000000,
        .incl_len = length,
        .orig_len = length,
    };
    _write_bytes(&rec, sizeof(rec));
    _write_bytes(data, length);
    _frame_count++;

    xSemaphoreGive(_mutex);
}

size_t pcap_writer_get_buffer(uint8_t *out, size_t max_len)
{
    if (!_mutex) return 0;
    xSemaphoreTake(_mutex, portMAX_DELAY);
    size_t to_copy = (_pos < max_len) ? _pos : max_len;
    memcpy(out, _buf, to_copy);
    xSemaphoreGive(_mutex);
    return to_copy;
}

uint32_t pcap_writer_frame_count(void)
{
    return _frame_count;
}

void pcap_writer_reset(void)
{
    if (!_mutex) return;
    xSemaphoreTake(_mutex, portMAX_DELAY);
    _frame_count = 0;
    _pos         = sizeof(pcap_global_header_t);
    ESP_LOGI(TAG, "PCAP buffer reset");
    xSemaphoreGive(_mutex);
}
