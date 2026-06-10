/**
 * @file pcap_writer.h
 * @brief In-memory PCAP frame buffer with HTTP-export support.
 *
 * Frames captured by the promiscuous sniffer are stored in a circular
 * ring buffer and can be retrieved as a valid .pcap binary blob via
 * the HTTP endpoint /api/pcap/download.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of frames kept in the ring buffer. */
#define PCAP_RING_SIZE  4096

/**
 * @brief Initialise the PCAP ring buffer and write the global header.
 */
void pcap_writer_init(void);

/**
 * @brief Append a raw 802.11 frame to the buffer.
 *
 * @param data        Pointer to frame payload bytes.
 * @param length      Frame length in bytes.
 * @param timestamp   Capture timestamp (microseconds since boot).
 */
void pcap_writer_write_frame(const uint8_t *data, uint32_t length,
                             uint32_t timestamp);

/**
 * @brief Copy the current PCAP buffer into @p out.
 *
 * @param out      Destination buffer (caller-allocated).
 * @param max_len  Size of @p out.
 * @return         Number of bytes written.
 */
size_t pcap_writer_get_buffer(uint8_t *out, size_t max_len);

/**
 * @brief Return the total number of frames captured since last reset.
 */
uint32_t pcap_writer_frame_count(void);

/**
 * @brief Clear the ring buffer and reset the frame counter.
 */
void pcap_writer_reset(void);

#ifdef __cplusplus
}
#endif
