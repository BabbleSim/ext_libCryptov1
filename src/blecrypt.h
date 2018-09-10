/*
 * Copyright 2018 Oticon A/S
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef BLECRYPT_H
#define BLECRYPT_H

// This file provides an API for BLE packet encryption/decryption using the
// OpenSSL library.

#include <stdint.h>

// CCM size parameters specified in BT Core v4.2 vol 6 part E section 1
#define BLE_CCM_M   4   // Number of bytes in MIC (a.k.a. MAC) field
#define BLE_CCM_L   2   // Number of bytes in Length field (in counter mode blocks)

// Various BLE specific lengths
#define KEY_LEN     16
#define SKD_LEN     KEY_LEN
#define IV_LEN      8

// Various derived lengths
#define MIC_LEN     BLE_CCM_M

// Nonce length depends on CCM parameter L
#define NONCE_LEN   (15 - BLE_CCM_L)

// Packet direction
typedef enum {
    SLAVE_TO_MASTER_DIRECTION,
    MASTER_TO_SLAVE_DIRECTION
} blecrypt_packet_direction_t;

// Performs simple AES-128 encryption of 128-bit data.
// This is the security function e (BT Core v4.2 vol 3 part H section 2.2.1) - except for parameter endianness.
// This is also the HCI_LE_Encrypt command (BT Core v4.2 vol 1 part E section 7.8.22).
// Applications:
//   * Generating and resolving resolvable random address (via ah function, BT Core v4.2 vol 3 part H section 2.2.2).
//   * Generating pairing confirm value (via c1 function, BT Core v4.2 vol 3 part H section 2.2.3).
//   * Generating short term key (via s1 function, BT Core v4.2 vol 3 part H section 2.2.4).
//   * Generating session key.
void blecrypt_aes_128(
    // Inputs
    const uint8_t *key_be,                          // Key (KEY_LEN bytes, big-endian)
    const uint8_t *plaintext_data_be,               // Plaintext data (KEY_LEN bytes, big-endian)
    // Outputs (the pointers themselves are inputs and must point to large enough areas)
    uint8_t *encrypted_data_be);                    // Plaintext data (KEY_LEN bytes, big-endian)

// Encrypts payload of one packet and appends MIC.
// Encrypted and unencrypted packet payloads must reside at different (non-overlapping) locations.
void blecrypt_packet_encrypt(
    // Inputs
    uint8_t packet_1st_header_byte,                 // First byte of packet header (or just LLID and RFU (RFU=0 for BLE v4.x) - other bits are ignored)
    uint8_t packet_payload_len,                     // Packet payload length (not including header and MIC)
    const uint8_t *packet_payload,                  // Packet payload to be encrypted (packet_payload_len bytes)
    const uint8_t *sk,                              // Session key (KEY_LEN bytes, BIG-ENDIAN)
    const uint8_t *ccm_nonce,                       // CCM Nonce (NONCE_LEN bytes, little-endian)
    // Outputs (the pointers themselves are inputs and must point to large enough areas)
    uint8_t *encrypted_packet_payload_and_mic);     // Resulting encrypted payload with MIC appended (packet_payload_len + MIC_LEN bytes)

// Decrypts payload of one packet and checks MIC (if present).
// Encrypted and unencrypted packet payloads must reside at different (non-overlapping) locations.
int blecrypt_packet_decrypt(                        // Returns 1 if MIC is ok, else 0
    // Inputs
    uint8_t packet_1st_header_byte,                 // First byte of packet header (or just LLID and RFU (RFU=0 for BLE v4.x) - other bits are ignored)
    uint8_t packet_payload_len,                     // Packet payload length (not including header and MIC)
    const uint8_t *packet_payload_and_mic,          // Packet payload (with MIC if any) to be decrypted (packet_payload_len (+ MIC_LEN) bytes)
    const uint8_t *sk,                              // Session key (KEY_LEN bytes, BIG-ENDIAN)
    const uint8_t *ccm_nonce,                       // CCM Nonce (NONCE_LEN bytes, little-endian)
    int no_mic,                                     // 1 if packet to be decrypted does not include a MIC, otherwise 0 
    // Outputs (the pointers themselves are inputs and must point to large enough areas)
    uint8_t *decrypted_packet_payload);             // Resulting decrypted payload (packet_payload_len bytes)

// Reverses byte order of data
void blecrypt_reverse_byte_order(const uint8_t *in_data, uint8_t *out_data, int len);

#endif // #ifndef BLECRYPT_H
