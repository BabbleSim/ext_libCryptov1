/*
 * Copyright 2018 Oticon A/S
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "blecrypt.h"

static void print_bytes(const void *data, int data_len)
{
    char s[3*data_len + 1];
    memset(s, 0, 3*data_len + 1);
    const uint8_t *ip = data;
    char *op = s;
    if (data_len > 0)
    {
        op += sprintf(op, "%02x", *ip++);
        while (--data_len > 0)
        {
            op += sprintf(op, " %02x", *ip++);
        }
    } 
    printf("    %s\n", s);
}

// Calculates session key for encryption/decryption (wrapper for blecrypt_aes_128 function).
// Call this once when BLE link is going to be encrypted.
void blecrypt_session_key_calc(
    // Inputs
    const uint8_t *skd,                             // Session key diversifier (SKD_LEN bytes, little-endian)
    const uint8_t *ltk,                             // Long (or short) term key (KEY_LEN bytes, little-endian)
    // Outputs (the pointers themselves are inputs and must point to large enough areas)
    uint8_t *sk)                                    // Session key (KEY_LEN bytes, BIG-ENDIAN)
{
    uint8_t skd_be[KEY_LEN];
    uint8_t ltk_be[KEY_LEN];

    // Flip key and plaintext data to big-endian
    blecrypt_reverse_byte_order(skd, skd_be, KEY_LEN);
    blecrypt_reverse_byte_order(ltk, ltk_be, KEY_LEN);

    // Calculate session key by encrypting SKD with LTK
    blecrypt_aes_128(ltk_be, skd_be, sk);
}


// Tests session key calculation by calculating session key and checking result against reference.
static void test_session_key_calc(
    // Inputs
    const uint8_t *skd,
    const uint8_t *ltk,
    const uint8_t *expected_sk, // little-endian here
    // Outputs (the pointers themselves are inputs and must point to large enough areas)
    uint8_t *sk) // session key is big-endian for OpenSSL
{
    uint8_t sk_le[KEY_LEN];

    // Calculate session key
    blecrypt_session_key_calc(skd, ltk, sk);

    // Check results (session key needs to be flipped to little-endian for comparison)
    blecrypt_reverse_byte_order(sk, sk_le, KEY_LEN);
    if (memcmp(sk_le, expected_sk, KEY_LEN) != 0)
    {
        printf("FAILED: Session key doesn't match reference.\n");
        exit(1);
    }
    printf("PASSED: Verified session key.\n");
    print_bytes(sk_le, KEY_LEN);
}

// Calculates CCM nonce for packet.
static void nonce_calc(
    // Inputs
    const uint8_t *iv,                              // Initialization vector (IV_LEN bytes, little-endian)
    uint64_t packet_counter,                        // 39-bit packet count (in given direction, excl. retransmissions and empty packets) since start of encryption
    blecrypt_packet_direction_t packet_direction,   // Direction of packet
    // Outputs (the pointers themselves are inputs and must point to large enough areas)
    uint8_t *ccm_nonce)                             // Resulting nonce (NONCE_LEN bytes, little-endian)
{
    int i;
    // Copy 39-bit packet counter into first 5 bytes of nonce and set 40th bit depending on packet
    // direction
    for (i = 0; i < NONCE_LEN - IV_LEN - 1; i++)
    {
        ccm_nonce[i] = packet_counter & 0xFF;
        packet_counter >>= 8;
    }
    ccm_nonce[i] = (packet_counter & 0x7F) | (packet_direction == MASTER_TO_SLAVE_DIRECTION ? 0x80 : 0);
    // Copy initialization vector into remaining 8 bytes of nonce
    memcpy(&ccm_nonce[NONCE_LEN - IV_LEN], iv, IV_LEN);
}


// Tests encryption by encrypting 1 packet and checking result against reference.
static void test_packet_encryption(
    // Inputs
    const uint8_t *unencrypted_packet_payload,
    const uint8_t *expected_encrypted_packet,
    blecrypt_packet_direction_t packet_direction,
    uint64_t packet_counter,
    const uint8_t *iv,
    const uint8_t *sk) // session key is big-endian for OpenSSL
{
    // Set up variables
    uint8_t packet_1st_header_byte = expected_encrypted_packet[0];
    int packet_payload_and_mic_len = expected_encrypted_packet[1];
    const uint8_t *expected_encrypted_packet_payload_and_mic = &expected_encrypted_packet[2];
    int packet_payload_len = packet_payload_and_mic_len - MIC_LEN;
    uint8_t encrypted_packet_payload_and_mic[255 /*packet_payload_and_mic_len*/]; // Local buffer for encryption output

    uint8_t ccm_nonce[NONCE_LEN];
    // Calculate nonce
    nonce_calc(iv, packet_counter, packet_direction, ccm_nonce);

    // Encrypt
    blecrypt_packet_encrypt(
        packet_1st_header_byte, packet_payload_len, unencrypted_packet_payload, sk, ccm_nonce,
        encrypted_packet_payload_and_mic);

    // Check results
    if (memcmp(encrypted_packet_payload_and_mic, expected_encrypted_packet_payload_and_mic, packet_payload_and_mic_len) != 0)
    {
        printf("FAILED: Encrypted packet doesn't match reference.\n");
        exit(1);
    }
    printf("PASSED: Verified encrypted packet payload and MIC.\n");
    print_bytes(encrypted_packet_payload_and_mic, packet_payload_and_mic_len);
}

// Tests decryption by decrypting 1 packet and checking result against reference.
static void test_packet_decryption(
    // Inputs
    const uint8_t *encrypted_packet,
    const uint8_t *expected_decrypted_packet_payload,
    blecrypt_packet_direction_t packet_direction,
    uint64_t packet_counter,
    const uint8_t *iv,
    const uint8_t *sk, // session key is big-endian for OpenSSL
    int no_mic)
{
    // Set up variables
    uint8_t packet_1st_header_byte = encrypted_packet[0];
    int packet_payload_len = encrypted_packet[1] - (no_mic ? 0 : MIC_LEN);
    const uint8_t *encrypted_packet_payload_and_mic = &encrypted_packet[2];
    uint8_t decrypted_packet_payload[251 /*packet_payload_len*/]; // Local buffer for decryption output
    int mic_ok;

    uint8_t ccm_nonce[NONCE_LEN];
    // Calculate nonce
    nonce_calc(iv, packet_counter, packet_direction, ccm_nonce);

    // Decrypt
    mic_ok = blecrypt_packet_decrypt(
        packet_1st_header_byte, packet_payload_len, encrypted_packet_payload_and_mic, sk, ccm_nonce,
        no_mic,
        decrypted_packet_payload);

    // Check results
    if (!mic_ok)
    {
        printf("FAILED: MIC verification failed.\n");
        exit(1);
    }
    if (memcmp(decrypted_packet_payload, expected_decrypted_packet_payload, packet_payload_len) != 0)
    {
        printf("FAILED: Decrypted packet doesn't match reference.\n");
        exit(1);
    }
    if (no_mic)
    {
        printf("PASSED: Verified decrypted packet payload (MIC not present).\n");
    }
    else
    {
        printf("PASSED: Verified MIC and decrypted packet payload.\n");
    }
    print_bytes(decrypted_packet_payload, packet_payload_len);
}

///////////////////////////////////////////////////////////////////////////////
// BLE sample data from BT Core v4.2 vol 6 part C section 1
///////////////////////////////////////////////////////////////////////////////

// LTK (16 bytes little-endian) - slave's long term key
static const uint8_t ref_ltk[KEY_LEN] = {
    0xbf, 0x01, 0xfb, 0x9d, 0x4e, 0xf3, 0xbc, 0x36, 0xd8, 0x74, 0xf5, 0x39, 0x41, 0x38, 0x68, 0x4c
};

// SKDm (8 bytes little-endian) - master's part of session key diversifier
static const uint8_t ref_skd_m[SKD_LEN/2] = {
    0x13, 0x02, 0xf1, 0xe0, 0xdf, 0xce, 0xbd, 0xac
};

// IVm (4 bytes little-endian) - master's part of initialization vector
static const uint8_t ref_iv_m[IV_LEN/2] = {
    0x24, 0xab, 0xdc, 0xba
};

// SKDs (8 bytes little-endian) - slave's part of session key diversifier
static const uint8_t ref_skd_s[SKD_LEN/2] = {
    0x79, 0x68, 0x57, 0x46, 0x35, 0x24, 0x13, 0x02
};

// IVs (4 bytes little-endian) - slave's part of initialization vector
static const uint8_t ref_iv_s[IV_LEN/2] = {
    0xbe, 0xba, 0xaf, 0xde
};

// SK (16 bytes little-endian) - session key (this is the CCM key used to encrypt BLE packets)
static const uint8_t ref_sk[KEY_LEN] = {
    0x66, 0xc6, 0xc2, 0x27, 0x8e, 0x3b, 0x8e, 0x05, 0x3e, 0x7e, 0xa3, 0x26, 0x52, 0x1b, 0xad, 0x99
};

// Packets

// LL_START_ENC_RSP1 (master -> slave)
static const uint8_t packet0_encrypted[] = {
    0x0F, 0x05, 0x9f, 0xcd, 0xa7, 0xf4, 0x48
};
static const uint8_t packet0_payload_unencrypted[] = {
    0x06
};

// LL_START_ENC_RSP2 (slave -> master)
static const uint8_t packet1_encrypted[] = {
    0x07, 0x05, 0xa3, 0x4c, 0x13, 0xa4, 0x15
};
static const uint8_t packet1_payload_unencrypted[] = {
    0x06
};

// LL_DATA1 (master -> slave)
static const uint8_t packet2_encrypted[] = {
    0x0e, 0x1f, 0x7a, 0x70, 0xd6, 0x64, 0x15, 0x22, 0x6d, 0xf2, 0x6b, 0x17, 0x83, 0x9a, 0x06, 0x04, 0x05, 0x59, 0x6b, 0xd6, 0x56, 0x4f, 0x79, 0x6b, 0x5b, 0x9c, 0xe6, 0xff, 0x32, 0xf7, 0x5a, 0x6d, 0x33
};
static const uint8_t packet2_payload_unencrypted[] = {
    0x17, 0x00, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

// LL_DATA2 (slave -> master)
static const uint8_t packet3_encrypted[] = {
    0x06, 0x1f, 0xf3, 0x88, 0x81, 0xe7, 0xbd, 0x94, 0xc9, 0xc3, 0x69, 0xb9, 0xa6, 0x68, 0x46, 0xdd, 0x47, 0x86, 0xaa, 0x8c, 0x39, 0xce, 0x54, 0x0d, 0x0d, 0xae, 0x3a, 0xdc, 0xdf, 0x89, 0xb9, 0x60, 0x88
};
static const uint8_t packet3_payload_unencrypted[] = {
    0x17, 0x00, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51
};

///////////////////////////////////////////////////////////////////////////////
// End of BLE sample data
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// MIC-less test data (copy of BLE sample data with MIC removed)
///////////////////////////////////////////////////////////////////////////////

// LL_DATA1 (master -> slave) with no MIC
static const uint8_t packet2_encrypted_no_mic[] = {
    0x0e, 0x1b, 0x7a, 0x70, 0xd6, 0x64, 0x15, 0x22, 0x6d, 0xf2, 0x6b, 0x17, 0x83, 0x9a, 0x06, 0x04, 0x05, 0x59, 0x6b, 0xd6, 0x56, 0x4f, 0x79, 0x6b, 0x5b, 0x9c, 0xe6, 0xff, 0x32
};

///////////////////////////////////////////////////////////////////////////////
// End of MIC-less test data
///////////////////////////////////////////////////////////////////////////////


// Values of MIC presence flag for decryption 
#define HAS_MIC     0
#define HAS_NO_MIC  1

int main(int argc, char *argv[])
{
    // In reality both the master and slave devices have copies of both the master and slave packet
    // counters, but the counter values should always be the same in both devices (as soon as
    // transmissions have been acknowledged), so for this test bench we need only 1 copy of the 2
    // counters
    uint64_t master_packet_counter = 0;
    uint64_t slave_packet_counter = 0;

    // SKD - session key diversifier
    uint8_t skd[SKD_LEN];
    // IV - initialization vector
    uint8_t iv[IV_LEN];
    // SK - session key (this is the CCM key used to encrypt BLE packets)
    uint8_t sk[KEY_LEN]; // sk is big-endian for OpenSSL

    // Calculate SKD by concatenating SKDm and SKDs (master and slave contributions)
    memcpy(skd, ref_skd_m, SKD_LEN/2);
    memcpy(skd + SKD_LEN/2, ref_skd_s, SKD_LEN/2);

    // Calculate IV by concatenating IVm and IVs (master and slave contributions)
    memcpy(iv, ref_iv_m, IV_LEN/2);
    memcpy(iv + IV_LEN/2, ref_iv_s, IV_LEN/2);

    // Calculate session key, and check results
    test_session_key_calc(skd, ref_ltk, ref_sk, sk);

    // Encrypt and decrypt packets, and check results
    test_packet_encryption(packet0_payload_unencrypted, packet0_encrypted, MASTER_TO_SLAVE_DIRECTION, master_packet_counter, iv, sk);
    test_packet_decryption(packet0_encrypted, packet0_payload_unencrypted, MASTER_TO_SLAVE_DIRECTION, master_packet_counter, iv, sk, HAS_MIC);
    master_packet_counter++;
    test_packet_encryption(packet1_payload_unencrypted, packet1_encrypted, SLAVE_TO_MASTER_DIRECTION, slave_packet_counter, iv, sk);
    test_packet_decryption(packet1_encrypted, packet1_payload_unencrypted, SLAVE_TO_MASTER_DIRECTION, slave_packet_counter, iv, sk, HAS_MIC);
    slave_packet_counter++;
    test_packet_encryption(packet2_payload_unencrypted, packet2_encrypted, MASTER_TO_SLAVE_DIRECTION, master_packet_counter, iv, sk);
    test_packet_decryption(packet2_encrypted, packet2_payload_unencrypted, MASTER_TO_SLAVE_DIRECTION, master_packet_counter, iv, sk, HAS_MIC);
    // Non-standard MIC-less encryption mode
    test_packet_decryption(packet2_encrypted_no_mic, packet2_payload_unencrypted, MASTER_TO_SLAVE_DIRECTION, master_packet_counter, iv, sk, HAS_NO_MIC);
    master_packet_counter++;
    test_packet_encryption(packet3_payload_unencrypted, packet3_encrypted, SLAVE_TO_MASTER_DIRECTION, slave_packet_counter, iv, sk);
    test_packet_decryption(packet3_encrypted, packet3_payload_unencrypted, SLAVE_TO_MASTER_DIRECTION, slave_packet_counter, iv, sk, HAS_MIC);
    slave_packet_counter++;

    printf("All tests PASSED!\n");
    return 0;
}
