/*
 * Copyright 2018 Oticon A/S
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "blecrypt.h"
#include "tinycrypt/constants.h"
#include "tinycrypt/aes.h"
#include "tinycrypt/ccm_mode.h"

// Performs simple AES-128 encryption of 128-bit data.
// This is the security function e (BT Core v4.2 vol 3 part H section 2.2.1).
// This is also the HCI_LE_Encrypt command (BT Core v4.2 vol 1 part E section 7.8.22).
// Applications:
//   * Generating and resolving resolvable random address (via ah function, BT Core v4.2 vol 3 part H section 2.2.2).
//   * Generating pairing confirm value (via c1 function, BT Core v4.2 vol 3 part H section 2.2.3).
//   * Generating short term key (via s1 function, BT Core v4.2 vol 3 part H section 2.2.4).
//   * Generating session key.
void blecrypt_aes_128(
    // Inputs
    const uint8_t *key_be,                          // Key (KEY_LEN bytes, BIG-ENDIAN)
    const uint8_t *plaintext_data_be,               // Plaintext data (KEY_LEN bytes, BIG-ENDIAN)
    // Outputs (the pointers themselves are inputs and must point to large enough areas)
    uint8_t *encrypted_data_be)                     // Encrypted data (KEY_LEN bytes, BIG-ENDIAN)
{
  int result;
  struct tc_aes_key_sched_struct s;

  result = tc_aes128_set_encrypt_key(&s, key_be);

  if (result == TC_CRYPTO_SUCCESS) {
    result = tc_aes_encrypt(encrypted_data_be, plaintext_data_be, &s);
  }

  if (result == TC_CRYPTO_FAIL) {
    fprintf(stderr,"Bad error in %s %i, most likely a null pointer\n",__func__, __LINE__);
  }
}

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
    uint8_t *encrypted_packet_payload_and_mic)      // Resulting encrypted payload with MIC appended (packet_payload_len + MIC_LEN bytes)
{
  // Set additional authenticated data (AAD) to first byte of packet header with NESN = SN = MD = 0
  // == associated_data
  uint8_t aad = packet_1st_header_byte & 0xE3;

  int result;
  struct tc_aes_key_sched_struct sched;
  struct tc_ccm_mode_struct c;

  result = tc_aes128_set_encrypt_key(&sched, sk);

  if (result == TC_CRYPTO_SUCCESS) {
    result = tc_ccm_config(&c, &sched, (uint8_t *)ccm_nonce, NONCE_LEN, MIC_LEN);
  }

  if (result == TC_CRYPTO_FAIL) {
    fprintf(stderr,"Bad error in %s %i, most likely a null pointer\n", __func__, __LINE__);
    return;
  }

  result = tc_ccm_generation_encryption(encrypted_packet_payload_and_mic,
                                        packet_payload_len+MIC_LEN,
                                        &aad, 1,
                                        packet_payload, packet_payload_len,
                                        &c);
  if (result == TC_CRYPTO_FAIL) {
    fprintf(stderr,"Bad error in %s %i, most likely a null pointer\n", __func__, __LINE__);
    return;
  }
}

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
    uint8_t *decrypted_packet_payload)              // Resulting decrypted payload (packet_payload_len bytes)
{
  // Set additional authenticated data (AAD) to first byte of packet header with NESN = SN = MD = 0
  // == associated_data
  uint8_t aad = packet_1st_header_byte & 0xE3;

  int result;
  struct tc_aes_key_sched_struct sched;
  struct tc_ccm_mode_struct c;

  result = tc_aes128_set_encrypt_key(&sched, sk);

  if (result == TC_CRYPTO_SUCCESS) {
    result = tc_ccm_config(&c, &sched, (uint8_t *)ccm_nonce, NONCE_LEN, MIC_LEN);
  }

  if (result == TC_CRYPTO_FAIL) {
    fprintf(stderr,"Bad error in %s %i, most likely a null pointer\n", __func__, __LINE__);
    return 0;
  }

  if (no_mic) {
    c.mlen = 0;
  }

  result = tc_ccm_decryption_verification(decrypted_packet_payload,
                                          packet_payload_len,
                                          &aad, 1,
                                          packet_payload_and_mic, packet_payload_len + (no_mic?0:4),
                                          &c);
  if (result == TC_CRYPTO_FAIL) {
    //Unfortunately tinycrypt reports config errors just like MIC errors
    //so we just report them all up as mic errors
    return 0;
  }
  return 1;
}

// Reverses byte order of data
void blecrypt_reverse_byte_order(const uint8_t *in_data, uint8_t *out_data, int len)
{
  int i;
  in_data += len - 1;
  for (i = 0; i < len; i++)
  {
    *out_data++ = *in_data--;
  }
}
