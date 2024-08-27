/*
 * Copyright 2018 Oticon A/S
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include "blecrypt.h"

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
    // Create OpenSSL cypher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // Set cipher type to AES-128, mode to ECB ("Electronic Codebook": simple independent encryption of blocks),
    // and provide encryption key
    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key_be, NULL);
    // Encrypt plaintext data and put result in encrypted_data_be and length in outlen
    int outlen;
    EVP_EncryptUpdate(ctx, encrypted_data_be, &outlen, plaintext_data_be, SKD_LEN);
    // Free cipher context
    EVP_CIPHER_CTX_free(ctx);
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
    uint8_t aad = packet_1st_header_byte & 0xE3;
    blecrypt_packet_encrypt_v2(aad,
                               packet_payload_len,
                               packet_payload,
                               sk,
                               ccm_nonce,
                               encrypted_packet_payload_and_mic);
}

// Decrypt payload of one packet and checks MIC (if present).
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
    uint8_t aad = packet_1st_header_byte & 0xE3;
    return blecrypt_packet_decrypt_v2(aad,
                                      packet_payload_len,
                                      packet_payload_and_mic,
                                      sk,
                                      ccm_nonce,
                                      no_mic,
                                      decrypted_packet_payload);
}

/**
 * Encrypt a BLE packet payload and append the MIC,
 * as per Bluetooth Core Specification Version 5.3 | Vol 6, Part E
 *
 * In comparison to blecrypt_packet_encrypt()
 * this version is adapted to not apply the BT 4.2 AAD mask,
 * but leave it to the caller, to be more transparent as to how the mask is meant to be applied
 * for newer standard versions.
 *
 * \note Encrypted and unencrypted packet payloads must reside at different (non-overlapping) locations.
 *
 * \param[in] aad  Additional Authentication Data: First byte of packet header after applying the bit mask
 *                 Note: For BT 4.2 this is 0xE3. For 5.2 it depends on the packet type.
 * \param[in] packet_payload_len  Input packet payload length (i.e. not including header and MIC)
 * \param[in] packet_payload  Pointer to the packet payload to be encrypted (buffer must contain packet_payload_len bytes)
 * \param[in] sk  Session key (KEY_LEN bytes, BIG-ENDIAN)
 * \param[in] ccm_nonce  CCM Nonce (NONCE_LEN bytes, little-endian)
 *
 * \param[out] encrypted_packet_payload_and_mic Pointer to a buffer where the resulting encrypted payload with MIC appended will be stored
 *             (packet_payload_len + MIC_LEN bytes). The caller must allocate it.
 */
void blecrypt_packet_encrypt_v2(
    uint8_t aad,
    int packet_payload_len,
    const uint8_t *packet_payload,
    const uint8_t *sk,
    const uint8_t *ccm_nonce,
    uint8_t *encrypted_packet_payload_and_mic)
{
    int outlen;
    // Set plaintext pointer to start of input packet payload
    const uint8_t *pt = packet_payload;
    // Set ciphertext pointer to start of encrypted packet payload
    uint8_t *ct = encrypted_packet_payload_and_mic;
    const int aad_len = 1; //Length of the Additional Authentication Data as per BT spec
    // Allocate new cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // Set cipher type to 128-bit AES, and mode to CCM (Counter with CBC-MAC)
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    // Set nonce length (because it is different from the 96-bit default)
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, NONCE_LEN, NULL);
    // Set MIC (a.k.a MAC tag) length
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, MIC_LEN, NULL);
    // Set encryption key and initialization vector (nonce)
    EVP_EncryptInit_ex(ctx, NULL, NULL, sk, ccm_nonce);
    // Set plaintext length (needed because AAD is used)
    EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, packet_payload_len);
    // Provide AAD (addition authenticated data)
    EVP_EncryptUpdate(ctx, NULL, &outlen, &aad, aad_len);
    // Encrypt plaintext to cyphertext (and return number of encrypted bytes in outlen)
    EVP_EncryptUpdate(ctx, ct, &outlen, pt, packet_payload_len);
    // Get MIC and append it to encrypted data
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, MIC_LEN, (ct += outlen));
    // Free cypher context
    EVP_CIPHER_CTX_free(ctx);
}

/**
 * Decrypt a BLE packet payload and check the MIC (if present)
 * as per Bluetooth Core Specification Version 5.3 | Vol 6, Part E
 *
 * In comparison to blecrypt_packet_decrypt()
 * this version is adapted to not apply the BT 4.2 AAD mask,
 * but leave it to the caller, to be more transparent as to how the mask is meant to be applied
 * for newer standard versions.
 *
 * \note Encrypted and unencrypted packet payloads must reside at different (non-overlapping) locations.
 *
 * \param[in] aad  Additional Authentication Data: First byte of packet header after applying the bit mask
 *                 Note: For BT 4.2 this is 0xE3. For 5.2 it depends on the packet type.
 * \param[in] packet_payload_len  Unencrypted packet payload length (i.e. *not* including header and MIC)
 * \param[in] packet_payload_and mic  Pointer to the packet payload (with MIC if any) to be decrypted (packet_payload_len (+ MIC_LEN) bytes)
 * \param[in] sk  Session key (KEY_LEN bytes, BIG-ENDIAN)
 * \param[in] ccm_nonce  CCM Nonce (NONCE_LEN bytes, little-endian)
 * \param[in] no_mic  Set to 1 if packet to be decrypted does not include a MIC, otherwise 0
 *
 * \param[out] decrypted_packet_payload Pointer to a buffer where the resulting decrypted payload will be stored
 *             (packet_payload_len bytes). The caller must allocate it.
 *
 * \return Returns 1 if MIC is ok, else 0
 */
int blecrypt_packet_decrypt_v2(
    uint8_t aad,
    int packet_payload_len,
    const uint8_t *packet_payload_and_mic,
    const uint8_t *sk,
    const uint8_t *ccm_nonce,
    int no_mic,
    uint8_t *decrypted_packet_payload)
{
    int outlen, ok;
    // Set ciphertext pointer to start of input packet payload
    const uint8_t *ct = packet_payload_and_mic;
    // Set plaintext pointer to start of decrypted packet payload
    uint8_t *pt = decrypted_packet_payload;
    const int aad_len = 1; //Length of the Additional Authentication Data as per BT spec
    // Allocate new cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // Set cipher type to 128-bit AES, and mode to CCM (Counter with CBC-MAC)
    EVP_DecryptInit(ctx, EVP_aes_128_ccm(), NULL, NULL);
    // Set nonce length (because it is different from the 96-bit default)
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, NONCE_LEN, NULL);
    // Set hack flag indicating whether packet has MIC (standard BLE) or not
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_IGNORE_TAG, no_mic, NULL);

    if (no_mic)
    {
        /* Set dummy MIC (a.k.a. tag) value to prevent complaints from OpenSSL */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, MIC_LEN, (uint8_t[MIC_LEN]){0});
    }
    else
    {
        /* Set expected MIC (a.k.a. tag) value (located at ct + packet_payload_len) */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, MIC_LEN, (uint8_t *) ct + packet_payload_len);
    }
    // Set decryption key and initialization vector (nonce)
    EVP_DecryptInit(ctx, NULL, sk, ccm_nonce);
    // Set ciphertext length (needed because AAD is used)
    EVP_DecryptUpdate(ctx, NULL, &outlen, NULL, packet_payload_len);
    // Provide AAD (addition authenticated data)
    EVP_DecryptUpdate(ctx, NULL, &outlen, &aad, aad_len);
    // Decrypt ciphertext to plaintext and verify MIC (also return number of decrypted bytes in outlen)
    ok = EVP_DecryptUpdate(ctx, pt, &outlen, ct, packet_payload_len);
    // Free cipher context
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}


/**
 * CCM encrypt a packet payload and append the MAC/MIC,
 *
 * In comparison to blecrypt_packet_encrypt_v2()
 * this version accepts variable sized AAD, and variable sized MAC/MIC
 * to support 802.15.4 usecases.
 * As such the "blecrypt_" prefix remains only due to the component it belongs to
 *
 * \note Encrypted and unencrypted packet payloads must reside at different (non-overlapping) locations.
 *
 * \param[in] adata Additional Authentication Data. Note, for BLE any possible bitmask must be applied by the caller
 * \param[in] alen   Length of adata
 * \param[in] mlen   Unencrypted packet payload length (i.e. *not* including header and MAC/MIC)
 * \param[in] maclen Size of the MAC/MIC in bytes
 * \param[in] noncelen Size of the nonce in bytes
 * \param[in] mdata  Unencrypted/input packet payload
 * \param[in] sk  Session key (KEY_LEN bytes)
 * \param[in] ccm_nonce  CCM Nonce (noncelen bytes)
 *
 * \param[out] encrypted_packet_payload_and_mac Pointer to a buffer where the resulting encrypted payload with MAC appended will be stored
 *             (mlen + maclen bytes). The caller must allocate it.
 */
void blecrypt_packet_encrypt_v3(
    uint8_t *adata,
    int alen,
    int mlen,
    int maclen,
    int noncelen,
    const uint8_t *mdata,
    const uint8_t *sk,
    const uint8_t *ccm_nonce,
    uint8_t *encrypted_packet_payload_and_mac)
{
  int outlen;
  // Set plaintext pointer to start of input packet payload
  const uint8_t *pt = mdata;
  // Set cyphertext pointer to start of encrypted packet payload
  uint8_t *ct = encrypted_packet_payload_and_mac;

  //  Allocate new cypher context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  // Set cipher type to 128-bit AES, and mode to CCM (Counter with CBC-MAC)
  EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
  // Set nonce length (because it is different from the 96-bit default)
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, noncelen, NULL);
  // Set MAC (a.k.a MAC tag) length
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, maclen, NULL);
  // Set encryption key and initialization vector (nonce)
  EVP_EncryptInit_ex(ctx, NULL, NULL, sk, ccm_nonce);
  // Set plaintext length (needed because AAD is used)
  EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, mlen);
  // Provide AAD (addition authenticated data)
  EVP_EncryptUpdate(ctx, NULL, &outlen, adata, alen);
  // Encrypt plaintext to cyphertext (and return number of encrypted bytes in outlen)
  EVP_EncryptUpdate(ctx, ct, &outlen, pt, mlen);
  // Get MAC and append it to encrypted data
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, maclen, (ct += outlen));
  // Free cypher context
  EVP_CIPHER_CTX_free(ctx);
}


/*
 * CCM decrypt a packet payload and check the MAC/MIC (if present)
 *
 * In comparison to blecrypt_packet_decrypt_v2()
 * this version accepts variable sized AAD, and variable sized MAC/MIC
 * to support 802.15.4 usecases.
 * As such the "blecrypt_" prefix remains only due to the component it belongs to
 *
 * \note Encrypted and unencrypted packet payloads must reside at different (non-overlapping) locations.
 *
 * \param[in] adata  Additional Authentication Data. Note, for BLE any possible bitmask must be applied by the caller
 * \param[in] alen   Length of adata
 * \param[in] mlen   Unencrypted packet payload length (i.e. *not* including header and MAC/MIC)
 * \param[in] maclen Size of the MAC/MIC in bytes
 * \param[in] noncelen Size of the nonce in bytes
 * \param[in] mdata_and_mac  Pointer to the packet payload (with MAC if any) to be decrypted (packet_payload_len (+ MIC_LEN) bytes)
 * \param[in] sk     Session key (KEY_LEN bytes)
 * \param[in] ccm_nonce  CCM Nonce (noncelen bytes)
 * \param[in] no_mac  Set to 1 if packet to be decrypted does not include a MAC, otherwise 0
 *
 * \param[out] decrypted_packet_payload Pointer to a buffer where the resulting decrypted payload will be stored
 *             (mlen bytes). The caller must allocate it.
 *
 * \return Returns 1 if MIC is ok, else 0
 */
int blecrypt_packet_decrypt_v3(
  uint8_t *adata,
  int alen,
  int mlen,
  int maclen,
  int noncelen,
  const uint8_t *mdata_and_mac,
  const uint8_t *sk,
  const uint8_t *ccm_nonce,
  int no_mac,
  uint8_t *decrypted_packet_payload)
{
  int outlen, ok;
  // Set cyphertext pointer to start of input packet payload
  const uint8_t *ct = mdata_and_mac;
  // Set plaintext pointer to start of decrypted packet payload
  uint8_t *pt = decrypted_packet_payload;
  //  Allocate new cypher context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  // Set cipher type to 128-bit AES, and mode to CCM (Counter with CBC-MAC)
  EVP_DecryptInit(ctx, EVP_aes_128_ccm(), NULL, NULL);
  // Set nonce length (because it is different from the 96-bit default)
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, noncelen, NULL);
  // Set hack flag indicating whether packet has MAC or not
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_IGNORE_TAG, no_mac, NULL);

  if (no_mac) {
#define DUMMY_MAC_LEN 4
    /* Set dummy MAC (a.k.a. tag) value to prevent complaints from OpenSSL */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, DUMMY_MAC_LEN, (uint8_t[DUMMY_MAC_LEN]){0});
  } else {
    /* Set expected MAC (a.k.a. tag) value (located at ct + mlen) */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, maclen, (uint8_t *)ct + mlen);
  }
  // Set decryption key and initialization vector (nonce)
  EVP_DecryptInit(ctx, NULL, sk, ccm_nonce);
  // Set cyphertext length (needed because AAD is used)
  EVP_DecryptUpdate(ctx, NULL, &outlen, NULL, mlen);
  // Provide AAD (addition authenticated data)
  // Mask the first byte of adata
  EVP_DecryptUpdate(ctx, NULL, &outlen, adata, alen);
  // Decrypt cyphertext to plaintext and verify MAC (also return number of decrypted bytes in outlen)
  ok = EVP_DecryptUpdate(ctx, pt, &outlen, ct, mlen);
  // Free cypher context
  EVP_CIPHER_CTX_free(ctx);
  return ok;
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
