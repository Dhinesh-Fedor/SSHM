#pragma once
/**
 * sshm_crypto.h
 * AEAD encryption/decryption helpers for SSHM using libsodium
 */

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SSHM_KEYBYTES 32
#define SSHM_NONCEBYTES 12  /* example nonce size, adjust per implementation */

/* Generate random 32-byte key */
int sshm_generate_key(uint8_t key[SSHM_KEYBYTES]);

/**
 * AEAD encrypt: output = nonce||ciphertext
 * @param key 32-byte key
 * @param plaintext Input data
 * @param pt_len Length of plaintext
 * @param output Output buffer (must be >= pt_len + nonce_len + tag_len)
 * @param output_len Max size of output buffer
 * @return Number of bytes written, or -1 on error
 */
ssize_t sshm_aead_encrypt(const uint8_t *key,
                          const uint8_t *plaintext, size_t pt_len,
                          uint8_t *output, size_t output_len);

/**
 * AEAD decrypt: input = nonce||ciphertext
 * @param key 32-byte key
 * @param input Encrypted data with nonce prepended
 * @param input_len Length of input
 * @param plaintext Output buffer
 * @param plaintext_len Max size of plaintext buffer
 * @return Number of bytes written, or -1 on error
 */
ssize_t sshm_aead_decrypt(const uint8_t *key,
                          const uint8_t *input, size_t input_len,
                          uint8_t *plaintext, size_t plaintext_len);

#ifdef __cplusplus
}
#endif

