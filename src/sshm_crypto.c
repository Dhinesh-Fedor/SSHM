/**
 * sshm_crypto.c
 * Implements AEAD encryption/decryption using libsodium (XChaCha20-Poly1305)
 */

#include "sshm_crypto.h"
#include <sodium.h>
#include <string.h>

/* Generate random 32-byte key */
int sshm_generate_key(uint8_t key[SSHM_KEYBYTES]) {
    if (!key) return -1;
   static int _sodium_initialized = 0;
   if (!_sodium_initialized) {
    if (sodium_init() < 0) return -1;
   _sodium_initialized = 1;
}
    randombytes_buf(key, SSHM_KEYBYTES);
    return 0;
}

/* AEAD encrypt (output = nonce||ciphertext) */
ssize_t sshm_aead_encrypt(const uint8_t *key,
                          const uint8_t *plaintext, size_t pt_len,
                          uint8_t *output, size_t output_len) {
    if (!key || !plaintext || !output) return -1;

    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t tag_len   = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (output_len < nonce_len + pt_len + tag_len) return -1;

    uint8_t nonce[nonce_len];
    randombytes_buf(nonce, sizeof(nonce));

    memcpy(output, nonce, nonce_len);

    unsigned long long cipher_len;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            output + nonce_len, &cipher_len,
            plaintext, pt_len,
            NULL, 0, NULL, nonce, key) != 0) return -1;

    return (ssize_t)(nonce_len + cipher_len);
}

/* AEAD decrypt (input = nonce||ciphertext) */
ssize_t sshm_aead_decrypt(const uint8_t *key,
                          const uint8_t *input, size_t input_len,
                          uint8_t *plaintext, size_t plaintext_len) {
    if (!key || !input || !plaintext) return -1;

    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (input_len < nonce_len + crypto_aead_xchacha20poly1305_ietf_ABYTES) return -1;

    const uint8_t *nonce = input;
    const uint8_t *cipher = input + nonce_len;
    size_t cipher_len = input_len - nonce_len;

    unsigned long long pt_len;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext, &pt_len, NULL,
            cipher, cipher_len,
            NULL, 0, nonce, key) != 0) return -1;

    if (pt_len > plaintext_len) return -1;
    return (ssize_t)pt_len;
}

