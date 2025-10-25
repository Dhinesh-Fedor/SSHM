#pragma once
/**
 * sshm_core.h
 * Public interface for Secure Shared Memory Toolkit (SSHM) v1.0
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SSHM_MAX_NAME 256
#define SSHM_KEYBYTES 32

typedef struct sshm_segment sshm_segment_t;

/* Library lifecycle */
int sshm_init(void);
void sshm_shutdown(void);

/* Segment operations */
sshm_segment_t *sshm_create(const char *name, size_t size, uint32_t flags,
                            const uint8_t *key, mode_t mode);
sshm_segment_t *sshm_open(const char *name, uint32_t flags, const uint8_t *key);
int sshm_close(sshm_segment_t *seg);
int sshm_destroy(sshm_segment_t *seg);

/* Read/write segment contents
   - sshm_write: per-call encrypt flag (do_encrypt)
       do_encrypt == 1 -> encrypt plaintext before storing into segment
       do_encrypt == 0 -> store plaintext as-is into encrypted segment (ciphertext will be plaintext bytes)
   - sshm_read: per-call decrypt flag (do_decrypt)
       do_decrypt == 1 -> decrypt stored content before returning
       do_decrypt == 0 -> return raw stored bytes
*/
int sshm_write(sshm_segment_t *seg, const void *data, size_t len, int do_encrypt);
ssize_t sshm_read(sshm_segment_t *seg, void *buffer, size_t buf_len, int do_decrypt);

/* Retrieve last error string (thread-local) */
const char *sshm_last_error(void);
void set_err(const char *fmt, ...);
size_t sshm_get_size(sshm_segment_t *seg);
uint32_t sshm_get_flags(sshm_segment_t *seg);

/* Segment flags */
#define SSHM_FLAG_NONE      0
#define SSHM_FLAG_ENCRYPTED (1u << 0)
#define SSHM_FLAG_PERSIST   (1u << 1)

/* Helper: human readable flags string (returns pointer to static buffer) */
const char *sshm_flags_to_string(uint32_t flags);

#ifdef __cplusplus
}
#endif

