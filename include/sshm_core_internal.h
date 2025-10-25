#pragma once
/**
 * sshm_core_internal.h
 * Internal struct definitions for Secure Shared Memory Toolkit (SSHM) v1.0
 * 
 * Notes:
 * - Designed for multi-process access.
 * - Uses a single payload buffer; no slots.
 * - Synchronization is done with a semaphore for read/write locking.
 * - Keys must be securely zeroed after use.
 */

#include <stdint.h>
#include <stddef.h>
#include <semaphore.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SSHM_MAX_NAME 256
#define SSHM_KEYBYTES 32

/* Internal header stored at the start of shared memory */
struct segment_header {
    uint32_t flags;          /* SSHM_FLAG_* */
    uint64_t version;        /* Segment versioning */
    uint64_t payload_size;   /* Total size of segment payload */
    uint64_t data_len;       /* Length of valid data in payload */
    uint32_t readers_count;  /* Active readers count for RW locking */
    uint32_t crc32;          /* Optional integrity check */
} __attribute__((packed));

/* Internal segment structure (not exposed to users) */
struct sshm_segment {
    char name[SSHM_MAX_NAME]; /* Segment name, null-terminated */
    int shm_fd;               /* File descriptor for shared memory */
    size_t map_size;          /* Total mapped size (header + payload) */
    uintptr_t map_base_offset;/* Base pointer as integer */
    uintptr_t header_offset;  /* Offset to segment_header, usually 0 */
    sem_t *sem;               /* POSIX semaphore for synchronization */
    uint32_t flags;           /* SSHM_FLAG_* */
    uint8_t key[SSHM_KEYBYTES]; /* Encryption key if needed */
};

/* Helper macros to convert offset <-> pointer */
#define SSHM_PTR(base, offset) ((void *)((uintptr_t)(base) + (uintptr_t)(offset)))
#define SSHM_OFFSET(base, ptr) ((uintptr_t)(ptr) - (uintptr_t)(base))

#ifdef __cplusplus
}
#endif

