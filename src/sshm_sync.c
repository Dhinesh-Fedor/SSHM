#include "sshm_sync.h"
#include "sshm_core_internal.h"
#include "sshm_utils.h"
#include <semaphore.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>

/* ---------------- Basic exclusive lock ---------------- */
int sshm_lock(sshm_segment_t *seg) {
    if (!seg || !seg->sem) return -1;
    while (sem_wait(seg->sem) != 0) {
        if (errno == EINTR) continue;  // Retry on signal
        return -1;
    }
    return 0;
}

int sshm_unlock(sshm_segment_t *seg) {
    if (!seg || !seg->sem) return -1;
    if (sem_post(seg->sem) != 0) return -1;
    return 0;
}

/* ---------------- Reader lock/unlock ---------------- */
int sshm_rlock(sshm_segment_t *seg) {
    if (!seg) return -1;
    if (sshm_lock(seg) != 0) return -1;

    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(seg->map_base_offset, seg->header_offset);
    hdr->readers_count++;

    sshm_unlock(seg);
    return 0;
}

int sshm_runlock(sshm_segment_t *seg) {
    if (!seg) return -1;
    if (sshm_lock(seg) != 0) return -1;

    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(seg->map_base_offset, seg->header_offset);
    if (hdr->readers_count > 0) hdr->readers_count--;

    sshm_unlock(seg);
    return 0;
}

/* ---------------- Writer lock/unlock ---------------- */
int sshm_wlock(sshm_segment_t *seg) {
    if (!seg) return -1;

    while (1) {
        if (sshm_lock(seg) != 0) return -1;

        struct segment_header *hdr = (struct segment_header *)SSHM_PTR(seg->map_base_offset, seg->header_offset);
        if (hdr->readers_count == 0) break;  // Exclusive access achieved

        sshm_unlock(seg);
        usleep(50); // Avoid tight busy-wait
    }
    return 0;
}

int sshm_wunlock(sshm_segment_t *seg) {
    return sshm_unlock(seg);
}

