#pragma once
/**
 * sshm_sync.h
 * POSIX semaphore helpers for SSHM
 * Internal use only
 */

#include "sshm_core.h"  /* Use opaque pointer only */

#ifdef __cplusplus
extern "C" {
#endif

/* Basic exclusive lock */
int sshm_lock(sshm_segment_t *seg);
int sshm_unlock(sshm_segment_t *seg);

/* Reader/Writer locks */
int sshm_rlock(sshm_segment_t *seg);   /* Acquire read lock */
int sshm_runlock(sshm_segment_t *seg); /* Release read lock */
int sshm_wlock(sshm_segment_t *seg);   /* Acquire write lock */
int sshm_wunlock(sshm_segment_t *seg); /* Release write lock */

#ifdef __cplusplus
}
#endif

