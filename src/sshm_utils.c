/**
 * sshm_utils.c
 * Error handling, logging, and secure memory operations.
 */

#include "sshm_utils.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* Convert SSHM error codes to human-readable string */
const char *sshm_errstr(int err) {
    switch(err) {
        case SSHM_OK: return "OK";
        case SSHM_ERR_NO_MEM: return "Out of memory";
        case SSHM_ERR_INVAL: return "Invalid argument";
        case SSHM_ERR_NOTFOUND: return "Not found";
        case SSHM_ERR_EXISTS: return "Already exists";
        case SSHM_ERR_PERM: return "Permission denied";
        case SSHM_ERR_ENCRYPT: return "Encryption error";
        case SSHM_ERR_AUTH_FAILED: return "Authentication failed";
        case SSHM_ERR_CORRUPT: return "Data corrupt";
        case SSHM_ERR_LOCK: return "Lock error";
        case SSHM_ERR_IO: return "I/O error";
        default: return "Generic error";
    }
}

/* Logging utility (stderr) */
int sshm_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    return r;
}

/* Securely zero memory */
void secure_zero(void *p, size_t n) {
    if (!p || n == 0) return;
#if defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    volatile unsigned char *v = (volatile unsigned char*)p;
    while (n--) *v++ = 0;
#endif
}

