#pragma once
/**
 * sshm_utils.h
 * Utility functions: error codes, logging, secure memory zeroing.
 */

#include <stddef.h>
#include <stdarg.h>  /* required for variadic logging */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Standard SSHM error codes */
enum sshm_error_codes {
    SSHM_OK = 0,
    SSHM_ERR_GENERIC = -1,
    SSHM_ERR_NO_MEM = -2,
    SSHM_ERR_INVAL = -3,
    SSHM_ERR_NOTFOUND = -4,
    SSHM_ERR_EXISTS = -5,
    SSHM_ERR_PERM = -6,
    SSHM_ERR_ENCRYPT = -7,
    SSHM_ERR_AUTH_FAILED = -8,
    SSHM_ERR_CORRUPT = -9,
    SSHM_ERR_LOCK = -10,
    SSHM_ERR_IO = -11,
};

/* Convert error code to human-readable string */
const char *sshm_errstr(int err);

/* Logging utility (variadic) */
int sshm_log(const char *fmt, ...);

/* Securely zero memory (prevents compiler optimizations from removing zeroing) */
void secure_zero(void *p, size_t n);

#ifdef __cplusplus
}
#endif

