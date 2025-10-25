/**
 * sshm_core.c
 * Core logic: create/open/destroy/read/write secure shared memory (SSHM) v1.0
 */

#include "sshm_core.h"
#include "sshm_core_internal.h"
#include "sshm_sync.h"
#include "sshm_utils.h"
#include "sshm_crypto.h"
#include "sshm_daemon.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sodium.h>
#include <stdarg.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <arpa/inet.h>    // for htonl/ntohl


/* ---------------- DEBUG MACRO ---------------- */
#define SSHM_DEBUG 1
#if SSHM_DEBUG
#define DBG(fmt, ...) do { fprintf(stderr, "[SSHM DEBUG] " fmt "\n", ##__VA_ARGS__); fflush(stderr); } while(0)
#else
#define DBG(fmt, ...) do {} while(0)
#endif

/* ---------------- small secure zero helper (local) ---------------- */
/* removed local secure_zero() implementation to use secure_zero() declared in sshm_utils.h */
 
/* ---------------- client-side socket helpers (local) ---------------- */
static ssize_t cli_write_exact(int fd, const void *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t w = write(fd, (const char*)buf + total, n - total);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += w;
    }
    return (ssize_t)total;
}
static ssize_t cli_read_exact(int fd, void *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, (char*)buf + total, n - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        total += r;
    }
    return (ssize_t)total;
}

/* ---------------- Daemon key management (client side) ---------------- */
/* register: ask daemon to generate key (if key==NULL) and store authorized pid list */
static int register_key_with_daemon(const char *name, const uint8_t key[SSHM_KEYBYTES]) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET, sizeof(addr.sun_path)-1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return -1; }

    char cmd[16] = {0}; strncpy(cmd, "register", sizeof(cmd)-1);
    char segname[256] = {0}; strncpy(segname, name, sizeof(segname)-1);

    ssize_t cmd_len = (ssize_t)(sizeof(cmd) - 1);
    ssize_t seg_len = (ssize_t)(sizeof(segname) - 1);

    if (cli_write_exact(sock, cmd, cmd_len) < 0) { close(sock); return -1; }
    if (cli_write_exact(sock, segname, seg_len) < 0) { close(sock); return -1; }

    /* authorize current process (owner) so parent/child rule applies */
    int auth_count = 1;
    pid_t owner = (pid_t)getpid();
    if (cli_write_exact(sock, &auth_count, sizeof(auth_count)) < 0) { close(sock); return -1; }
    if (cli_write_exact(sock, &owner, sizeof(owner)) < 0) { close(sock); return -1; }

    uint8_t tmpkey[SSHM_KEYBYTES];
    if (key) memcpy(tmpkey, key, SSHM_KEYBYTES);
    else memset(tmpkey, 0, SSHM_KEYBYTES); /* zeros => daemon will generate */

    if (cli_write_exact(sock, tmpkey, SSHM_KEYBYTES) < 0) { close(sock); return -1; }

    /* read single byte ack */
    char ack = 0;
    if (cli_read_exact(sock, &ack, 1) != 1) { close(sock); return -1; }
    close(sock);
    return (ack == '1') ? 0 : -1;
}

/* request: fetch key (32 bytes). caller must be authorized (daemon enforces). */
static int request_key_from_daemon(const char *name, uint8_t out[SSHM_KEYBYTES]) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET, sizeof(addr.sun_path)-1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return -1; }

    char cmd[16] = {0}; strncpy(cmd, "fetch", sizeof(cmd)-1);
    char segname[256] = {0}; strncpy(segname, name, sizeof(segname)-1);

    ssize_t cmd_len = (ssize_t)(sizeof(cmd) - 1);
    ssize_t seg_len = (ssize_t)(sizeof(segname) - 1);

    if (cli_write_exact(sock, cmd, cmd_len) < 0) { close(sock); return -1; }
    if (cli_write_exact(sock, segname, seg_len) < 0) { close(sock); return -1; }

    uint8_t reply[SSHM_KEYBYTES];
    ssize_t r = cli_read_exact(sock, reply, SSHM_KEYBYTES);
    close(sock);
    if (r != SSHM_KEYBYTES) return -1;
    /* if reply all zeros -> unauthorized or missing */
    int allzero = 1;
    for (int i = 0; i < SSHM_KEYBYTES; ++i) if (reply[i]) { allzero = 0; break; }
    if (allzero) return -1;
    memcpy(out, reply, SSHM_KEYBYTES);
    return 0;
}

/* notify: send an audit note to daemon */
static void sshm_notify_daemon(const char *op, const char *seg_name) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET, sizeof(addr.sun_path)-1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return; }

    char cmd[16] = {0}; strncpy(cmd, "note", sizeof(cmd)-1);
    char segname[256] = {0}; if (seg_name) strncpy(segname, seg_name, sizeof(segname)-1);
    char opbuf[32] = {0}; if (op) strncpy(opbuf, op, sizeof(opbuf)-1);

    ssize_t cmd_len = (ssize_t)(sizeof(cmd) - 1);
    ssize_t seg_len = (ssize_t)(sizeof(segname) - 1);
    ssize_t op_len  = (ssize_t)(sizeof(opbuf) - 1);

    cli_write_exact(sock, cmd, cmd_len);
    cli_write_exact(sock, segname, seg_len);
    cli_write_exact(sock, opbuf, op_len);
    /* read ack but ignore */
    char ack = 0;
    cli_read_exact(sock, &ack, 1);
    close(sock);
}

/* ---------------- New: remove key RPC client ---------------- */
static int remove_key_from_daemon(const char *name) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET, sizeof(addr.sun_path)-1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return -1; }

    char cmd[16] = {0}; strncpy(cmd, "remove", sizeof(cmd)-1);
    char segname[256] = {0}; strncpy(segname, name, sizeof(segname)-1);

    ssize_t cmd_len = (ssize_t)(sizeof(cmd) - 1);
    ssize_t seg_len = (ssize_t)(sizeof(segname) - 1);

    if (cli_write_exact(sock, cmd, cmd_len) < 0) { close(sock); return -1; }
    if (cli_write_exact(sock, segname, seg_len) < 0) { close(sock); return -1; }

    char ack = 0;
    if (cli_read_exact(sock, &ack, 1) != 1) { close(sock); return -1; }
    close(sock);
    return (ack == '1') ? 0 : -1;
}

/* ---------------- Thread-local error ---------------- */
static __thread char tls_err[256];
const char *sshm_last_error(void) { return tls_err; }
void set_err(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(tls_err, sizeof(tls_err), fmt, ap);
    va_end(ap);
}

/* ---------------- Human-readable flags helper ---------------- */
const char *sshm_flags_to_string(uint32_t flags) {
    static char buf[64];
    buf[0] = '\0';
    if (flags == SSHM_FLAG_NONE) return "None";
    if (flags & SSHM_FLAG_ENCRYPTED) {
        if (buf[0]) strcat(buf, "|");
        strcat(buf, "Encrypted");
    }
    if (flags & SSHM_FLAG_PERSIST) {
        if (buf[0]) strcat(buf, "|");
        strcat(buf, "Persist");
    }
    return buf;
}

/* ---------------- Helper: segment key presence check ---------------- */
/* Return 1 if the segment has a non-zero key (i.e. we have a key available) */
static int seg_has_key(sshm_segment_t *seg) {
    if (!seg) return 0;
    /* Treat an all-zero key as "no key". */
    for (size_t i = 0; i < SSHM_KEYBYTES; ++i) {
        if (seg->key[i] != 0) return 1;
    }
    return 0;
}

/* ---------------- Active segments, init, create, open, ... ---------------- */
#define MAX_ACTIVE_SEGMENTS 128
static sshm_segment_t *active_segments[MAX_ACTIVE_SEGMENTS];
static int active_segment_count = 0;
static pthread_mutex_t active_lock = PTHREAD_MUTEX_INITIALIZER;

/* Daemon state */
static int daemon_started = 0;

/* ---------------- Initialization ---------------- */
int sshm_init(void) {
    if (sodium_init() < 0) { set_err("libsodium init failed"); return -1; }

    //int daemon_started = 0;
    if (!daemon_started) {
        pid_t pid = fork();
        if (pid < 0) { set_err("fork failed"); return -1; }
        if (pid == 0) { sshm_run_daemon(); _exit(0); }

        /* Retry until daemon socket is ready */
        int retries = 50;
        while (retries-- && access(DAEMON_SOCKET, F_OK) != 0) usleep(100000);
        if (retries <= 0) { set_err("SSHM daemon did not start"); return -1; }

        daemon_started = 1;
        printf("[SSHM DEBUG] Daemon started and ready\n");
    }
    return 0;
}


void sshm_shutdown(void) {
    pthread_mutex_lock(&active_lock);
    for (int i = 0; i < active_segment_count; i++) sshm_destroy(active_segments[i]);
    active_segment_count = 0;
    pthread_mutex_unlock(&active_lock);

    if (daemon_started) { sshm_daemon_cleanup(); daemon_started = 0; }
}

/* ---------------- Helpers ---------------- */
static void semname_for(const char *name, char out[128]) {
    snprintf(out, 128, "/sshm_%s_lock", name);
}

static uint32_t simple_crc32(const void *data, size_t n) {
    const uint8_t *p = data;
    uint32_t crc = 0;
    for (size_t i = 0; i < n; i++) crc = crc * 101 + p[i];
    return crc;
}

/* ---------------- Segment size ---------------- */
size_t sshm_get_size(sshm_segment_t *seg) {
    if (!seg) return 0;
    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(seg->map_base_offset, seg->header_offset);
    return hdr->payload_size;
}

/* Return the flags for a segment (safe accessor) */
uint32_t sshm_get_flags(sshm_segment_t *seg) {
    if (!seg) return SSHM_FLAG_NONE;
    return seg->flags;
}

/* ---------------- Create Segment ---------------- */
sshm_segment_t* sshm_create(const char *name, size_t size, uint32_t flags,
                            const uint8_t *key, mode_t mode) {
    if (!name || strlen(name) == 0 || strlen(name) > SSHM_MAX_NAME) { set_err("invalid name"); return NULL; }

    uint32_t real_flags = flags;

    /* build map size/header/payload etc */
    size_t map_size = sizeof(struct segment_header) + size;
    char shmname[SSHM_MAX_NAME + 16];
    snprintf(shmname, sizeof(shmname), "/sshm_%s", name);

    int fd = shm_open(shmname, O_CREAT | O_EXCL | O_RDWR, mode ? mode : 0660);
    if (fd < 0) { set_err("shm_open failed: %s", strerror(errno)); return NULL; }
    if (ftruncate(fd, (off_t)map_size) != 0) { set_err("ftruncate failed: %s", strerror(errno)); close(fd); shm_unlink(shmname); return NULL; }

    void *base = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { set_err("mmap failed: %s", strerror(errno)); close(fd); shm_unlink(shmname); return NULL; }

    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(base, 0);
    hdr->flags = real_flags;
    hdr->version = 0;
    hdr->payload_size = (uint64_t)size;
    hdr->data_len = 0;
    hdr->readers_count = 0;
    hdr->crc32 = 0;

    char semname[128]; semname_for(name, semname);
    sem_t *sem = sem_open(semname, O_CREAT | O_EXCL, 0600, 1);
    if (sem == SEM_FAILED) { sem_unlink(semname); sem = sem_open(semname, O_CREAT, 0600, 1); }
    if (sem == SEM_FAILED) { set_err("sem_open failed"); munmap(base, map_size); close(fd); shm_unlink(shmname); return NULL; }

    /* Allocate segment struct */
    sshm_segment_t *seg = calloc(1, sizeof(*seg));
    if (!seg) { set_err("calloc failed"); sem_close(sem); sem_unlink(semname); munmap(base, map_size); close(fd); shm_unlink(shmname); return NULL; }

    strncpy(seg->name, name, sizeof(seg->name) - 1);
    seg->shm_fd = fd;
    seg->map_size = map_size;
    seg->map_base_offset = (uintptr_t)base;
    seg->header_offset = 0;
    seg->sem = sem;
    seg->flags = real_flags;

    /* If encrypted, register key with daemon and fetch it */
    if (real_flags & SSHM_FLAG_ENCRYPTED) {
        if (register_key_with_daemon(name, key) != 0) {
            DBG("register_key_with_daemon failed for %s", name);
        } else {
            uint8_t fetched[SSHM_KEYBYTES];
            if (request_key_from_daemon(name, fetched) == 0) {
                memcpy(seg->key, fetched, SSHM_KEYBYTES);
                secure_zero(fetched, sizeof(fetched));
            }
        }
    }

    pthread_mutex_lock(&active_lock);
    if (active_segment_count < MAX_ACTIVE_SEGMENTS) active_segments[active_segment_count++] = seg;
    pthread_mutex_unlock(&active_lock);

    sshm_notify_daemon("create", name);
    return seg;
}


/* ---------------- Open Segment ---------------- */
sshm_segment_t* sshm_open(const char *name, uint32_t flags, const uint8_t *key) {
    (void)flags;

    char shmname[SSHM_MAX_NAME + 16];
    snprintf(shmname, sizeof(shmname), "/sshm_%s", name);

    int fd = shm_open(shmname, O_RDWR, 0);
    if (fd < 0) { set_err("shm_open failed: %s", strerror(errno)); return NULL; }

    struct stat st;
    if (fstat(fd, &st) != 0) { set_err("fstat failed: %s", strerror(errno)); close(fd); return NULL; }
    size_t map_size = (size_t)st.st_size;

    void *map_base = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map_base == MAP_FAILED) { set_err("mmap failed: %s", strerror(errno)); close(fd); return NULL; }

    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(map_base, 0);

    sshm_segment_t *seg = calloc(1, sizeof(*seg));
    if (!seg) { set_err("calloc failed"); munmap(map_base, map_size); close(fd); return NULL; }

    strncpy(seg->name, name, sizeof(seg->name) - 1);
    seg->shm_fd = fd;
    seg->map_size = map_size;
    seg->map_base_offset = (uintptr_t)map_base;
    seg->header_offset = 0;
    seg->flags = hdr->flags;

 /* if the segment is encrypted, obtain key if needed */
if (seg->flags & SSHM_FLAG_ENCRYPTED) {
    if (key) {
        memcpy(seg->key, key, SSHM_KEYBYTES);
    } else {
        uint8_t tmp[SSHM_KEYBYTES];
        if (request_key_from_daemon(name, tmp) == 0) {
            memcpy(seg->key, tmp, SSHM_KEYBYTES);
            secure_zero(tmp, sizeof(tmp));
        } else {
            DBG("request_key_from_daemon failed for %s - opening without key (ciphertext-only)", name);
            memset(seg->key, 0, sizeof(seg->key));
        }
    }
} else if (key) {
    /* optional: copy key even if segment is plaintext, for user convenience */
    memcpy(seg->key, key, SSHM_KEYBYTES);
}


    /* open existing semaphore */
    char semname2[128]; semname_for(name, semname2);
    sem_t *sem = sem_open(semname2, 0);
    if (sem == SEM_FAILED) sem = NULL;
    seg->sem = sem;

    pthread_mutex_lock(&active_lock);
    if (active_segment_count < MAX_ACTIVE_SEGMENTS) active_segments[active_segment_count++] = seg;
    pthread_mutex_unlock(&active_lock);

    sshm_notify_daemon("open", name);
    return seg;
}

/* ---------------- Close / Destroy Segment ---------------- */
int sshm_close(sshm_segment_t *seg) {
    if (!seg) return -1;

    if (seg->sem) { sem_close(seg->sem); seg->sem = NULL; }
    if (seg->map_base_offset && seg->map_size > 0) munmap((void *)seg->map_base_offset, seg->map_size);
    if (seg->shm_fd >= 0) { close(seg->shm_fd); seg->shm_fd = -1; }

    pthread_mutex_lock(&active_lock);
    for (int i = 0; i < active_segment_count; i++) {
        if (active_segments[i] == seg) {
            active_segments[i] = active_segments[active_segment_count - 1];
            active_segments[active_segment_count - 1] = NULL;
            active_segment_count--;
            break;
        }
    }
    pthread_mutex_unlock(&active_lock);

    secure_zero(seg->key, sizeof(seg->key));
    free(seg);
    return 0;
}

int sshm_destroy(sshm_segment_t *seg) {
    if (!seg) return -1;

    char shmname[SSHM_MAX_NAME + 16]; snprintf(shmname, sizeof(shmname), "/sshm_%s", seg->name);
    char semname[128]; semname_for(seg->name, semname);

    if (seg->sem) { sem_close(seg->sem); sem_unlink(semname); seg->sem = NULL; }
    if (seg->map_base_offset && seg->map_size > 0) munmap((void *)seg->map_base_offset, seg->map_size);
    if (seg->shm_fd >= 0) { close(seg->shm_fd); shm_unlink(shmname); seg->shm_fd = -1; }

    /* request daemon to remove key securely */
    if (remove_key_from_daemon(seg->name) == 0) {
        DBG("Key removed from daemon for %s", seg->name);
    } else {
        DBG("Failed to remove key from daemon for %s (may not exist or unauthorized)", seg->name);
    }

    /* audit destroy */
    sshm_notify_daemon("destroy", seg->name);

    pthread_mutex_lock(&active_lock);
    for (int i = 0; i < active_segment_count; i++) {
        if (active_segments[i] == seg) {
            active_segments[i] = active_segments[active_segment_count - 1];
            active_segments[active_segment_count - 1] = NULL;
            active_segment_count--;
            break;
        }
    }
    pthread_mutex_unlock(&active_lock);

    secure_zero(seg->key, sizeof(seg->key));
    free(seg);
    return 0;
}

/* ---------------- Read/Write with locks (per-call enc/dec) ---------------- */
/* Update signatures to match header: include do_encrypt / do_decrypt flags */
int sshm_write(sshm_segment_t *seg, const void *data, size_t len, int do_encrypt) {
    if (!seg || !data) return -1;

    if (sshm_wlock(seg) != 0) { set_err("failed to acquire writer lock"); return -1; }

    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(seg->map_base_offset, seg->header_offset);
    void *payload = (char *)SSHM_PTR(seg->map_base_offset, sizeof(struct segment_header));

    size_t slot_capacity = len;
    if (seg->flags & SSHM_FLAG_ENCRYPTED && do_encrypt)
        slot_capacity += crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    slot_capacity += 1 + 4; // type + length

    if ((hdr->data_len + slot_capacity) > hdr->payload_size) {
        set_err("Not enough space in segment");
        sshm_notify_daemon("overflow", seg->name);
        sshm_wunlock(seg);
        return -1;
    }

    uint8_t *chunk_buf = malloc(slot_capacity);
    if (!chunk_buf) { sshm_wunlock(seg); return -1; }

    size_t chunk_len = 0;

    if (seg->flags & SSHM_FLAG_ENCRYPTED && do_encrypt) {
        chunk_buf[0] = 1; // encrypted type
        uint32_t net_len = htonl(len + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        memcpy(chunk_buf + 1, &net_len, 4);

        uint8_t *nonce = chunk_buf + 5;
        uint8_t *ct_out = nonce + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

        unsigned long long ct_len;
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                ct_out, &ct_len,
                (const uint8_t *)data, len,
                NULL, 0, NULL,
                nonce, seg->key) != 0) {
            free(chunk_buf);
            sshm_wunlock(seg);
            return -1;
        }

        chunk_len = 5 + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + (size_t)ct_len;
    } else {
        chunk_buf[0] = 0; // plaintext
        uint32_t net_len = htonl(len);
        memcpy(chunk_buf + 1, &net_len, 4);
        memcpy(chunk_buf + 5, data, len);
        chunk_len = 5 + len;
    }

    uint32_t old_version = hdr->version;
    hdr->version = old_version + 1; // odd = write in progress
    msync(hdr, sizeof(*hdr), MS_SYNC);

    memcpy((char *)payload + hdr->data_len, chunk_buf, chunk_len);
    msync((char *)payload + hdr->data_len, chunk_len, MS_SYNC);

    hdr->data_len += chunk_len;
    hdr->crc32 = simple_crc32(payload, hdr->data_len);
    hdr->version = old_version + 2; // even = write complete
    msync(hdr, sizeof(*hdr), MS_SYNC);

    sshm_wunlock(seg);
    secure_zero(chunk_buf, chunk_len);
    free(chunk_buf);

    sshm_notify_daemon("write", seg->name);
    return 0;
}


ssize_t sshm_read(sshm_segment_t *seg, void *buffer, size_t buf_len, int do_decrypt) {
    if (!seg || !buffer) return -1;
    if (sshm_rlock(seg) != 0) { set_err("Failed to acquire reader lock"); return -1; }

    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(seg->map_base_offset, seg->header_offset);
    uint8_t *payload = (uint8_t *)SSHM_PTR(seg->map_base_offset, sizeof(struct segment_header));
    ssize_t total_out = 0;

    int max_retries = 16;

    while (max_retries-- > 0) {
        uint32_t ver_before = hdr->version;
        if (ver_before & 1) { usleep(1000); continue; } // write in progress

        size_t offset = 0;
        size_t out_off = 0;
        size_t data_len = hdr->data_len;

        while (offset + 5 <= data_len && out_off < buf_len) {
            uint8_t chunk_type = payload[offset++];
            uint32_t be_len;
            memcpy(&be_len, payload + offset, 4);
            offset += 4;
            uint32_t chunk_len = ntohl(be_len);

            if (offset + chunk_len > data_len) break; // incomplete

            if (chunk_type == 1 && do_decrypt) {
                if (!seg_has_key(seg)) { offset += chunk_len; continue; }

                ssize_t dec = sshm_aead_decrypt(seg->key, payload + offset, chunk_len,
                                                (uint8_t *)buffer + out_off, buf_len - out_off);
                if (dec > 0) out_off += dec;
            } else { // plaintext
                size_t tocopy = (chunk_len > buf_len - out_off) ? buf_len - out_off : chunk_len;
                memcpy((uint8_t *)buffer + out_off, payload + offset, tocopy);
                out_off += tocopy;
            }

            offset += chunk_len;
        }

        uint32_t ver_after = hdr->version;
        if ((ver_before == ver_after) && !(ver_after & 1)) {
            total_out = out_off;
            break;
        }

        usleep(1000);
    }

    if (total_out == 0) set_err("No consistent data could be read");

    sshm_runlock(seg);
    sshm_notify_daemon("read", seg->name);
    return total_out;
}
