/**
 * sshm_daemon.c
 * SSHM Daemon v1.1 – manages encryption keys and audit logs
 * Auto-authorizes parent-child relationships for multi-process access
 */

#include "sshm_daemon.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef DAEMON_SOCKET
#define DAEMON_SOCKET "/tmp/sshm_daemon.sock"
#endif

#define MAX_SEGMENTS 2048
#define MAX_AUDIT 4096

typedef struct {
    char name[256];
    uint8_t key[32];
    pid_t *authorized_pids;
    size_t auth_count;
    int in_use;
} key_entry_t;

typedef struct {
    char name[256];
    char op[32];
    time_t timestamp;
} audit_entry_t;

static key_entry_t *key_db = NULL;
static int key_count = 0;
static audit_entry_t *audit_log = NULL;
static int audit_index = 0;

static pthread_mutex_t db_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t audit_lock = PTHREAD_MUTEX_INITIALIZER;
static int server_sock = -1;
static int daemon_running = 1;

/* simple secure zero */
static void secure_zero(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) *vp++ = 0;
}

/* Cleanup */
void sshm_daemon_cleanup(void) {
    if (server_sock >= 0) close(server_sock);
    unlink(DAEMON_SOCKET);
    if (key_db) {
        for (int i = 0; i < MAX_SEGMENTS; ++i) {
            if (key_db[i].in_use) {
                secure_zero(key_db[i].key, sizeof(key_db[i].key));
                free(key_db[i].authorized_pids);
            }
        }
        free(key_db);
    }
    if (audit_log) free(audit_log);
}

/* Signal Handler */
static void sig_handler(int signo) { (void)signo; daemon_running = 0; }

/* I/O Helpers */
static ssize_t read_exact(int fd, void *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, (char*)buf + total, n - total);
        if (r < 0) { if (errno == EINTR) continue; return r; }
        if (r == 0) break;
        total += r;
    }
    return (ssize_t)total;
}

static ssize_t write_exact(int fd, const void *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t w = write(fd, (const char*)buf + total, n - total);
        if (w < 0) { if (errno == EINTR) continue; return w; }
        total += w;
    }
    return (ssize_t)total;
}

/* get peer pid from unix socket */
static pid_t get_peer_pid(int clientfd) {
#ifdef SO_PEERCRED
    struct { pid_t pid; uid_t uid; gid_t gid; } cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(clientfd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) {
        return (pid_t)cred.pid;
    }
#endif
    return -1;
}

/* helper: read PPid from /proc/<pid>/status */
static pid_t get_parent_of(pid_t pid) {
    if (pid <= 0) return -1;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    pid_t ppid = -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "PPid:\t%d", &ppid) == 1) break;
    }
    fclose(f);
    return ppid;
}

/* Key DB helpers */
static key_entry_t* find_key(const char *name) {
    for (int i = 0; i < key_count; i++)
        if (key_db[i].in_use && strcmp(key_db[i].name, name) == 0)
            return &key_db[i];
    return NULL;
}

static int store_key_with_auth(const char *name, const uint8_t key[32],
                               pid_t *auth_pids, size_t auth_count) {
    pthread_mutex_lock(&db_lock);
    key_entry_t *entry = find_key(name);
    if (!entry) {
        if (key_count >= MAX_SEGMENTS) { pthread_mutex_unlock(&db_lock); return -1; }
        entry = &key_db[key_count++];
        memset(entry, 0, sizeof(*entry));
        entry->in_use = 1;
        snprintf(entry->name, sizeof(entry->name), "%s", name);
    } else {
        if (entry->authorized_pids) { free(entry->authorized_pids); entry->authorized_pids = NULL; entry->auth_count = 0; }
    }

    memcpy(entry->key, key, 32);
    if (auth_pids && auth_count) {
        entry->authorized_pids = calloc(auth_count, sizeof(pid_t));
        if (!entry->authorized_pids) { pthread_mutex_unlock(&db_lock); return -1; }
        memcpy(entry->authorized_pids, auth_pids, auth_count * sizeof(pid_t));
        entry->auth_count = auth_count;
    } else {
        entry->authorized_pids = NULL;
        entry->auth_count = 0;
    }
    pthread_mutex_unlock(&db_lock);
    return 0;
}

/* Authorization check with parent-child support */
static int is_authorized_for_entry(key_entry_t *entry, pid_t caller_pid) {
    if (!entry || !entry->in_use) return 0;

    pid_t caller_ppid = get_parent_of(caller_pid);

    for (size_t i = 0; i < entry->auth_count; ++i) {
        pid_t auth = entry->authorized_pids[i];
        pid_t auth_ppid = get_parent_of(auth);

        if (auth == caller_pid) return 1;          // exact match
        if (auth == caller_ppid) return 1;         // caller is child of authorized PID
        if (auth_ppid == caller_pid) return 1;     // caller is parent of authorized PID
    }

    // allow everyone if no auth list
    if (entry->auth_count == 0) return 1;

    return 0;
}

/* Audit Logging */
static void add_audit(const char *name, const char *op) {
    pthread_mutex_lock(&audit_lock);
    strncpy(audit_log[audit_index].name, name ? name : "-", sizeof(audit_log[audit_index].name)-1);
    strncpy(audit_log[audit_index].op, op ? op : "-", sizeof(audit_log[audit_index].op)-1);
    audit_log[audit_index].timestamp = time(NULL);
    audit_index = (audit_index + 1) % MAX_AUDIT;
    pthread_mutex_unlock(&audit_lock);
}

static void iso8601_time(time_t t, char *buf, size_t sz) {
    struct tm tm_val;
    gmtime_r(&t, &tm_val);
    strftime(buf, sz, "%Y-%m-%dT%H:%M:%SZ", &tm_val);
}

/* Client Handler */
static void* handle_client(void *arg) {
    int client = *(int*)arg; free(arg);
    char cmd[16] = {0};
    char segname[256] = {0};
    if (read_exact(client, cmd, sizeof(cmd)-1) <= 0) { close(client); return NULL; }
    cmd[sizeof(cmd)-1] = 0;
    if (read_exact(client, segname, sizeof(segname)-1) <= 0) segname[0] = 0;

    pid_t caller = get_peer_pid(client);
    printf("[DAEMON DEBUG] Command '%s' for '%s' from PID %d\n", cmd, segname, caller);

    if (strcmp(cmd, "register") == 0) {
        int auth_count = 0;
        if (read_exact(client, &auth_count, sizeof(int)) <= 0) { close(client); return NULL; }
        pid_t *auths = NULL;
        if (auth_count > 0) {
            auths = calloc(auth_count, sizeof(pid_t));
            if (!auths) { close(client); return NULL; }
            if (read_exact(client, auths, auth_count * sizeof(pid_t)) != (ssize_t)(auth_count * sizeof(pid_t))) {
                free(auths); close(client); return NULL;
            }
        }
        uint8_t key[32];
        if (read_exact(client, key, 32) != 32) { if (auths) free(auths); close(client); return NULL; }

        int allzero = 1;
        for (int i = 0; i < 32; ++i) if (key[i]) { allzero = 0; break; }
        if (allzero) {
            int fd = open("/dev/urandom", O_RDONLY);
            if (fd >= 0) {
                if (read_exact(fd, key, 32) != 32) { close(fd); if (auths) free(auths); close(client); return NULL; }
                close(fd);
            } else {
                for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(rand() & 0xff);
            }
        }

        int ret = store_key_with_auth(segname, key, auths, (size_t)auth_count);
        if (ret == 0) {
            printf("[DAEMON DEBUG] Registered key for '%s'\n", segname);
            add_audit(segname, "register");
        } else {
            printf("[DAEMON DEBUG] Failed to register key for '%s'\n", segname);
        }
        char ack = (ret == 0) ? '1' : '0';
        write_exact(client, &ack, 1);
        if (auths) free(auths);

    } else if (strcmp(cmd, "fetch") == 0) {
        uint8_t reply[32] = {0};
        pthread_mutex_lock(&db_lock);
        key_entry_t *entry = find_key(segname);
        if (entry && is_authorized_for_entry(entry, caller)) {
            memcpy(reply, entry->key, 32);
            add_audit(segname, "fetch_ok");
        } else {
            add_audit(segname, "fetch_unauth");
        }
        pthread_mutex_unlock(&db_lock);
        write_exact(client, reply, 32);

    } else if (strcmp(cmd, "note") == 0) {
        char op[32] = {0};
        if (read_exact(client, op, sizeof(op)-1) <= 0) { close(client); return NULL; }
        add_audit(segname, op);
        char ack = '1'; write_exact(client, &ack, 1);

    } else if (strcmp(cmd, "remove") == 0) {
        pthread_mutex_lock(&db_lock);
        key_entry_t *entry = find_key(segname);
        if (entry && entry->in_use) {
            secure_zero(entry->key, sizeof(entry->key));
            if (entry->authorized_pids) { free(entry->authorized_pids); entry->authorized_pids = NULL; }
            entry->auth_count = 0;
            entry->in_use = 0;
            add_audit(segname, "remove_key");
            char ack = '1'; write_exact(client, &ack, 1);
        } else {
            add_audit(segname, "remove_key_notfound");
            char nack = '0'; write_exact(client, &nack, 1);
        }
        pthread_mutex_unlock(&db_lock);

    } else if (strcmp(cmd, "audit") == 0) {
        int count = 0;
        if (read_exact(client, &count, sizeof(int)) <= 0) count = MAX_AUDIT;
        pthread_mutex_lock(&audit_lock);
        int total = (count > MAX_AUDIT) ? MAX_AUDIT : count;
        for (int i = 0; i < total; i++) {
            int idx = (audit_index - total + i + MAX_AUDIT) % MAX_AUDIT;
            if (audit_log[idx].timestamp == 0) continue;
            char buf[512], ts[64];
            iso8601_time(audit_log[idx].timestamp, ts, sizeof(ts));
            snprintf(buf, sizeof(buf), "%s\t%s\t%s\n", ts, audit_log[idx].name, audit_log[idx].op);
            write_exact(client, buf, strlen(buf));
        }
        pthread_mutex_unlock(&audit_lock);

    } else if (strcmp(cmd, "shutdown") == 0) {
        add_audit("daemon", "shutdown"); daemon_running = 0;
    }

    close(client);
    return NULL;
}

/* Main Loop */
int sshm_run_daemon(void) {
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    atexit(sshm_daemon_cleanup);

    key_db = calloc(MAX_SEGMENTS, sizeof(key_entry_t));
    audit_log = calloc(MAX_AUDIT, sizeof(audit_entry_t));
    if (!key_db || !audit_log) { fprintf(stderr,"Memory alloc failed\n"); return -1; }

    server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sock < 0) { perror("socket"); return -1; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET, sizeof(addr.sun_path)-1);
    unlink(DAEMON_SOCKET);

    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return -1; }
    if (listen(server_sock, 10) < 0) { perror("listen"); return -1; }

    printf("SSHM Daemon running...\n");
    while (daemon_running) {
        int *client = malloc(sizeof(int));
        if (!client) continue;
        *client = accept(server_sock, NULL, NULL);
        if (*client < 0) { free(client); continue; }
        pthread_t tid; pthread_create(&tid, NULL, handle_client, client);
        pthread_detach(tid);
    }
    sshm_daemon_cleanup();
    return 0;
}
