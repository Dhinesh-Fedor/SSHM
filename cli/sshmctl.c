/**
 * sshmctl.c
 * CLI for SSHM: create/destroy/write/read/audit/start/shutdown
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "sshm_core.h"
#include "sshm_daemon.h"

#define DAEMON_SOCKET "/tmp/sshm_daemon.sock"

/* Segment flags */
#define SSHM_FLAG_NONE      0
#define SSHM_FLAG_ENCRYPTED (1u << 0)
#define SSHM_FLAG_PERSIST   (1u << 1)

/* Display usage */
void usage(void) {
    fprintf(stderr,
        "Usage: sshmctl <cmd> [args]\n"
        "Commands:\n"
        "  create <name> <size> [--none|--encrypted|--persist|--enc-persist]\n"
        "  destroy <name>\n"
        "  write <name> <infile> [--enc] [--none|--encrypted|--persist|--enc-persist]\n"
        "  read <name> <outfile> [--dec] [--none|--encrypted|--persist|--enc-persist]\n"
        "  remove-key <name>\n"
        "  audit [count]\n"
        "  start-daemon\n"
        "  shutdown-daemon\n"
    );
}

/* Parse CLI string to segment flags */
static uint32_t parse_flag(const char *str) {
    if (!str) return SSHM_FLAG_NONE;
    if (strcmp(str, "--none") == 0) return SSHM_FLAG_NONE;
    if (strcmp(str, "--encrypted") == 0) return SSHM_FLAG_ENCRYPTED;
    if (strcmp(str, "--persist") == 0) return SSHM_FLAG_PERSIST;
    if (strcmp(str, "--enc-persist") == 0) return SSHM_FLAG_ENCRYPTED | SSHM_FLAG_PERSIST;
    fprintf(stderr, "Unknown flag '%s', using NONE\n", str);
    return SSHM_FLAG_NONE;
}

/* Send command to daemon with optional int payload */
static int daemon_command_with_int(const char *cmd, const char *segname, const int *opt_int) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET, sizeof(addr.sun_path)-1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect daemon");
        close(sock);
        return -1;
    }

    char cmdbuf[16] = {0};
    char segbuf[256] = {0};
    strncpy(cmdbuf, cmd ? cmd : "", sizeof(cmdbuf)-1);
    if (segname) strncpy(segbuf, segname, sizeof(segbuf)-1);

    ssize_t cmd_len = sizeof(cmdbuf)-1;
    ssize_t seg_len = sizeof(segbuf)-1;

    if (write(sock, cmdbuf, cmd_len) != cmd_len) { perror("write cmd"); close(sock); return -1; }
    if (write(sock, segbuf, seg_len) != seg_len) { perror("write seg"); close(sock); return -1; }

    if (opt_int) {
        if (write(sock, opt_int, sizeof(int)) != (ssize_t)sizeof(int)) { perror("write int"); close(sock); return -1; }
    }

    char buf[512];
    ssize_t r;
    while ((r = read(sock, buf, sizeof(buf)-1)) > 0) {
        buf[r] = '\0';
        fputs(buf, stdout);
    }
    close(sock);
    return 0;
}

/* Convenience wrappers */
int daemon_command(const char *cmd) {
    return daemon_command_with_int(cmd, NULL, NULL);
}

int fetch_audit(int count) {
    return daemon_command_with_int("audit", NULL, &count);
}

int daemon_remove_key(const char *name) {
    return daemon_command_with_int("remove", name, NULL);
}

/* Main CLI */
int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];

    /* Start daemon */
    if (strcmp(cmd, "start-daemon") == 0) {
        if (fork() == 0) _exit(sshm_run_daemon());
        printf("Daemon started\n");
        return 0;
    }

    /* Shutdown daemon */
    if (strcmp(cmd, "shutdown-daemon") == 0) {
        return daemon_command_with_int("shutdown", NULL, NULL);
    }

    /* Initialize SSHM core */
    if (sshm_init() != 0) {
        fprintf(stderr, "sshm_init failed: %s\n", sshm_last_error());
        return 2;
    }

    /* CREATE */
    if (strcmp(cmd, "create") == 0) {
        if (argc < 4) { usage(); return 1; }
        const char *name = argv[2];
        size_t sz = strtoul(argv[3], NULL, 10);
        uint32_t flags = parse_flag(argc >= 5 ? argv[4] : NULL);

        sshm_segment_t *seg = sshm_create(name, sz, flags, NULL, 0660);
        if (!seg) { fprintf(stderr, "create failed: %s\n", sshm_last_error()); return 5; }

        printf("Created '%s' (size=%zu flags=%s)\n", name, sz, sshm_flags_to_string(sshm_get_flags(seg)));
        sshm_close(seg);
        return 0;
    }

    /* DESTROY */
    if (strcmp(cmd, "destroy") == 0) {
        if (argc < 3) { usage(); return 1; }
        const char *name = argv[2];

        sshm_segment_t *seg = sshm_open(name, SSHM_FLAG_NONE, NULL);
        if (!seg) { fprintf(stderr, "open failed: %s\n", sshm_last_error()); return 6; }

        printf("Destroyed '%s' (flags=%s)\n", name, sshm_flags_to_string(sshm_get_flags(seg)));
        sshm_destroy(seg);
        return 0;
    }

    /* WRITE */
    if (strcmp(cmd, "write") == 0) {
        if (argc < 4) { usage(); return 1; }
        const char *name = argv[2];
        const char *infile = argv[3];
        int do_enc = 0;
        const char *flag_arg = NULL;

        for (int i = 4; i < argc; ++i) {
            if (strcmp(argv[i], "--enc") == 0) do_enc = 1;
            else flag_arg = argv[i];
        }
        uint32_t flags = parse_flag(flag_arg);

        FILE *f = fopen(infile, "rb");
        if (!f) { perror("infile"); return 7; }
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        fseek(f, 0, SEEK_SET);
        void *buf = malloc(len);
        if (!buf) { perror("malloc"); fclose(f); return 8; }
        fread(buf, 1, len, f);
        fclose(f);

        sshm_segment_t *seg = sshm_open(name, flags, NULL);
        if (!seg) { fprintf(stderr, "open failed: %s\n", sshm_last_error()); free(buf); return 9; }
        if (sshm_write(seg, buf, len, do_enc) != 0) {
            fprintf(stderr, "write failed: %s\n", sshm_last_error());
            sshm_close(seg); free(buf); return 10;
        }

        printf("Wrote %ld bytes to '%s' (enc=%d flags=%s)\n", len, name, do_enc, sshm_flags_to_string(sshm_get_flags(seg)));
        sshm_close(seg);
        free(buf);
        return 0;
    }

    /* READ */
    if (strcmp(cmd, "read") == 0) {
        if (argc < 4) { usage(); return 1; }
        const char *name = argv[2];
        const char *outfile = argv[3];
        int do_dec = 0;
        const char *flag_arg = NULL;

        for (int i = 4; i < argc; ++i) {
            if (strcmp(argv[i], "--dec") == 0) do_dec = 1;
            else flag_arg = argv[i];
        }
        uint32_t flags = parse_flag(flag_arg);

        sshm_segment_t *seg = sshm_open(name, flags, NULL);
        if (!seg) { fprintf(stderr, "open failed: %s\n", sshm_last_error()); return 11; }

        size_t buf_len = sshm_get_size(seg);
        void *buf = malloc(buf_len);
        if (!buf) { perror("malloc"); sshm_close(seg); return 12; }
        ssize_t r = sshm_read(seg, buf, buf_len, do_dec);
        if (r < 0) { fprintf(stderr, "read failed: %s\n", sshm_last_error()); sshm_close(seg); free(buf); return 13; }

        FILE *f = fopen(outfile, "wb");
        if (!f) { perror("outfile"); sshm_close(seg); free(buf); return 14; }
        fwrite(buf, 1, r, f);
        fclose(f);

        printf("Read %zd bytes from '%s' to '%s' (dec=%d flags=%s)\n", r, name, outfile, do_dec, sshm_flags_to_string(sshm_get_flags(seg)));
        sshm_close(seg);
        free(buf);
        return 0;
    }

    /* REMOVE-KEY */
    if (strcmp(cmd, "remove-key") == 0) {
        if (argc < 3) { usage(); return 1; }
        const char *name = argv[2];
        if (daemon_remove_key(name) == 0) {
            printf("Key removed for '%s'\n", name);
            return 0;
        } else {
            fprintf(stderr, "remove-key failed for '%s'\n", name);
            return 1;
        }
    }

    /* AUDIT */
    if (strcmp(cmd, "audit") == 0) {
        int count = 10;
        if (argc >= 3) count = atoi(argv[2]);
        return fetch_audit(count);
    }

    usage();
    return 1;
}
