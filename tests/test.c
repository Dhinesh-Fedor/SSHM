#include "sshm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/types.h>

/*
  Test: 2 writers writing "Hello World" messages in between two readers.
  Each child prints its role and pid. Parent also does a final read after children exit.
*/

/* Child opens segment by name to avoid pointer/FD fragility across fork */
static void child_reader(int id, const char *seg_name, unsigned int start_delay_us) {
    usleep(start_delay_us);
    sshm_segment_t *seg = sshm_open(seg_name, SSHM_FLAG_NONE, NULL);
    if (!seg) {
        fprintf(stderr, "[reader %d pid=%d] open failed: %s\n", id, (int)getpid(), sshm_last_error());
        _exit(2);
    }

    size_t buf_len = sshm_get_size(seg);
    if (buf_len == 0) { sshm_close(seg); _exit(0); }
    char *buf = malloc(buf_len + 1);
    if (!buf) { sshm_close(seg); _exit(2); }

    /* read ciphertext (do_decrypt = 0) -- caller will see raw framed chunks */
    ssize_t n = sshm_read(seg, buf, buf_len, 0);
    if (n < 0) {
        fprintf(stderr, "[reader %d pid=%d] read error: %s\n", id, (int)getpid(), sshm_last_error());
    } else {
        if ((size_t)n > buf_len) n = buf_len;
        buf[n] = '\0';
        printf("[reader %d pid=%d] read %zd bytes: %s", id, (int)getpid(), n, buf);
        fflush(stdout);
    }

    free(buf);
    sshm_close(seg);
    _exit(0);
}

static void child_writer(int id, const char *seg_name, const char *msg, unsigned int start_delay_us) {
    usleep(start_delay_us);
    sshm_segment_t *seg = sshm_open(seg_name, SSHM_FLAG_ENCRYPTED, NULL);
    if (!seg) {
        fprintf(stderr, "[writer %d pid=%d] open failed: %s\n", id, (int)getpid(), sshm_last_error());
        _exit(2);
    }

    /* encrypted write (do_encrypt = 1) */
    if (sshm_write(seg, msg, strlen(msg), 1) != 0) {
        fprintf(stderr, "[writer %d pid=%d] write error: %s\n", id, (int)getpid(), sshm_last_error());
    } else {
        printf("[writer %d pid=%d] wrote: %s", id, (int)getpid(), msg);
        fflush(stdout);
    }
    sshm_close(seg);
    _exit(0);
}

int main(void) {
    const char *seg_name = "hw_test";

    if (sshm_init() != 0) {
        fprintf(stderr, "sshm_init failed: %s\n", sshm_last_error());
        return 1;
    }

    /* Create encrypted segment for the test */
    sshm_segment_t *seg = sshm_create(seg_name, 4096, SSHM_FLAG_ENCRYPTED, NULL, 0600);
    if (!seg) {
        fprintf(stderr, "Create failed: %s\n", sshm_last_error());
        return 1;
    }
    printf("Segment created (name=%s size=%zu flags=0x%x)\n", seg_name, sshm_get_size(seg), (unsigned)sshm_get_flags(seg));
    fflush(stdout);

    /* Parent writes an initial marker (encrypted) */
    const char *init = "INITIAL\n";
    if (sshm_write(seg, init, strlen(init), 1) != 0) {
        fprintf(stderr, "Initial write failed: %s\n", sshm_last_error());
        sshm_destroy(seg);
        return 1;
    }
    printf("[parent pid=%d] wrote initial marker\n", (int)getpid());
    fflush(stdout);

    pid_t pids[4] = {0};

    /* Fork reader 1 (should read initial content) */
    pid_t pid = fork();
    if (pid == 0) { child_reader(1, seg_name, 100 * 1000); } /* 100ms */
    if (pid > 0) pids[0] = pid;

    /* Fork writer 1 */
    pid = fork();
    if (pid == 0) {
        const char *m1 = "Hello World from writer 1\n";
        child_writer(1, seg_name, m1, 250 * 1000); /* 250ms */
    }
    if (pid > 0) pids[1] = pid;

    /* Fork writer 2 */
    pid = fork();
    if (pid == 0) {
        const char *m2 = "Hello World from writer 2\n";
        child_writer(2, seg_name, m2, 350 * 1000); /* 350ms */
    }
    if (pid > 0) pids[2] = pid;

    /* Fork reader 2 (should read after both writers) */
    pid = fork();
    if (pid == 0) { child_reader(2, seg_name, 500 * 1000); } /* 500ms */
    if (pid > 0) pids[3] = pid;

    /* Parent waits for children and then does a final read */
    for (int i = 0; i < 4; ++i) {
        if (pids[i] > 0) {
            int status = 0;
            waitpid(pids[i], &status, 0);
        }
    }

    /* Final parent read (return ciphertext, do_decrypt = 0) */
    size_t buflen = sshm_get_size(seg);
    char *buf = malloc(buflen + 1);
    if (buf) {
        ssize_t n = sshm_read(seg, buf, buflen, 0);
        if (n >= 0) {
            if ((size_t)n > buflen) n = buflen;
            buf[n] = '\0';
            printf("[final reader parent pid=%d] read %zd bytes:\n%s", (int)getpid(), n, buf);
            fflush(stdout);
        } else {
            fprintf(stderr, "[final reader parent pid=%d] read failed: %s\n", (int)getpid(), sshm_last_error());
        }
        free(buf);
    }

    /* Cleanup */
    //sshm_destroy(seg);
    //sshm_shutdown();
    return 0;
}

