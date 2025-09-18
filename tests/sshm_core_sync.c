#include "sshm.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    const char *name = "/test_sync";
    uint32_t magic = 0xDEADBEEF;

    printf("\n=== TEST: CREATE ===\n");
    int fd = sshm_create(name, O_CREAT | O_RDWR, 0666, 1024);
    if (fd == -1) { perror("sshm_create failed"); return 1; }
    close(fd);

    printf("\n=== TEST: OPEN & FORK ===\n");
    pid_t pid = fork();

    if (pid == -1) {
        perror("fork failed");
        return 1;
    }
    else if (pid == 0) {
        // === CHILD PROCESS ===
        sleep(2); // let parent go first
        const char *child_msg = "\nChild: Hello from shared memory!";
        sshm_write(name, magic, child_msg, strlen(child_msg));
        printf("[Child] Wrote message.\n");
        sleep(1); // simulate work
        char buf[256];
        ssize_t r = sshm_read(name, magic, buf, sizeof(buf)-1);
        if (r > 0) {
            buf[r] = '\0';
            printf("\n[Child] Read back: %s\n", buf);
        }
        _exit(0);
    } 
    else {
        // === PARENT PROCESS ===
        const char *parent_msg = "\nParent: Writing first!";
        sshm_write(name, magic, parent_msg, strlen(parent_msg));
        printf("[Parent] Wrote message.\n");
        sleep(3); // wait while child writes
        char buf[256];
        ssize_t r = sshm_read(name, magic, buf, sizeof(buf)-1);
        if (r > 0) {
            buf[r] = '\0';
            printf("\n[Parent] Read back: %s\n", buf);
        }
        wait(NULL); // wait for child
    }

   printf("\n=== TEST: DELETE ===\n");
    if (sshm_delete(name, magic) == -1) {
        perror("sshm_delete failed");
        return 1;
    }
    printf("Shared memory & semaphore deleted.\n");
    return 0;

}

