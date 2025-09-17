#include "sshm.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *name = "/test1";
    uint32_t magic = 0xDEADBEEF;

    // 1. Create shared memory
    printf("\n=== TEST: CREATE ===\n");
    int fd = sshm_create(name, O_CREAT | O_RDWR, 0666, 1024);
    if (fd == -1) {
        perror("sshm_create failed");
        return 1;
    }
    close(fd); // caller should close after create

    // 2. Inspect metadata
    printf("\n=== TEST: INSPECT AFTER CREATE ===\n");
    if (sshm_inspect(name, magic) == -1) {
        perror("sshm_inspect failed");
        return 1;
    }

    // 3. Open existing
    printf("\n=== TEST: OPEN EXISTING ===\n");
    int exist_fd = sshm_o_exist(name, magic);
    if (exist_fd == -1) {
        perror("sshm_o_exist failed");
        return 1;
    }
    close(exist_fd);

    // 4. Write some data
    printf("\n=== TEST: WRITE ===\n");
    const char *msg = "Hello World!Hello World!Hello World!";
    ssize_t written = sshm_write(name, magic, msg, strlen(msg));
    if (written == -1) {
        perror("sshm_write failed");
        return 1;
    }
    printf("Wrote %zd bytes.\n", written);

    // 5. Inspect again
    printf("\n=== TEST: INSPECT AFTER WRITE ===\n");
    if (sshm_inspect(name, magic) == -1) {
        perror("sshm_inspect failed");
        return 1;
    }

    // 6. Read back
    printf("\n=== TEST: READ ===\n");
    char buffer[256];
    ssize_t read_bytes = sshm_read(name, magic, buffer, sizeof(buffer));
    if (read_bytes == -1) {
        perror("sshm_read failed");
        return 1;
    }
    // Ensure null-terminated for printing as string
    if (read_bytes < sizeof(buffer)) buffer[read_bytes] = '\0';
    else buffer[sizeof(buffer)-1] = '\0';

    printf("Read %zd bytes: %s\n", read_bytes, buffer);

    // 7. Delete segment
    printf("\n=== TEST: DELETE ===\n");
    if (sshm_delete(name, magic) == -1) {
        perror("sshm_delete failed");
        return 1;
    }
    printf("Shared memory deleted successfully.\n");

    return 0;
}

