#include "sshm.h"

int main() {
    const char *name = "/test1";
    uint32_t magic = 0xDEADBEEF;
    char data[] = "Hello World!";

    ssize_t n = sshm_write(name, magic, data, strlen(data));

    if (n == -1) {
        perror("sshm_write failed");
        return 1;
    }

    printf("Successfully wrote %zd bytes to shared memory.\n", n);

    return 0;
}

