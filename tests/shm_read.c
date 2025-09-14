#include "sshm.h"

int main(void) {
    const char *name = "/test1";
    uint32_t magic = 0xDEADBEEF;
    char buff[36];   

    ssize_t n = sshm_read(name, magic, buff, sizeof(buff));

    if (n == -1) {
        printf("\nsshm_read failed");
        return 1;
        exit(EXIT_FAILURE);
    }


    printf("\nRead %zd bytes: %s\n", n, buff);

    return 0;
}

