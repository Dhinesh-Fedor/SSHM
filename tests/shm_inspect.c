#include "sshm.h"

int main() {
    const char *name = "/test_sync";
    uint32_t magic = 0xDEADBEEF;

    int ret = sshm_inspect(name, magic);
    if (ret == 0) {
        printf("Inspect successful!\n");
    } else {
        fprintf(stderr, "Inspect failed!\n");
    }

    return 0;
}

