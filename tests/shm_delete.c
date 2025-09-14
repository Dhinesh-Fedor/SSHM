#include "sshm.h"

int main() {
    const char *name = "/test1";
    uint32_t magic = 0xDEADBEEF;

    int ret = sshm_delete(name, magic);
    if (ret == 0) {
        printf("Shared memory '%s' deleted successfully!\n", name);
    } else {
        fprintf(stderr, "Failed to delete shared memory '%s'\n", name);
    }

    return 0;
}

