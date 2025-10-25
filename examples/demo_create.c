/**
 * demo_create.c
 * Example: create an encrypted SSHM segment
 */

#include <stdio.h>
#include <stdint.h>
#include "sshm.h"

int main() {
    // Key for encryption
    uint8_t key[SSHM_KEYBYTES];
    if (sshm_generate_key(key) != 0) {
        fprintf(stderr, "Failed to generate key\n");
        return 1;
    }

    // Create an encrypted segment named "example" with 4096 bytes
    // Mode 0600 = read/write for owner only
    sshm_segment_t *seg = sshm_create("example", 4096, SSHM_FLAG_ENCRYPTED, key, 0600);
    if (!seg) {
        fprintf(stderr, "Failed to create segment: %s\n", sshm_last_error());
        return 1;
    }

    printf("Segment 'example' created successfully!\n");

    // Optional: write some data
    const char *msg = "Hello SSHM!";
    if (sshm_write(seg, msg, strlen(msg)) != 0) {
        fprintf(stderr, "Failed to write: %s\n", sshm_last_error());
    }

    // Read back
    char buf[1024] = {0};
    ssize_t r = sshm_read(seg, buf, sizeof buf);
    if (r > 0) {
        printf("Read from segment: %.*s\n", (int)r, buf);
    }

    // Cleanup
    sshm_destroy(seg);
    return 0;
}

