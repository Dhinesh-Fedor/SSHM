#include "../include/sshm_create.h"


#include<stdio.h>
#include<stdlib.h>

int sshm_create(const char *name, int oflags, mode_t mode) {
    int shm_fd;

    shm_fd = shm_open(name, oflags, mode);
    if (shm_fd == -1) {
        perror("shm_open");
        exit(EXIT_FAILURE);
    }

    printf("shm_open: SUCCESS!\n");
    
    return 0;

}

