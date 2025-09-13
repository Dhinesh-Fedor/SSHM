#ifndef SSHM_CORE_H
#define SSHM_CORE_H

#include<stdint.h>
#include<stddef.h>
#include<sys/types.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>

typedef struct {
    uint32_t MAGIC;
    uint32_t VERSION;
    size_t SIZE;
} sshm_meta_t;

struct stat st;

sshm_meta_t DEFAULTS = {
    .MAGIC = 0xDEADBEEF,
    .VERSION = 1,
};

int sshm_create(const char *name, int oflags, mode_t mode, size_t size);
int sshm_o_exist(const char *name, uint32_t magic);

#endif
