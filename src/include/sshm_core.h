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
#include<string.h>

typedef struct {
    uint32_t MAGIC;
    uint32_t VERSION;
    size_t SIZE;
    size_t USED_SIZE;
    char SEM_NAME[256];
    char SEG_NAME[256];
} sshm_meta_t;

typedef struct {
    char SEG_NAME[256];
    uint8_t KEY[32];
    size_t SIZE;
    size_t USED_SIZE;
} sshm_meta_local_t;

extern struct stat st;

extern sshm_meta_t DEFAULTS;





int sshm_create(const char *name, int oflags, mode_t mode, size_t size);
int sshm_o_exist(const char *name, uint32_t magic);
ssize_t sshm_write(const char *name, uint32_t magic, const void *data, size_t len);
ssize_t sshm_read(const char *name, uint32_t magic, void *buffer, size_t buf_len);
int sshm_delete(const char *name, uint32_t magic);
int sshm_inspect(const char *name, uint32_t magic);

#endif
