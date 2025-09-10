#ifndef SSHM_CORE_H
#define SSHM_CORE_H

#include<stdint.h>
#include<stddef.h>
#include<sys/types.h>
#include<fcntl.h>

typedef struct {
    uint32_t MAGIC;
    uint32_t VERSION;
    size_t SIZE;
} sshm_meta_t;




int sshm_create(const char *name, int oflags, mode_t mode, size_t size);

#endif
