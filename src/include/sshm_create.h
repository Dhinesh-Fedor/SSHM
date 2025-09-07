#ifndef SSHM_CREATE_H
#define SSHM_CREATE_H

#include<unistd.h>
#include<fcntl.h>
#include<sys/mman.h>
#include<sys/types.h>


int sshm_create(const char *name, int oflags, mode_t mode);

#endif
