#ifndef SSHM_SYNC_H
#define SSHM_SYNC_H


#include "sshm_core.h"

#include<semaphore.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdio.h>
#include<sys/stat.h>


int sshm_sem_create(const char *sem_name, int oflags, mode_t mode, unsigned int value);
int sshm_sem_open(const char *sem_name);
int sshm_sem_lock(const char *sem_name);
int sshm_sem_unlock(const char *sem_name);
int sshm_sem_delete(const char *sem_name);

#endif
