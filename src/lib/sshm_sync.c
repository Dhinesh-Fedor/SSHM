#include "../include/sshm_sync.h"

int sshm_sem_create(const char *sem_name, int oflags, mode_t mode, unsigned int value){

    sem_t *sshm_sem = sem_open(sem_name, oflags, mode, value);

    if (sshm_sem == SEM_FAILED) {
        perror("Failed to create semaphore");
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("sshm_sem initialized!\n");


    return 1;
}

int sshm_sem_open(const char *sem_name) {

    sem_t *sshm_sem = sem_open(sem_name, 0);

    if (sshm_sem == SEM_FAILED) {
        perror("Failed to create semaphore");
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("sshm_sem opened!\n");

    sem_close(sshm_sem);

    return 1;
}

int sshm_sem_lock(const char *sem_name){

    sem_t *sshm_sem = sem_open(sem_name, 0);

    if (sshm_sem == SEM_FAILED) { 
        perror("sem_open"); 
        return -1;
        exit(EXIT_FAILURE);
    }

    sem_wait(sshm_sem);

    sem_close(sshm_sem);

    return 1;
}

int sshm_sem_unlock(const char *sem_name){

    sem_t *sshm_sem = sem_open(sem_name, 0);
    
    if (sshm_sem == SEM_FAILED) { 
        perror("sem_open");
        return -1; }
    
    sem_post(sshm_sem);
    
    sem_close(sshm_sem);

    return 1;
}

int sshm_sem_delete(const char *sem_name){

    sem_unlink(sem_name);
    
    printf("semaphore deleted.\n");

    return 1;
}
