#include "../include/sshm_core.h"
#include "../include/sshm_sync.h"

sshm_meta_t DEFAULTS = (sshm_meta_t) {
    .MAGIC = 0xDEADBEEF,
    .VERSION = 1,
    .USED_SIZE = 0
};

struct stat st;

int sshm_create(const char *name, int oflags, mode_t mode, size_t size) {
    size_t meta_size = sizeof(sshm_meta_t);
    int shm_fd;
    const char *seg_name = name+1;

    shm_fd = shm_open(name, oflags, mode);
    if (shm_fd == -1) {
        perror("Failed to create Shared Memory");
        return -1;
        exit(EXIT_FAILURE);
    }
    printf("shm_open: SUCCESS!\n");
    
    size_t tot_size = meta_size + size;
    int shm_size_alloc = ftruncate(shm_fd, tot_size);
    if (shm_size_alloc == -1) {
        perror("Failed to create Shared Memory: Size allocation error!");
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }
    printf("shm_size_alloc: SUCCESS!\n");

    void *shm_map = mmap(NULL, tot_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_map == MAP_FAILED) {
        printf("Failed to create Shared Memory: mmap failed!");
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }
        
    printf("mmap: SUCCESS!\n");

    sshm_meta_t *addr = (sshm_meta_t *) shm_map;
    addr->SIZE = size;
    addr->MAGIC = DEFAULTS.MAGIC;
    addr->VERSION = DEFAULTS.VERSION;
    addr->USED_SIZE = DEFAULTS.USED_SIZE;
    strcpy(addr->SEG_NAME,seg_name);
    snprintf(addr->SEM_NAME, sizeof(addr->SEM_NAME), "sem_sshm_%s", seg_name);


    printf("Shared Memory Created Successfully!\n");


    sshm_sem_create(addr->SEM_NAME, O_CREAT | O_EXCL, mode, 1);

    printf("=== Shared Memory Metadata ===\n");
    printf("Magic   : 0x%X\n", addr->MAGIC);
    printf("Version : %u\n", addr->VERSION);
    printf("Seg_Name: %s\n",addr->SEG_NAME);
    printf("Sem_Name: %s\n",addr->SEM_NAME);
    printf("Size    : %zu bytes\n", addr->SIZE);
    printf("==============================\n");
    
    munmap(shm_map,st.st_size);
    close(shm_fd);
    return shm_fd;
}

int sshm_o_exist(const char *name, uint32_t magic) {
    int shm_fd;

    shm_fd = shm_open(name, O_RDWR,0);
    if (shm_fd == -1){
        perror("Failed to open Shared Memory");
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("shm_open: SUCCESS!\n");

    fstat(shm_fd,&st);
    size_t shm_size = st.st_size;
    
    void  *shm_map = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_map == MAP_FAILED) {
        printf("Failed to open Shared Memory: mmap failed!");
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("mmap: SUCCESS!\n");
    
    sshm_meta_t *addr = (sshm_meta_t *) shm_map;

    if ( addr->MAGIC != magic) {
        printf("Failed to open Shared Memory: Magic Mismatch!");
        munmap(shm_map,st.st_size);
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("Shared Memory Opened Successfully!\n");
    
    sshm_sem_open(addr->SEM_NAME);

    printf("=== Shared Memory Metadata ===\n");
    printf("Magic   : 0x%X\n", addr->MAGIC);
    printf("Version : %u\n", addr->VERSION);
    printf("Seg_Name: %s\n",addr->SEG_NAME);
    printf("Sem_Name: %s\n",addr->SEM_NAME);
    printf("Size    : %zu bytes\n", addr->SIZE);
    printf("Used    : %zu bytes\n", addr->USED_SIZE);
    printf("==============================\n");
    
    munmap(shm_map,st.st_size);
    close(shm_fd);

    return shm_fd;
}

ssize_t sshm_write(const char *name, uint32_t magic, const void *data, size_t len) {

    int shm_fd;
    
    shm_fd = shm_open(name, O_RDWR,0);
    if (shm_fd == -1){
        perror("Failed to open Shared Memory");
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("shm_open: SUCCESS!\n");

    fstat(shm_fd,&st);
    size_t shm_size = st.st_size;
    
    void  *shm_map = mmap(NULL, shm_size, PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_map == MAP_FAILED) {
        printf("Failed to open Shared Memory: mmap failed!");
        close(shm_fd); 
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("mmap: SUCCESS!\n");
    
    sshm_meta_t *addr = (sshm_meta_t *) shm_map;

    if ( addr->MAGIC != magic) {
        printf("Failed to open Shared Memory: Magic Mismatch!");
        munmap(shm_map,st.st_size);
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("Shared Memory Opened Successfully!\n");

    sshm_sem_lock(addr->SEM_NAME);
 
    size_t remaining = addr->SIZE - addr->USED_SIZE;

    if ( remaining < len ) {
        printf("Writing Failed: Not enough space in the Shared Memory Segment.");
        munmap(shm_map,st.st_size);
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }

    void *u_space = (char *)addr + sizeof(sshm_meta_t);
    
    memcpy(u_space+addr->USED_SIZE, data, len);
    addr->USED_SIZE += len;

    printf("Data written into the Memory Segment Successfully!\n");

    sshm_sem_unlock(addr->SEM_NAME);
    
    munmap(shm_map,st.st_size);
    close(shm_fd);

    return len;
}


ssize_t sshm_read(const char* name, uint32_t magic, void *buffer, size_t buf_len) {

    int shm_fd;
    
    shm_fd = shm_open(name, O_RDONLY,0);
    if (shm_fd == -1){
        perror("Failed to open Shared Memory");
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("shm_open: SUCCESS!\n");

    fstat(shm_fd,&st);
    size_t shm_size = st.st_size;
    
    void  *shm_map = mmap(NULL, shm_size, PROT_READ, MAP_SHARED, shm_fd, 0);
    if (shm_map == MAP_FAILED) {
        printf("Failed to open Shared Memory: mmap failed!");
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("mmap: SUCCESS!\n");
    
    sshm_meta_t *addr = (sshm_meta_t *) shm_map;

    if ( addr->MAGIC != magic) {
        printf("Failed to open Shared Memory: Magic Mismatch!");
        munmap(shm_map,st.st_size);
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("Shared Memory Opened Successfully!\n");

    sshm_sem_lock(addr->SEM_NAME);

    void *u_space = (char *) addr + sizeof(sshm_meta_t);

    size_t copy_size = addr->USED_SIZE;

    if (copy_size > buf_len) {
        printf("Read Failed: Buffer too small to hold Shared Memory data.");
        munmap(shm_map,st.st_size);
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }

    memcpy(buffer, u_space, copy_size);

    fprintf(stdout, buffer, copy_size);

    printf("\nREAD SUCCESSFULL!");

    sshm_sem_unlock(addr->SEM_NAME);

    munmap(shm_map,st.st_size);
    close(shm_fd);

    return copy_size;
}

int sshm_delete(const char *name, uint32_t magic) {

    int shm_fd;
    
    shm_fd = shm_open(name, O_RDONLY,0);
    if (shm_fd == -1){
        perror("Failed to Delete Shared Memory");
        return -1;
        exit(EXIT_FAILURE);
    }
    
    fstat(shm_fd,&st);
    size_t shm_size = st.st_size;
    
    void  *shm_map = mmap(NULL, shm_size, PROT_READ, MAP_SHARED, shm_fd, 0);
    if (shm_map == MAP_FAILED) {
        printf("Failed to Delete Shared Memory");
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }
    
    sshm_meta_t *addr = (sshm_meta_t *) shm_map;

    if ( addr->MAGIC != magic) {
        printf("Failed to Delete Shared Memory: Magic Mismatch!");
        munmap(shm_map, st.st_size);
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }

    sshm_sem_delete(addr->SEM_NAME);
    
    int del = shm_unlink(name);
    if ( del == -1) {
    perror("Failed to delete shared memory");
    munmap(shm_map, st.st_size);
    close(shm_fd);
    return -1;
    exit(EXIT_FAILURE);
    }
    
    munmap(shm_map,st.st_size);
    close(shm_fd);
    
    printf("Delete SUCCESSFULL\n");

    return 0;
}

int sshm_inspect(const char *name, uint32_t magic) {
    int shm_fd;

    shm_fd = shm_open(name, O_RDWR,0);
    if (shm_fd == -1){
        perror("Failed to open Shared Memory");
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("shm_open: SUCCESS!\n");

    fstat(shm_fd,&st);
    size_t shm_size = st.st_size;
    
    void  *shm_map = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_map == MAP_FAILED) {
        printf("Failed to open Shared Memory: mmap failed!");
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }

    printf("mmap: SUCCESS!\n");
    
    sshm_meta_t *addr = (sshm_meta_t *) shm_map;

    if ( addr->MAGIC != magic) {
        printf("Failed to open Shared Memory: Magic Mismatch!");
        munmap(shm_map,st.st_size);
        close(shm_fd);
        return -1;
        exit(EXIT_FAILURE);
    }


    printf("Shared Memory Opened Successfully!\n");
    

    printf("=== Shared Memory Metadata ===\n");
    printf("Magic   : 0x%X\n", addr->MAGIC);
    printf("Version : %u\n", addr->VERSION);
    printf("Seg_Name: %s\n",addr->SEG_NAME);
    printf("Sem_Name: %s\n",addr->SEM_NAME);
    printf("Size    : %zu bytes\n", addr->SIZE);
    printf("Used    : %zu bytes\n", addr->USED_SIZE);
    printf("==============================\n");
    
    munmap(shm_map,st.st_size);
    close(shm_fd);

    return 0;
}
