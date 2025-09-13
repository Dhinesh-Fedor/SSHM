#include "../include/sshm_core.h"



int sshm_create(const char *name, int oflags, mode_t mode, size_t size) {
    int shm_fd;
    size_t meta_size = sizeof(sshm_meta_t);

    shm_fd = shm_open(name, oflags, mode);
    if (shm_fd == -1) {
        perror("Failed to create Shared Memory");
        exit(EXIT_FAILURE);
    }
    printf("shm_open: SUCCESS!\n");
    
    size_t tot_size = meta_size + size;
    int shm_size_alloc = ftruncate(shm_fd, tot_size);
    if (shm_size_alloc == -1) {
        perror("Failed to create Shared Memory: Size allocation error!");
        exit(EXIT_FAILURE);
    }
    printf("shm_size_alloc: SUCCESS!\n");

    void *shm_map = mmap(NULL, tot_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_map == MAP_FAILED) {
        printf("Failed to create Shared Memory: mmap failed!");
        exit(EXIT_FAILURE);
    }
        
    printf("mmap: SUCCESS!\n");

    sshm_meta_t *addr = (sshm_meta_t *) shm_map;
    addr->SIZE = size;

    printf("Shared Memory Created Successfully!\n");
    

    printf("=== Shared Memory Metadata ===\n");
    printf("Magic   : 0x%X\n", addr->MAGIC);
    printf("Version : %u\n", addr->VERSION);
    printf("Size    : %zu bytes\n", addr->SIZE);
    printf("==============================\n");

    

    return 0;

}

int sshm_o_exist(const char *name, uint32_t magic) {
    int shm_fd;

    shm_fd = shm_open(name, O_RDWR,0);
    if (shm_fd == -1){
        perror("Failed to open Shared Memory");
        exit(EXIT_FAILURE);
    }

    printf("shm_open: SUCCESS!\n");

    fstat(shm_fd,&st);
    size_t shm_size = st.st_size;
    
    void  *shm_map = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_map == MAP_FAILED) {
        printf("Failed to open Shared Memory: mmap failed!");
        exit(EXIT_FAILURE);
    }

    printf("mmap: SUCCESS!\n");
    
    sshm_meta_t *addr = (sshm_meta_t *) shm_map;

    if ( addr->MAGIC != magic) {
        printf("Failed to open Shared Memory: Magic Mismatch!");
        exit(EXIT_FAILURE);
    }

    printf("Shared Memory Opened Successfully!\n");
    

    printf("=== Shared Memory Metadata ===\n");
    printf("Magic   : 0x%X\n", addr->MAGIC);
    printf("Version : %u\n", addr->VERSION);
    printf("Size    : %zu bytes\n", addr->SIZE);
    printf("==============================\n");

    

    return 0;
   




}
