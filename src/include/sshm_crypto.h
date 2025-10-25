#ifndef SSHM_CRYPTO_H
#define SSHM_CRYPTO_H


#include<sodium.h>
#include<stdlib.h>
#include<unistd.h>

int sshm_sodium_init();
int sshm_key_generate();
int sshm_encrypt();
int sshm_decrypt();



#endif

