#include "sshm.h"

int main(){
    char name[20] = "/test";
    sshm_create(name, O_CREAT | O_EXCL | O_RDWR, 0600);
}
