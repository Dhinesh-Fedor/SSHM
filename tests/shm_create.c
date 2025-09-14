#include "sshm.h"


int main(){
    char name[20] = "/test1";
    sshm_create(name, O_CREAT | O_EXCL | O_RDWR, 0600, 2048);
}
