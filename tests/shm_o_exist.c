#include "sshm.h"


int main(){
    char name[20] = "/test1";
    uint32_t magic = 0xDEADBEEF;
    sshm_o_exist(name,magic);
}
