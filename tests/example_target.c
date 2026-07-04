#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>

int var1 = 0;


int sleep_func(){
    int var0 = 0;
    int var2 = 9;
    printf("Sleeping: %d\n", var1);
    var1 = var1 + 1;
    sleep(3);

    return 0;
}


int main(){

    void* libHandle;
    int ret;

    while(1){
        ret = sleep_func();
        printf("Ret value: %d\n", ret);
        sleep(1);
    }

    return 0;
}
