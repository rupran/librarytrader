#include <stdio.h>

static int state = 0;

int external(int n){
    return n + 1;
}

void also_external(void){
    state = 1;
}

static int internal(char *bar){
    return fputs("mock", stdin);
}
