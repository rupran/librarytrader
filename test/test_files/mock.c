#include <stdlib.h>

static int state = 0;

int external(int n){
    return n + 1;
}

void also_external(void){
    state = 1;
}

int external_caller(void){
    return external(state);
}

int second_level_caller(void){
    return external_caller();
}

static void* internal(int n){
    return malloc(n * 200);
}

void* ref_internal(){
    return internal(42);
}
