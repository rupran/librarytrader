#include <stdlib.h>

static int state = 0;
static void *internal (int n) __attribute__((noinline));

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

int recursive(unsigned int start);

int recursive_helper(unsigned int c) {
    unsigned int local = external(c);
    return recursive(local/2);
}

int recursive(unsigned int start){
    if (start == 0) {
	return external(start);
    } else {
	return recursive_helper(start);
    }
}
