#include <stdio.h>

void from_init(void){
	puts("called from init");
}

__attribute__((constructor)) void func_init(void) {
	from_init();
}

void from_fini(void){
	puts("called from fini");
}

__attribute__((destructor)) void func_fini(void) {
	from_fini();
}

void func_normal(){
	puts("normal function");
}
