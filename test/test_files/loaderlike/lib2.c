extern void deeper();

void one_more(){
	deeper();
}

static void local_func(){
	one_more();
}

void func(){
	local_func();
}

__attribute__((weak)) void wfunc(){
	local_func();
}
