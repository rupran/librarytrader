extern void f1();

/* This is overridden by the strong definition in lib2.c */
__attribute__((weak)) void one_more(){
	return;
}

int main(){
	f1();
}
