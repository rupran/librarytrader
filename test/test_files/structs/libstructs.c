int helper(void){
	return 42;
}

int from_obj(void){
	return 1337;
}

struct fptr {
	int (*fptr)(void);
} fptr_struct = { &helper };


static struct objptr {
	struct fptr *fptr;
	int (*ptr)(void);
} objptr_struct = { &fptr_struct, &from_obj };

struct objptr *x = &objptr_struct;

int interface(void){
	return x->fptr->fptr();
}
