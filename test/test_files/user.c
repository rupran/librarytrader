#include <stdlib.h>

extern int second_level_caller(void);

int helper(int c){
    return c/2;
}

int main(){
    int k = second_level_caller();
    if (k == 1)
	exit(helper(k));
    else
	exit(EXIT_FAILURE);
}
