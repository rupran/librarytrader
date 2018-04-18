extern int with_runpath(int par);

int lowest(int par){
    int local = with_runpath(par);
    return local * 2;
}
