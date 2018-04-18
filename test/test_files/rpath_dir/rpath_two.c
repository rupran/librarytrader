extern int lowest(int par);

int exported_two(int par){
    return lowest(par) - 4711;
}
