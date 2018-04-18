extern int not_in_ldconfig(int n);

int where_is_it(int par){
    return not_in_ldconfig(par) + 2018;
}
