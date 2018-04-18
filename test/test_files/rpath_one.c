extern int exported_two(int par);

int exported(int par) {
    return par + 42;
}

int rpath_user(int par){
   int local = exported(par);
   local += exported_two(par);
   return local;
}
