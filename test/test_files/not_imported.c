extern int external(int n);

int reference_to_mock(short c){
    return external(c);
}
