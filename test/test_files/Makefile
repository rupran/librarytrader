CC=gcc
CFLAGS=-shared -fPIC

mock.so: mock.c
	$(CC) $(CFLAGS) -o $@ $^
	strip -s $@
