CC=gcc
SHARED_FLAGS=-shared -fPIC -O3 -m64
CFLAGS=$(SHARED_FLAGS) -Wl,-Bsymbolic-functions
RPATH_DIR=rpath_dir
RPATH_SUBDIR=$(RPATH_DIR)/rpath_subdir
LOADERDIR=loaderlike
TARGETS=user libmock.so libmock_plt.so librpath_one.so \
	$(RPATH_DIR)/librpath_two.so $(RPATH_SUBDIR)/librpath_three.so \
	$(RPATH_SUBDIR)/librunpath.so $(RPATH_DIR)/libldd_search.so \
	libnoldconfig.so libnot_imported.so structs/structs structs/libstructs.so \
	structs/structs32 structs/libstructs32.so \
	$(addprefix $(LOADERDIR)/, bin bin1a bin2 lib1a.so lib1.so lib2.so lib3.so)

.PHONY: all clean

all: $(TARGETS)
	chmod -x $(filter %.so,$(TARGETS))

user: user.c libmock.so
	$(CC) -L. -o $@ $< -lmock

# This is intentionally not included in TARGETS as Travis CI does not build
# PIE executables with the PIE bit in DT_FLAGS_1 which is needed for our
# test case. For now, the binary comes with the checkout.
user_pie: user.c libmock.so
	$(CC) -L. -pie -fPIC -Wl,-E -o $@ $< -lmock

libmock.so: mock.c
	$(CC) $(CFLAGS) -o $@ $^

libmock_plt.so: mock.c
	$(CC) $(SHARED_FLAGS) -o $@ $<

librpath_one.so: rpath_one.c $(RPATH_DIR)/librpath_two.so
	$(CC) $(CFLAGS) -Wl,-rpath='$$ORIGIN/$(RPATH_DIR):$$ORIGIN/$(RPATH_SUBDIR)' \
		-Wl,--disable-new-dtags -o $@ $< -L$(RPATH_DIR) -lrpath_two

$(RPATH_DIR)/librpath_two.so: $(RPATH_DIR)/rpath_two.c $(RPATH_SUBDIR)/librpath_three.so
	$(CC) $(CFLAGS) -o $@ $< -L$(RPATH_SUBDIR) -lrpath_three

$(RPATH_SUBDIR)/librpath_three.so: $(RPATH_SUBDIR)/rpath_three.c \
	$(RPATH_SUBDIR)/librunpath.so libmock.so
	$(CC) $(CFLAGS) -Wl,-rpath='$$ORIGIN',--enable-new-dtags -o $@ $< \
		-L$(RPATH_SUBDIR) -lrunpath -L. -lmock

$(RPATH_SUBDIR)/librunpath.so: $(RPATH_SUBDIR)/runpath.c
	$(CC) $(CFLAGS) -o $@ $<

$(RPATH_DIR)/libldd_search.so: $(RPATH_DIR)/ldd_search.c libnoldconfig.so
	$(CC) $(CFLAGS) -o $@ $< -L. -lnoldconfig

libnoldconfig.so: noldconfig.c
	$(CC) $(CFLAGS) -o $@ $<

libnot_imported.so: not_imported.c libmock.so
	$(CC) $(CFLAGS) -o $@ $< -L. -lmock

structs/libstructs.so: structs/libstructs.c
	$(CC) $(CFLAGS) -o $@ $<

structs/structs: structs/structs.c structs/libstructs.so
	$(CC) $(CFLAGS) -Wl,-rpath='$$ORIGIN',--enable-new-dtags -Lstructs -o $@ $< -lstructs

structs/libstructs32.so: structs/libstructs.c
	$(CC) $(CFLAGS:64=32) -o $@ $<

structs/structs32: structs/structs.c structs/libstructs32.so
	$(CC) $(CFLAGS:64=32) -Wl,-rpath='$$ORIGIN',--enable-new-dtags -Lstructs -o $@ $< -lstructs32

$(LOADERDIR)/lib3.so: $(LOADERDIR)/lib3.c
	$(CC) $(CFLAGS) -o $@ $<

$(LOADERDIR)/lib2.so: $(LOADERDIR)/lib2.c $(LOADERDIR)/lib3.so
	$(CC) $(CFLAGS) -o $@ $< -L$(LOADERDIR) -l3

$(LOADERDIR)/lib1.so: $(LOADERDIR)/lib1.c $(LOADERDIR)/lib2.so
	$(CC) $(CFLAGS) -o $@ $< -L$(LOADERDIR) -l2

$(LOADERDIR)/bin: $(LOADERDIR)/bin.c $(LOADERDIR)/lib1.so
	$(CC) $(CFLAGS) -o $@ $< -L$(LOADERDIR) -l1

$(LOADERDIR)/bin2: $(LOADERDIR)/bin2.c $(LOADERDIR)/lib1.so
	$(CC) $(CFLAGS) -o $@ $< -L$(LOADERDIR) -l1

$(LOADERDIR)/lib1a.so: $(LOADERDIR)/lib1a.c $(LOADERDIR)/lib2.so
	$(CC) $(CFLAGS) -o $@ $< -L$(LOADERDIR) -l2

$(LOADERDIR)/bin1a: $(LOADERDIR)/bin1a.c $(LOADERDIR)/lib1a.so
	$(CC) $(CFLAGS) -o $@ $< -L$(LOADERDIR) -l1a

clean:
	rm -f $(TARGETS)
