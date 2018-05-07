CC=gcc
SHARED_FLAGS=-shared -fPIC -O3
CFLAGS=$(SHARED_FLAGS) -Wl,-Bsymbolic-functions
RPATH_DIR=rpath_dir
RPATH_SUBDIR=$(RPATH_DIR)/rpath_subdir
TARGETS=user libmock.so libmock_plt.so librpath_one.so \
	$(RPATH_DIR)/librpath_two.so $(RPATH_SUBDIR)/librpath_three.so \
	$(RPATH_SUBDIR)/librunpath.so $(RPATH_DIR)/libldd_search.so \
	libnoldconfig.so libnot_imported.so

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
	strip -s $@

libmock_plt.so: mock.c
	$(CC) $(SHARED_FLAGS) -o $@ $<
	strip -s $@

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

clean:
	rm -f $(TARGETS)
