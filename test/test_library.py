import os
import unittest

from librarytrader.library import Library
from librarytrader.librarystore import LibraryStore

FILE_PATH = 'test/test_files/'
LDCONFIG_FILE = FILE_PATH + 'ldconfig_out'
TEST_LIBRARY  = FILE_PATH + 'mock.so'

def create_store_and_lib():
    store = LibraryStore(ldconfig_file=LDCONFIG_FILE)
    lib = Library(os.path.abspath(TEST_LIBRARY))
    return store, lib


class TestLibrary(unittest.TestCase):

    def test_resolve_libs_single(self):
        store, lib = create_store_and_lib()

        store.resolve_libs_single(lib)

        # We need one lib, libc.so.6, linking to libc-2.23.so
        self.assertEqual(len(lib.needed_libs), 1)

        import_name, path = list(lib.needed_libs.items())[0]
        self.assertEqual(import_name, 'libc.so.6')
        self.assertEqual(path, os.path.abspath(FILE_PATH + 'libc-2.23.so'))

        # No recursion, only parameters are in store
        self.assertEqual(len(store), 1)

    def test_resolve_libs_recursive(self):
        store, lib = create_store_and_lib()

        store.resolve_libs_recursive(lib)

        # We need one lib, libc.so.6, linking to libc-2.23.so
        self.assertEqual(len(lib.needed_libs), 1)

        self.assertEqual(len(store), 5)
        # Stored items are:
        # mock.so
        # libc.so.6 -> libc-2.23.so
        # libc-2.23.so
        # ld-linux-x86-64.so.2 -> ld-2.23.so
        # ld-2.23.so
        self.assertEqual(len(list(key for (key, val) in store.items()
                                  if isinstance(val, str))), 2)
        # ... two of them are links

        # Check if resolving functions works
        resol = store.resolve_functions(lib)
        self.assertEqual(len(resol), 2)
        self.assertTrue('fputs' in resol)
        # the other one is __cxa_finalize, imported as a weak symbol from libc

if __name__ == '__main__':
    unittest.main()
