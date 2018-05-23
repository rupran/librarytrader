import logging
import os
import tempfile
import unittest

from librarytrader.library import Library
from librarytrader.librarystore import LibraryStore
from librarytrader.interface_calls import disassemble_capstone, \
    disassemble_objdump, resolve_calls, resolve_calls_in_library

FILE_PATH = 'test/test_files/'
RPATH_DIR = FILE_PATH + 'rpath_dir/'
RPATH_SUB = RPATH_DIR + 'rpath_subdir/'
LDLIB_DIR = FILE_PATH + 'ld_library_dir/'
LDCONFIG_FILE = FILE_PATH + 'ldconfig_out'
TEST_LIBRARY  = FILE_PATH + 'libmock.so'
TEST_LIB_PLT  = FILE_PATH + 'libmock_plt.so'
TEST_BINARY   = FILE_PATH + 'user'
TEST_BIN_PIE  = FILE_PATH + 'user_pie'
TEST_LIBC     = FILE_PATH + 'libc-2.23.so'
TEST_LIBC_LNK = FILE_PATH + 'libc.so.6'
TEST_RPATH    = FILE_PATH + 'librpath_one.so'
TEST_RPATH_2  = RPATH_DIR + 'librpath_two.so'
TEST_RPATH_3  = RPATH_SUB + 'librpath_three.so'
TEST_RUNPATH  = RPATH_SUB + 'librunpath.so'
TEST_LD_PATHS = RPATH_DIR + 'libldd_search.so'
TEST_NOLDCONF = FILE_PATH + 'libnoldconfig.so'
TEST_LDLIBC   = LDLIB_DIR + 'libc-2.23.so'
TEST_EXECONLY = FILE_PATH + 'libnot_imported.so'

def create_store_and_lib(libpath=TEST_LIBRARY, parse=False,
                         resolve_libs_recursive=False, call_resolve=False):
    store = LibraryStore(ldconfig_file=LDCONFIG_FILE)
    lib = Library(os.path.abspath(libpath), parse=parse)
    if resolve_libs_recursive:
        store.resolve_libs_recursive(lib)
    if call_resolve:
        resolve_calls(store)
    return store, lib

class TestLibrary(unittest.TestCase):

    def test_0_abspath_required(self):
        # We need absolute paths to construct libraries, so check that
        # relative paths fail
        self.assertRaises(ValueError, Library, TEST_LIBRARY)

    def test_0_drop_pie_exports(self):
        user_pie = Library(os.path.abspath(TEST_BIN_PIE))
        # Parsing .symtab should identify exports
        user_pie.parse_symtab()
        self.assertNotEqual(len(user_pie.exports.keys()), 0)

        # After parsing .dynamic the exports should be dropped
        user_pie.parse_dynamic()
        self.assertEquals(len(user_pie.exports.keys()), 0)

    def test_0_fail_on_elferror(self):
        store = LibraryStore(ldconfig_file=LDCONFIG_FILE)
        # Makefile isn't an ELF file, so we fail in store._get_or_create_library
        store.resolve_libs_single_by_path(os.path.abspath(FILE_PATH + 'Makefile'))
        self.assertEquals(len(store.items()), 0)

    def test_0_resolve_libs_single(self):
        store, lib = create_store_and_lib()

        store.resolve_libs_single(lib)

        # We need one lib, libc.so.6, linking to libc-2.23.so
        self.assertEqual(len(lib.needed_libs), 1)

        import_name, path = list(lib.needed_libs.items())[0]
        self.assertEqual(import_name, 'libc.so.6')
        self.assertEqual(path, os.path.abspath(FILE_PATH + 'libc-2.23.so'))

        # No recursion, only parameters are in store
        self.assertEqual(len(store), 1)

    def test_0_resolve_libs_single_by_path(self):
        store, _ = create_store_and_lib()

        store.resolve_libs_single_by_path(os.path.abspath(TEST_LIBRARY))
        lib = store[os.path.abspath(TEST_LIBRARY)]

        # We need one lib, libc.so.6, linking to libc-2.23.so
        self.assertEqual(len(lib.needed_libs), 1)

        import_name, path = list(lib.needed_libs.items())[0]
        self.assertEqual(import_name, 'libc.so.6')
        self.assertEqual(path, os.path.abspath(FILE_PATH + 'libc-2.23.so'))

        # No recursion, only parameters are in store
        self.assertEqual(len(store), 1)

    def test_0_resolve_libs_with_symlinks(self):
        store = LibraryStore(ldconfig_file=LDCONFIG_FILE)

        store.resolve_libs_single_by_path(os.path.abspath(TEST_LIBC_LNK))

        # libc.so.6 -> libc-2.23.so and libc-2.23.so
        self.assertEquals(len(store.items()), 2)
        self.assertEquals(store.get_from_path(os.path.abspath(TEST_LIBC_LNK)),
                          store[os.path.abspath(TEST_LIBC)])

    def test_1_resolve_libs_recursive(self):
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

    def test_1_resolve_libs_recursive_by_path(self):
        store, _ = create_store_and_lib()

        store.resolve_libs_recursive_by_path(os.path.abspath(TEST_LIBRARY))
        lib = store[os.path.abspath(TEST_LIBRARY)]

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

    def test_2_resolution_with_rpaths_and_runpaths(self):
        store, one = create_store_and_lib(TEST_RPATH, parse=True,
                                          resolve_libs_recursive=True)

        # librpath_one.so has RPATH for rpath_dir/ and rpath_dir/rpath_subdir
        # and needs librpath_two.so -> local rpath discovery
        # rpath_dir/librpath_two.so has _no_ RPATH but needs librpath_three.so
        # which is at rpath_dir/rpath_subdir -> inherited discovery
        # rpath_dir/rpath_subdir/librpath_three.so has RUNPATH '.' and needs
        # librunpath.so -> runpath discovery
        self.assertEquals(os.path.abspath(TEST_RPATH_2),
                          one.needed_libs['librpath_two.so'])

        two = store[os.path.abspath(TEST_RPATH_2)]
        self.assertEquals(os.path.abspath(TEST_RPATH_3),
                          two.needed_libs['librpath_three.so'])

        three = store[os.path.abspath(TEST_RPATH_3)]
        self.assertEquals(os.path.abspath(TEST_RUNPATH),
                          three.needed_libs['librunpath.so'])

    def test_2_resolution_with_fs_search(self):
        store, search = create_store_and_lib(TEST_LD_PATHS,
                                             resolve_libs_recursive=True)

        # TEST_NOLDCONF is at a location which is a basepath in LDCONFIG_FILE
        # but not mentioned directly. search also has no RPATH or RUNPATH set
        # so our resolution has to do a file system search.

        # Make sure we found the library
        self.assertEquals(os.path.abspath(TEST_NOLDCONF),
                          search.needed_libs['libnoldconfig.so'])

    def test_2_resolution_with_ld_library_path(self):
        # Save possibly set LD_LIBRARY_PATH
        backup = None
        if 'LD_LIBRARY_PATH' in os.environ:
            backup = os.environ['LD_LIBRARY_PATH']

        # Set LD_LIBRARY_PATH and resolve libraries
        os.environ['LD_LIBRARY_PATH'] = '$ORIGIN/ld_library_dir'
        store, lib = create_store_and_lib(resolve_libs_recursive=True)

        # Possibly restore LD_LIBRARY_PATH
        if backup:
            os.environ['LD_LIBRARY_PATH'] = backup
        else:
            del os.environ['LD_LIBRARY_PATH']

        # Assert we found the library in the LD_LIBRARY_PATH instead of the
        # one from the ldconfig file.
        self.assertEquals(os.path.abspath(TEST_LDLIBC),
                          lib.needed_libs['libc.so.6'])

    def test_3_resolve_imports_to_library(self):
        store, lib = create_store_and_lib(resolve_libs_recursive=True)

        # Check if resolving functions works
        store.resolve_functions(lib)
        self.assertEqual(len([func for (func, path) in lib.imports.items()
                              if path]), 2)
        self.assertIsNotNone(lib.imports['malloc'])
        # the other one is __cxa_finalize, imported as a weak symbol from libc

    def test_3_resolve_imports_to_library_by_path(self):
        store, lib = create_store_and_lib(resolve_libs_recursive=True)

        # Check if resolving functions by name works
        store.resolve_functions(lib.fullname)
        self.assertEqual(len([func for (func, path) in lib.imports.items()
                              if path]), 2)
        self.assertIsNotNone(lib.imports['malloc'])
        # the other one is __cxa_finalize, imported as a weak symbol from libc

    call_result = {'external_caller': set(['external']),
                   'second_level_caller': set(['external_caller']),
                   'recursive': set(['recursive_helper', 'external']),
                   'recursive_helper': set(['recursive', 'external'])
                   }

    def test_4_resolve_calls_by_capstone(self):
        store, lib = create_store_and_lib()
        lib.parse_functions()

        calls, _ = resolve_calls_in_library(lib, disassemble_capstone)

        self.assertEqual(len(calls), 4)
        self.assertDictEqual(calls, self.call_result)

    def test_4_resolve_calls_by_objdump(self):
        store, lib = create_store_and_lib()
        lib.parse_functions()

        calls, _ = resolve_calls_in_library(lib, disassemble_objdump)

        self.assertEqual(len(calls), 4)
        self.assertDictEqual(calls, self.call_result)

    def test_4_resolve_calls_by_capstone_plt(self):
        store, lib = create_store_and_lib(TEST_LIB_PLT)
        lib.parse_functions()

        calls, _ = resolve_calls_in_library(lib, disassemble_capstone)

        # The results should match the variant with symbolic functions
        self.assertEquals(len(calls), 4)
        self.assertDictEqual(calls, self.call_result)

    def test_4_resolve_calls_by_objdump_plt(self):
        store, lib = create_store_and_lib(TEST_LIB_PLT)
        lib.parse_functions()

        calls, _ = resolve_calls_in_library(lib, disassemble_objdump)

        # The results should match the variant with symbolic functions
        self.assertEquals(len(calls), 4)
        self.assertDictEqual(calls, self.call_result)

    def test_4_resolve_calls_integrated(self):
        store, lib = create_store_and_lib(resolve_libs_recursive=True)

        result = resolve_calls(store)
        # calls for mock.so, libc-2.23.so and ld-2.23.so
        self.assertEqual(len(result), 3)
        self.assertDictEqual(dict(store[lib.fullname].calls), self.call_result)

    def test_5_transitive_calls(self):
        store, lib = create_store_and_lib(resolve_libs_recursive=True,
                                          call_resolve=True)

        result = store.get_transitive_calls(lib, 'second_level_caller')
        # Check that transitive callees are returned
        self.assertSetEqual(result, set(['external_caller', 'external']))

        # Check that functions calling themselves recursively work and cover
        # the use of the cache (external is called from recursive and its
        # recursive_helper function)
        result = store.get_transitive_calls(lib, 'recursive')
        self.assertSetEqual(result, set(['external', 'recursive_helper', 'recursive']))

    def test_6_propagate_calls_all_entries(self):
        store, binary = create_store_and_lib(TEST_BINARY,
                                             resolve_libs_recursive=True,
                                             call_resolve=True)
        lib = Library(os.path.abspath(TEST_LIBRARY))
        not_imported = Library(os.path.abspath(TEST_EXECONLY))
        store.resolve_libs_recursive(not_imported)

        store.resolve_all_functions(all_entries=True)
        store.propagate_call_usage(all_entries=True)
        # Check if all transitively called functions have the binary as their user
        self.assertIn(binary.fullname, store[lib.fullname].exports['external'])
        self.assertIn(binary.fullname, store[lib.fullname].exports['external_caller'])
        self.assertIn(binary.fullname, store[lib.fullname].exports['second_level_caller'])
        # If we use all libraries in the store as entry points for the
        # resolution, TEST_EXECONLY should show up as a user of 'external' in
        # TEST_LIBRARY
        self.assertIn(not_imported.fullname, store[lib.fullname].exports['external'])

    def test_6_propagate_calls_exec_only(self):
        store, binary = create_store_and_lib(TEST_BINARY,
                                             resolve_libs_recursive=True,
                                             call_resolve=True)
        lib = Library(os.path.abspath(TEST_LIBRARY))
        not_imported = Library(os.path.abspath(TEST_EXECONLY))
        store.resolve_libs_recursive(not_imported)

        store.resolve_all_functions(all_entries=False)
        store.propagate_call_usage(all_entries=False)
        # Check if all transitively called functions have the binary as their user
        self.assertIn(binary.fullname, store[lib.fullname].exports['external'])
        self.assertIn(binary.fullname, store[lib.fullname].exports['external_caller'])
        self.assertIn(binary.fullname, store[lib.fullname].exports['second_level_caller'])
        # In this case, the library not imported from TEST_BINARY should not
        # show up as a user of TEST_LIBRARY
        self.assertNotIn(not_imported.fullname, store[lib.fullname].exports['external'])


    def test_7_store_load(self):
        store, binary = create_store_and_lib(TEST_BINARY,
                                             resolve_libs_recursive=True,
                                             call_resolve=True)
        lib = Library(os.path.abspath(TEST_LIBRARY))

        resolved_functions = store.resolve_all_functions(all_entries=True)
        store.propagate_call_usage(all_entries=True)

        # Create a temporary file, close it (we only need the path) and dump
        fd, name = tempfile.mkstemp()
        os.close(fd)
        store.dump(name)

        # Reload into an empty store
        new_store = LibraryStore(ldconfig_file=LDCONFIG_FILE)
        new_store.load(name)

        # The file is no longer needed, delete it
        os.remove(name)

        # Assert restoration of store
        self.assertEqual(store.keys(), new_store.keys())
        self.assertIn(lib.fullname, new_store.keys())
        self.assertIn(binary.fullname, new_store.keys())

        # Assert restoration of needed_libs
        self.assertIn(lib.fullname,
                      new_store[binary.fullname].needed_libs.values())

        # Assert restoration of calls
        self.assertIn(binary.fullname,
                      new_store[lib.fullname].exports['external'])
        self.assertIn(binary.fullname,
                      new_store[lib.fullname].exports['external_caller'])
        self.assertIn(binary.fullname,
                      new_store[lib.fullname].exports['second_level_caller'])

if __name__ == '__main__':
    unittest.main()
