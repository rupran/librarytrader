#!/usr/bin/env python3

import collections
import os
import sys

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from data.container import LDResolve, LibraryArchive


class Library:

    def __init__(self, filename):
        if not os.path.isabs(filename):
            raise ValueError("{} is no absolute path".format(filename))

        self.fullname = filename

        self.fd = open(filename, 'rb')
        self.elffile = ELFFile(self.fd)
        self.elfheader = self.elffile.header

        self.exported_functions = None
        self.undefs = None

        self.needed_libs = None
        self.rpaths = None

    def parse_symtab(self):
        exports = collections.OrderedDict()
        undefs = collections.OrderedDict()

        for section in self.elffile.iter_sections():
            if isinstance(section, SymbolTableSection):
                for _, symbol in enumerate(section.iter_symbols()):
                    shndx = symbol['st_shndx']
                    symbol_type = symbol['st_info']['type']
                    if symbol_type != 'STT_FUNC':
                        # TODO: check for use of LOOS/IFUNC wrt libc symbols
                        # like memcpy... consider adding the following to the
                        # if check:
                        # and symbol_type != 'STT_LOOS':
                        continue

                    if shndx == 'SHN_UNDEF':
                        undefs[symbol.name] = None
                    else:
                        exports[symbol.name] = None

        return exports, undefs

    def parse_dynamic(self):
        needed = {}
        rpaths = []
        for section in self.elffile.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    needed[tag.needed] = None
                elif tag.entry.d_tag == 'DT_RPATH':
                    #TODO: RPATH vs. RUNPATH
                    #TODO: RPATH gets passed down
                    rpaths = [rpath.replace("$ORIGIN",
                                            os.path.dirname(self.fullname))
                              for rpath in tag.rpath.split(',')]

        return needed, rpaths

    def parse_functions(self):
        self.exported_functions, self.undefs = self.parse_symtab()
        self.needed_libs, self.rpaths = self.parse_dynamic()
        del self.elffile
        self.fd.close()

    def is_compatible(self, other):
        hdr = self.elfheader
        o_hdr = other.elfheader
        return hdr['e_ident']['EI_CLASS'] == o_hdr['e_ident']['EI_CLASS'] and \
            hdr['e_machine'] == o_hdr['e_machine']

    def find_compatible_libs(self, resolver, cache):
        for needed in self.needed_libs:
            for path in resolver.get_paths(needed, self.rpaths):
                if path in cache:
                    target = cache[path]
                else:
                    target = Library(path)

                if self.is_compatible(target):
                    self.needed_libs[needed] = target.fullname
                    # TODO: move cache handling into receiver?
                    if path not in cache:
                        yield target
                    break


if __name__ == '__main__':

    resolver = LDResolve()
    cache = LibraryArchive()

    paths = []
    for path in sys.argv[1:]:
        if os.path.isdir(path):
            paths.extend([os.path.join(os.path.abspath(sys.argv[1]), entry.name)
                          for entry in os.scandir(sys.argv[1])
                          if entry.is_file()])
        else:
            paths.append(path)

    for path in paths:
        print("Processing {}".format(path), file=sys.stderr)

        if os.path.islink(path):
            # If we get a symlink, note in in the cache and process target
            print("{} is a symlink to {}".format(path, os.readlink(path)),
                  file=sys.stderr)
            target = os.readlink(path)
            if not os.path.isabs(target):
                target = os.path.join(os.path.dirname(path), target)
            cache.add_library(path, target)
            path = target
        elif not os.path.isfile(path):
            continue
        elif path in cache:
            # skip potentially processed targets of symlinks
            continue

        try:
            item = Library(path)
        except ELFError as e:
            print("ERR: {} => {}".format(path, e), file=sys.stderr)
            continue

        worklist = collections.deque()
        worklist.append(item)

        while worklist:
            current_lib = worklist.pop()
            current_lib.parse_functions()

            cache.add_library(current_lib.fullname, current_lib)

            needed = current_lib.find_compatible_libs(resolver, cache)
            worklist.extend(x for x in needed)


    print(len(cache))

    lib = cache[paths[0]]
    undef = lib.undefs

    for function in undef:
        found = False
        for imp, imp_lib in lib.needed_libs.items():
            if function in cache[imp_lib].exported_functions:
                print('Found {} in {}'.format(function, imp_lib))
                found = True
                break
        if not found:
            # TODO: consider symbol versioning?
            print('Did not find {}'.format(function))
