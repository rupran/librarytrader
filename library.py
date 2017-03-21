import collections
import os
import sys

from common.datatypes import LDResolve, LibraryArchive
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection


class Library:

    def __init__(self, filename):
        if not os.path.isabs(filename):
            raise ValueError("{} is no absolute path".format(filename))

        self.fullname = filename
        self.filename = os.path.basename(filename)
        self.elffile = ELFFile(open(filename, 'rb'))

        self.machine = self.elffile.header['e_machine']
        self.ei_class = self.elffile.header['e_ident']['EI_CLASS']

        self.exported_functions = None
        self.undefs = None
        self.needed_libs = None
        self.libmap = {}

    def parse_symtab(self):
        exports = collections.OrderedDict()
        undefs = collections.OrderedDict()

        for section in self.elffile.iter_sections():
            if isinstance(section, SymbolTableSection):
                for nsym, symbol in enumerate(section.iter_symbols()):
                    shndx = symbol['st_shndx']
                    symbol_type = symbol['st_info']['type']
                    if symbol_type != 'STT_FUNC':
                    # TODO: check for use of LOOS/IFUNC wrt libc symbols like
                    # memcpy... consider adding the following to the if check:
                    # and symbol_type != 'STT_LOOS': 
                        continue

                    if shndx == 'SHN_UNDEF':
                        undefs[symbol.name] = symbol 
                    else:
                        exports[symbol.name] = symbol

        return exports, undefs

    def get_needed_libs(self):
        needed = []
        for section in self.elffile.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    needed.append(tag.needed)
        return needed

    def parse_functions(self):
        self.exported_functions, self.undefs = self.parse_symtab()
        self.needed_libs = self.get_needed_libs()


if __name__ == '__main__':

    cache = LibraryArchive()
    resolver = LDResolve()

    initial = sys.argv[1]

    worklist = collections.deque()
    worklist.append(Library(sys.argv[1]))

    while worklist:
        current_lib = worklist.pop()
        current_lib.parse_functions()
        
        for needed in current_lib.needed_libs:
            for path in resolver.get_paths(needed):
                # Check if we already processed the target and skip it
                if path in cache:
                    continue
                
                # Find the matching library, add it to the worklist
                target = Library(path)
                if current_lib.ei_class == target.ei_class and \
                        current_lib.machine == target.machine:
                    worklist.append(target)
                    current_lib.libmap[needed] = target

        cache.add_library(current_lib.fullname, current_lib)

    print(len(cache))

    lib = cache[initial]
    undef = lib.undefs

    for function in undef:
        found = False
        for imp, imp_lib in lib.libmap.items():
            if function in imp_lib.exported_functions:
                print('Found {} in {}'.format(function, imp_lib.fullname))
                found = True
                break
        if not found:
            # TODO: consider symbol versioning?
            print('Did not find {}'.format(function))
