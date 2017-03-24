import collections
import os

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

class Library:

    def __init__(self, filename):
        if not os.path.isabs(filename):
            raise ValueError("{} is no absolute path".format(filename))

        self.fullname = filename

        self._fd = open(filename, 'rb')
        self._elffile = ELFFile(self._fd)
        self._elfheader = self._elffile.header

        self.exports = None
        self.imports = None

        self.needed_libs = None
        self.rpaths = None

    def parse_symtab(self):
        exports = collections.OrderedDict()
        imports = collections.OrderedDict()

        for section in self._elffile.iter_sections():
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
                        imports[symbol.name] = None
                    else:
                        exports[symbol.name] = None

        return exports, imports

    def parse_dynamic(self):
        needed = {}
        rpaths = []
        for section in self._elffile.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    needed[tag.needed] = None
                elif tag.entry.d_tag == 'DT_RPATH':
                    #TODO: RPATH gets passed down, RUNPATH doesn't
                    rpaths = [rpath.replace("$ORIGIN",
                                            os.path.dirname(self.fullname))
                              for rpath in tag.rpath.split(':')]
                elif tag.entry.d_tag == 'DT_RUNPATH':
                    #TODO only evaluate DT_RPATH if DT_RUNPATH does not exist
                    rpaths = [rpath.replace("$ORIGIN",
                                            os.path.dirname(self.fullname))
                              for rpath in tag.runpath.split(':')]

        return needed, rpaths

    def parse_functions(self, release=False):
        self.exports, self.imports = self.parse_symtab()
        self.needed_libs, self.rpaths = self.parse_dynamic()
        if release:
            self._release_elffile()

    def _release_elffile(self):
        del self._elffile
        self._fd.close()

    def is_compatible(self, other):
        hdr = self._elfheader
        o_hdr = other._elfheader
        return hdr['e_ident']['EI_CLASS'] == o_hdr['e_ident']['EI_CLASS'] and \
            hdr['e_machine'] == o_hdr['e_machine']
