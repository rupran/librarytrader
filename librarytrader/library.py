# Copyright 2017-2018, Andreas Ziegler <andreas.ziegler@fau.de>
#
# This file is part of librarytrader.
#
# librarytrader is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# librarytrader is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with librarytrader.  If not, see <http://www.gnu.org/licenses/>.

import collections
import logging
import os

from elftools.elf.elffile import ELFFile

class Library:

    def __init__(self, filename, load_elffile=True, parse=False):
        if not os.path.isabs(filename):
            raise ValueError("{} is no absolute path".format(filename))

        self.fullname = filename

        if load_elffile:
            self.fd = open(filename, 'rb')
            self._elffile = ELFFile(self.fd)
            self.elfheader = self._elffile.header

        self.exports = collections.OrderedDict()
        self.imports = collections.OrderedDict()

        self.exports_plt = collections.OrderedDict()
        self.imports_plt = collections.OrderedDict()

        self.needed_libs = collections.OrderedDict()
        self.all_imported_libs = collections.OrderedDict()
        self.rpaths = []
        self.runpaths = []
        self.soname = None

        self.calls = {}

        if parse:
            self.parse_functions()

    def parse_symtab(self):
        ei_osabi = self.elfheader['e_ident']['EI_OSABI']
        section = self._elffile.get_section_by_name('.dynsym')
        if not section:
            return

        for _, symbol in enumerate(section.iter_symbols()):
            shndx = symbol['st_shndx']
            symbol_type = symbol['st_info']['type']
            symbol_bind = symbol['st_info']['bind']

            if symbol_type == 'STT_FUNC':
                pass
            elif (ei_osabi == 'ELFOSABI_LINUX' or \
                    ei_osabi == 'ELFOSABI_SYSV') \
                    and symbol_type == 'STT_LOOS':
                # TODO: generic check for use of LOOS/IFUNC. libc uses
                # STT_IFUNC (which is the same value as STT_LOOS) to
                # provide multiple, architecture-specific
                # implementations of stuff like memcpy, strcpy etc.
                pass
            else:
                continue

            if symbol_bind == 'STB_LOCAL':
                continue

            if shndx == 'SHN_UNDEF':
                self.imports[symbol.name] = None
            elif self.elfheader['e_type'] != 'ET_EXEC':
                self.exports[symbol.name] = None

    def parse_dynamic(self):
        section = self._elffile.get_section_by_name('.dynamic')
        if not section:
            return

        for tag in section.iter_tags():
            if tag.entry.d_tag == 'DT_NEEDED':
                self.needed_libs[tag.needed] = None
            elif tag.entry.d_tag == 'DT_RPATH':
                self.rpaths = [rpath.replace("$ORIGIN",
                                             os.path.dirname(self.fullname))
                               for rpath in tag.rpath.split(':')]
            elif tag.entry.d_tag == 'DT_RUNPATH':
                self.runpaths = [rpath.replace("$ORIGIN",
                                               os.path.dirname(self.fullname))
                                 for rpath in tag.runpath.split(':')]
            elif tag.entry.d_tag == 'DT_SONAME':
                self.soname = tag.soname
            elif tag.entry.d_tag == 'DT_FLAGS_1':
                # PIE
                if tag.entry.d_val & 0x8000000:
                    logging.info('\'%s\' is PIE, dropping exports...',
                                 self.fullname)
                    self.exports.clear()

    def parse_plt(self):
        relaplt = self._elffile.get_section_by_name('.rela.plt')
        plt = self._elffile.get_section_by_name('.plt')
        dynsym = self._elffile.get_section_by_name('.dynsym')
        if relaplt and plt and dynsym:
            base = plt['sh_offset']
            offset = 0
            for reloc in relaplt.iter_relocations():
                # The first entry in .plt is special, it contains the logic for
                # all other entries to jump into the loader. Real functions come
                # after that.
                offset += plt['sh_entsize']

                symbol = dynsym.get_symbol(reloc['r_info_sym'])
                if not symbol.name:
                    continue

                plt_addr = base + offset
                if symbol['st_shndx'] == 'SHN_UNDEF':
                    self.imports_plt[plt_addr] = symbol.name
                else:
                    self.exports_plt[plt_addr] = symbol.name
        else:
            logging.debug('missing sections for %s', self.fullname)

    def parse_functions(self, release=False):
        self.parse_symtab()
        self.parse_dynamic()
        self.parse_plt()
        if release:
            self._release_elffile()

    def _release_elffile(self):
        del self._elffile
        self.fd.close()
        del self.fd

    def is_compatible(self, other):
        hdr = self.elfheader
        o_hdr = other.elfheader
        return hdr['e_ident']['EI_CLASS'] == o_hdr['e_ident']['EI_CLASS'] and \
            hdr['e_machine'] == o_hdr['e_machine']

    def add_export_user(self, name, user_path):
        if self.exports[name] is None:
            self.exports[name] = []
        if user_path not in self.exports[name]:
            self.exports[name].append(user_path)
            return True
        return False

    def get_function_ranges(self):
        ranges = collections.defaultdict(list)
        dynsym = self._elffile.get_section_by_name('.dynsym')
        if not dynsym:
            return ranges
        for name in self.exports:
            # Could me more than one => symbol versioning. One probably has the
            # high bit set in .gnu.version at the corresponding offset
            # TODO: check that!
            # For now, evaluate them all
            syms = dynsym.get_symbol_by_name(name)
            for sym in syms:
                start = sym.entry['st_value']
                size = sym.entry['st_size']
                ranges[name].append((start, size))

        return ranges

    def summary(self):
        return '{}: {} imports, {} exports, {} needed libs, ' \
                   '{} rpaths, {} runpaths' \
                   .format(self.fullname, len(self.imports), len(self.exports),
                           len(self.needed_libs), len(self.rpaths),
                           len(self.runpaths))

    def __str__(self):
        return self.summary()
