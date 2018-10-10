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

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.common.utils import struct_parse
from elftools.construct import Padding, SLInt32, Struct

def _round_up_to_alignment(size, alignment):
    if size == 0:
        size = 1
    if alignment:
        return ((size + alignment - 1) // alignment) * alignment
    return size

class Library:

    def __init__(self, filename, load_elffile=True, parse=False):
        if not os.path.isabs(filename):
            raise ValueError("{} is no absolute path".format(filename))

        self.fullname = filename

        if load_elffile:
            self.fd = open(filename, 'rb')
            self._elffile = ELFFile(self.fd)
            self.elfheader = self._elffile.header
            text = self._elffile.get_section_by_name('.text')
            if not text:
                raise ELFError("{} has no text section".format(filename))
            self.load_offset = text['sh_addr'] - text['sh_offset']

        self._version_names = {}

        self.exports = collections.OrderedDict()
        self.function_addrs = set()
        self.imports = collections.OrderedDict()

        self.exports_plt = collections.OrderedDict()
        self.imports_plt = collections.OrderedDict()

        self.needed_libs = collections.OrderedDict()
        self.all_imported_libs = collections.OrderedDict()
        self.rpaths = []
        self.runpaths = []
        self.soname = None

        self.ranges = collections.defaultdict(list)
        self.external_calls = {}
        self.internal_calls = {}

        if parse:
            self.parse_functions()

    def _get_symbol_offset(self, symbol):
        return symbol['st_value'] - self.load_offset

    def _get_function_symbols(self, section):
        retval = []
        ei_osabi = self.elfheader['e_ident']['EI_OSABI']

        for idx, symbol in enumerate(section.iter_symbols()):
            symbol_type = symbol['st_info']['type']

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

            retval.append((idx, symbol))

        return retval

    def _get_versioned_name(self, symbol, idx):
        if idx not in self._version_names:
            return symbol.name
        return '{}@@{}'.format(symbol.name, self._version_names[idx])

    def parse_dynsym(self):
        section = self._elffile.get_section_by_name('.dynsym')
        if not section:
            return

        for idx, symbol in self._get_function_symbols(section):
            shndx = symbol['st_shndx']
            symbol_bind = symbol['st_info']['bind']
            if shndx == 'SHN_UNDEF':
                self.imports[self._get_versioned_name(symbol, idx)] = None
            else:
                start = self._get_symbol_offset(symbol)
                self.function_addrs.add(start)
                if symbol_bind != 'STB_LOCAL':
                    name = self._get_versioned_name(symbol, idx)
                    self.exports[name] = set()
                    size = symbol['st_size']
                    self.ranges[name].append((start, size))

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
                    logging.info('\'%s\' is PIE', self.fullname)
                    self.function_addrs.add(self.elfheader['e_entry'])

    def parse_plt(self):
        if self.elfheader['e_machine'] == 'EM_386':
            relaplt = self._elffile.get_section_by_name('.rel.plt')
        else:
            relaplt = self._elffile.get_section_by_name('.rela.plt')
        plt = self._elffile.get_section_by_name('.plt')
        dynsym = self._elffile.get_section_by_name('.dynsym')
        if relaplt and plt and dynsym:
            plt_base = plt['sh_offset']

            # On 32-bit binaries, sh_entsize might be 4 even though an entry
            # in the .plt is in fact 16 bytes long, so round up to sh_addralign.
            # (see https://reviews.llvm.org/D9560)
            increment = _round_up_to_alignment(plt['sh_entsize'], plt['sh_addralign'])

            plt_offset = 0
            for reloc in sorted(relaplt.iter_relocations(), key=lambda rel: rel['r_offset']):
                # The first entry in .plt is special, it contains the logic for
                # all other entries to jump into the loader. Real functions come
                # after that.
                plt_offset += increment

                symbol_index = reloc['r_info_sym']
                symbol = dynsym.get_symbol(symbol_index)
                if not symbol.name:
                    continue

                plt_addr = plt_base + plt_offset
                if symbol['st_shndx'] == 'SHN_UNDEF':
                    self.imports_plt[plt_addr] = \
                        self._get_versioned_name(symbol, symbol_index)
                else:
                    self.exports_plt[plt_addr] = \
                        self._get_versioned_name(symbol, symbol_index)
        else:
            logging.debug('missing sections (.rel{a}.plt, .plt., .dynsym) for %s',
                          self.fullname)

    def parse_plt_got(self):
        pltgot = self._elffile.get_section_by_name('.plt.got')
        if not pltgot:
            return

        entrysize = _round_up_to_alignment(pltgot['sh_entsize'],
                                           pltgot['sh_addralign'])
        count = pltgot['sh_size'] // entrysize

        # We only need the .got/.got.plt offset for 32 bit binaries
        if self.elfheader['e_machine'] == 'EM_386':
            got = self._elffile.get_section_by_name('.got.plt')
            if not got:
                got = self._elffile.get_section_by_name('.got')
            if not got:
                logging.debug('no .got section found')
                return

        # The names are different for 32 vs 64 bit binaries
        if self.elfheader['e_machine'] == 'EM_386':
            dynrel = self._elffile.get_section_by_name('.rel.dyn')
        else:
            # For 64 bit, the entries could be in .rela.got or merged into
            # .rela.dyn in the linker script, so try in that order.
            dynrel = self._elffile.get_section_by_name('.rela.got')
            if not dynrel:
                dynrel = self._elffile.get_section_by_name('.rela.dyn')
        if not dynrel:
            logging.debug('no .rel{a}.{dyn,got} section found')
            return

        dynrel_relocs = {e['r_offset']: e['r_info_sym'] for e in dynrel.iter_relocations()}

        # To find the corresponding symbol name, we need the .dynsym section
        dynsym = self._elffile.get_section_by_name('.dynsym')
        if not dynsym:
            logging.debug('no .dynsym section found')
            return

        for i in range(count):
            cur_entry = pltgot['sh_offset'] + i * entrysize
            pltgot_entry = struct_parse(Struct(None,
                                               Padding(2), # call indirect
                                               SLInt32('offset'),
                                               Padding(2)  # NOP to fill to 8 bytes
                                              ),
                                        self._elffile.stream,
                                        stream_pos=cur_entry)
            offset = pltgot_entry['offset']
            if self.elfheader['e_machine'] == 'EM_386':
                # 32-bit: relative to .got.plt/.got base address
                got_entry = got['sh_addr'] + offset
            else:
                # x86_64: relative to RIP. This means adding 6 to the offset
                # as RIP-relative addressing is based on the address of the
                # _next_ instruction rather than the current one
                got_entry = cur_entry + offset + 6 + self.load_offset

            if got_entry in dynrel_relocs:
                symbol_index = dynrel_relocs[got_entry]
                symbol = dynsym.get_symbol(symbol_index)
#                    print('Found {} - {}'.format(hex(cur_entry), symbol.name))
                if symbol['st_shndx'] == 'SHN_UNDEF':
                    self.imports_plt[cur_entry] = \
                        self._get_versioned_name(symbol, symbol_index)
                else:
                    self.exports_plt[cur_entry] = \
                        self._get_versioned_name(symbol, symbol_index)

    def parse_versions(self):
        versions = self._elffile.get_section_by_name('.gnu.version')
        if not versions:
            return

        idx_to_names = {}

        # Parse version definitions for version index -> name mapping
        verdefs = self._elffile.get_section_by_name('.gnu.version_d')
        if verdefs:
            for verdef, verdaux in verdefs.iter_versions():
                idx_to_names[int(verdef.entry['vd_ndx'])] = list(verdaux)[0].name

        # Parse version requirements for version index -> version name mapping
        verneed = self._elffile.get_section_by_name('.gnu.version_r')
        if verneed:
            for _, vernaux in verneed.iter_versions():
                for aux in vernaux:
                    idx_to_names[int(aux['vna_other'])] = aux.name

        # Directly construct mapping from symbol index to version name
        for idx, version in enumerate(versions.iter_symbols()):
            version_idx = version['ndx']
            # If it's a string, it's either VER_NDX_LOCAL or VER_NDX_GLOBAL,
            # both indicating unversioned names
            if isinstance(version_idx, int):
                # And-ing out bit 15 is necessary as it might be set to
                # indicate the symbol in question should be treated as hidden.
                self._version_names[idx] = idx_to_names[version_idx & 0x7fff]


    def parse_functions(self, release=False):
        self.parse_versions()
        self.parse_dynsym()
        self.parse_dynamic()
        self.parse_plt()
        self.parse_plt_got()
        self.gather_hookable_addresses_from_symtab()
        self.get_function_ranges()
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
        if name not in self.exports:
            # If the name can not be found, try to identify the corresponding
            # function without the version string attached
            possible_versioned_symbols = [symbol for symbol in self.exports
                                          if symbol.split('@@')[0] == name]
            # If there is one, use it, otherwise it's either not unique or
            # the corresponding symbol isn't there.
            if len(possible_versioned_symbols) == 1:
                name = possible_versioned_symbols[0]
            else:
                logging.error('%s not found in %s (user would be %s)', name,
                              self.fullname, user_path)
                return False
        if user_path not in self.exports[name]:
            self.exports[name].add(user_path)
            return True
        return False

    def get_function_ranges(self):
        return self.ranges

    def gather_hookable_addresses_from_symtab(self):
        if self.elfheader['e_type'] == 'ET_EXEC':
            self.function_addrs.add(self.elfheader['e_entry'] - \
                                    self.load_offset)

        symtab = self._elffile.get_section_by_name('.symtab')
        if not symtab:
            return

        for _, symbol in self._get_function_symbols(symtab):
            shndx = symbol['st_shndx']
            if shndx != 'SHN_UNDEF':
                self.function_addrs.add(self._get_symbol_offset(symbol))

    def summary(self):
        return '{}: {} imports, {} exports, {} needed libs, ' \
                   '{} rpaths, {} runpaths' \
                   .format(self.fullname, len(self.imports), len(self.exports),
                           len(self.needed_libs), len(self.rpaths),
                           len(self.runpaths))

    def __str__(self):
        return self.summary()
