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

import bisect
import collections
import logging
import os
import struct

import capstone
from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.common.utils import struct_parse
from elftools.construct import Padding, SLInt32, Struct
from elftools.elf.enums import ENUM_RELOC_TYPE_x64, ENUM_RELOC_TYPE_i386, \
    ENUM_RELOC_TYPE_AARCH64
from libdebuginfod import DebugInfoD

DEBUG_DIR = os.path.join(os.sep, 'usr', 'lib', 'debug')
BUILDID_DIR = os.path.join(os.sep, DEBUG_DIR, '.build-id')
EXTERNAL_DEBUG_DIR = os.environ.get('EXTERNAL_DEBUG_DIR')
EXTERNAL_BUILDID_DIR = os.environ.get('EXTERNAL_BUILDID_DIR')
USE_DEBUGINFOD = os.environ.get('USE_DEBUGINFOD')

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
                for segment in self._elffile.iter_segments():
                    if segment['p_type'] == 'PT_LOAD' and segment['p_flags'] == 0x5:
                        self.load_offset = segment['p_vaddr'] - segment['p_offset']
                        break
                else:
                    raise ELFError("{} has no text section or PT_LOAD".format(filename))
            else:
                self.load_offset = text['sh_addr'] - text['sh_offset']
            self.entrypoint = None
            if self.elfheader['e_type'] == 'ET_EXEC':
                self.entrypoint = self.elfheader['e_entry'] - self.load_offset

        self._version_names = {}
        self._version_indices = {}
        self.defines_versions = False
        self.version_descriptions = {}

        # exported_addrs: address -> symbol names
        self.exported_addrs = collections.defaultdict(list)
        # export_bind: symbol name -> symbol bind type (STB_{WEAK,GLOBAL,...})
        self.export_bind = {}
        # exported_names: symbol name -> address
        self.exported_names = collections.OrderedDict()
        # export_users: address -> list of referencing library paths
        self.export_users = collections.OrderedDict()
        self.function_addrs = set()
        # imports: symbol name -> path to implementing library
        self.imports = collections.OrderedDict()
        # local functions: address -> symbol name
        self.local_functions = collections.defaultdict(list)
        self.local_users = collections.OrderedDict()

        # exports_plt: plt address -> implementing address
        self.exports_plt = collections.OrderedDict()
        # imports_plt: plt address -> symbol name
        self.imports_plt = collections.OrderedDict()

        # needed_libs: name from DT_NEEDED -> path of library
        self.needed_libs = collections.OrderedDict()
        self.all_imported_libs = collections.OrderedDict()

        # defined objects: address -> name
        self.exported_objs = collections.defaultdict(list)
        # defined objects: name -> address
        self.exported_obj_names = collections.OrderedDict()
        # imported objects: address -> name
        self.imported_objs = collections.OrderedDict()
        # imported objects: name -> path to offering library
        self.imported_objs_locations = collections.OrderedDict()
        # local defined objects: address -> name
        self.local_objs = collections.defaultdict(list)
        # TODO: names for local objects are not unique!
        # address ranges for objects
        self.object_ranges = {}
        # outgoing functions from objects (object address -> list of addresses)
        self.object_to_functions = collections.defaultdict(set)
        # outgoing objects from objects (object address -> list of addresses)
        self.object_to_objects = collections.defaultdict(set)
        # function references to objects (function address -> list of objects)
        # these dictionaries are filled from the disassembly step
        self.export_object_refs = collections.defaultdict(set)
        self.local_object_refs = collections.defaultdict(set)
        self.import_object_refs = collections.defaultdict(set)

        # external users of objects: address -> list of referencing library paths
        self.object_users = collections.OrderedDict()

        # RELATIVE relocations pointing to local functions
        self.reloc_to_local = collections.OrderedDict()
        # RELATIVE relocations pointing to exported functions
        self.reloc_to_exported = collections.OrderedDict()

        self.rpaths = []
        self.runpaths = []
        self.soname = None
        self.init_functions = []
        self.fini_functions = []

        self.ranges = {}
        self.external_calls = collections.defaultdict(set)
        self.internal_calls = collections.defaultdict(set)
        self.local_calls = collections.defaultdict(set)

        if parse:
            self.parse_functions()

    def is_i386(self):
        return self.elfheader['e_machine'] == 'EM_386'

    def is_x86_64(self):
        return self.elfheader['e_machine'] == 'EM_X86_64'

    def is_aarch64(self):
        return self.elfheader['e_machine'] == 'EM_AARCH64'

    def _get_symbol_offset(self, symbol):
        return symbol['st_value'] - self.load_offset

    def _get_symbols_by_type(self, section, wanted_type, prefix_local):
        retval = []
        ei_osabi = self.elfheader['e_ident']['EI_OSABI']
        first_nonlocal = 0
        current_file = None
        if prefix_local:
            first_nonlocal = section['sh_info'] + 1

        for idx, symbol in enumerate(section.iter_symbols()):
            symbol_type = symbol['st_info']['type']

            if idx == 0:
                continue
            if prefix_local and symbol_type == 'STT_FILE':
                current_file = symbol.name
            if idx == first_nonlocal or current_file == '':
                current_file = None
            if symbol_type == wanted_type:
                pass
            elif wanted_type == 'STT_FUNC' and \
                    symbol_type == 'STT_LOOS' and \
                    ei_osabi in ('ELFOSABI_LINUX', 'ELFOSABI_SYSV'):
                # TODO: generic check for use of LOOS/IFUNC. libc uses
                # STT_IFUNC (which is the same value as STT_LOOS) to
                # provide multiple, architecture-specific
                # implementations of stuff like memcpy, strcpy etc.
                pass
            elif wanted_type == 'STT_FUNC' and \
                    'NOTYPE_AS_FUNCTION' in os.environ and \
                    symbol_type == 'STT_NOTYPE' and \
                    symbol['st_shndx'] == 'SHN_UNDEF':
                pass
            else:
                continue

            if prefix_local and current_file:
                symbol.name = '{}_{}'.format(current_file, symbol.name)
            retval.append((idx, symbol))

        return retval

    def _get_function_symbols(self, section, prefix_local=False):
        return self._get_symbols_by_type(section, 'STT_FUNC', prefix_local)

    def _get_object_symbols(self, section, prefix_local=False):
        return self._get_symbols_by_type(section, 'STT_OBJECT', prefix_local)

    def _get_versioned_name(self, symbol, idx):
        if idx not in self._version_names:
            return symbol.name
        return '{}@@{}'.format(symbol.name, self._version_names[idx])

    def _get_dynsym(self):
        dynsym = self._elffile.get_section_by_name('.dynsym')
        if not dynsym:
            # Try to get segment if no section was found
            for segment in self._elffile.iter_segments():
                if isinstance(segment, DynamicSegment):
                    dynsym = segment
                    break
        return dynsym

    def _search_for_plt(self):
        text_start = 0
        text_end = 0
        for segment in self._elffile.iter_segments():
            if segment['p_type'] == 'PT_LOAD' and segment['p_flags'] == 0x5:
                text_start = segment['p_offset']
                text_end = text_start + segment['p_filesz']
                break

        self.fd.seek(text_start)
        read_increment = 16
        plt_entsize = 16
        plt_addralign = 16

        if self.is_x86_64():
            match = lambda x: x[0:2] == b'\xff\x35' and x[6:8] == b'\xff\x25'
        elif self.is_i386():
            match = lambda x: x[0:2] == b'\xff\xb3' and x[6:8] == b'\xff\xa3'
        elif self.is_aarch64():
            if self.elfheader['e_ident']['EI_DATA'] == 'ELFDATA2LSB':
                match = lambda x: x[0:4] == b'\xf0\x7b\xbf\xa9'
            else:
                match = lambda x: x[0:4] == b'\xa9\xbf\x7b\xf0'
        else:
            logging.error('unsupported architecture for .plt search')
            return None

        cur_offset = text_start
        plt_offset = None
        read_bytes = self.fd.read(read_increment)
        while cur_offset < text_end:
            if match(read_bytes):
                plt_offset = cur_offset
                break
            cur_offset += read_increment
            read_bytes = self.fd.read(read_increment)

        if not plt_offset:
            return None
        else:
            logging.debug('found .plt at %x', plt_offset)

        # These are the only attributes we use in parse_plt()
        return {'sh_offset': plt_offset, 'sh_entsize': plt_entsize,
                'sh_addralign': plt_addralign}

    def _create_mock_rela_plt(self):
        dynamic = None
        for segment in self._elffile.iter_segments():
            if isinstance(segment, DynamicSegment):
                dynamic = segment
                break

        if not dynamic:
            return None

        is_rela = False
        entsize = 0
        tablesize = 0
        offset = 0
        if list(dynamic.iter_tags('DT_RELA')):
            is_rela = True
        elif not list(dynamic.iter_tags('DT_REL')):
            return None

        if is_rela:
            relaent = list(dynamic.iter_tags('DT_RELAENT'))
            pltrelsz = list(dynamic.iter_tags('DT_PLTRELSZ'))
            jmprel = list(dynamic.iter_tags('DT_JMPREL'))
            if not relaent or not pltrelsz or not jmprel:
                return None
            entsize = relaent[0].entry.d_val
            tablesize = pltrelsz[0].entry.d_val
            offset = jmprel[0].entry.d_val
            sectype = 'SHT_RELA'
        else:
            relent = list(dynamic.iter_tags('DT_RELENT'))
            pltrelsz = list(dynamic.iter_tags('DT_PLTRELSZ'))
            jmprel = list(dynamic.iter_tags('DT_JMPREL'))
            if not relent or not pltrelsz or not jmprel:
                return None
            entsize = relent[0].entry.d_val
            tablesize = pltrelsz[0].entry.d_val
            offset = jmprel[0].entry.d_val
            sectype = 'SHT_REL'

        hdr = {'sh_size': tablesize, 'sh_offset': offset - self.load_offset,
               'sh_entsize': entsize, 'sh_flags': 0x2, 'sh_addralign': 8,
               'sh_type': sectype}
        #print(self.fullname, hdr, list(rel.iter_relocations())[0])
        return RelocationSection(hdr, '.rela.plt', self._elffile)

    def _fixup_init_size(self, symbol, size, shndx):
        init_section = self._elffile.get_section(shndx)
        if init_section.name == '.init':
            size = max(size, init_section['sh_size'])
        return size

    def _fixup_fini_size(self, symbol, size, shndx):
        fini_section = self._elffile.get_section(shndx)
        if fini_section.name == '.fini':
            size = max(size, fini_section['sh_size'])
        return size

    def parse_dynsym(self):
        section = self._get_dynsym()
        if not section:
            return

        for idx, symbol in self._get_function_symbols(section):
            shndx = symbol['st_shndx']
            symbol_bind = symbol['st_info']['bind']
            if shndx == 'SHN_UNDEF':
                name = self._get_versioned_name(symbol, idx)
                if isinstance(name, bytes):
                    name = name.decode('utf-8')
                self.imports[name] = None
            else:
                start = self._get_symbol_offset(symbol)
                self.function_addrs.add(start)
                if symbol_bind != 'STB_LOCAL':
                    name = self._get_versioned_name(symbol, idx)
                    if isinstance(name, bytes):
                        name = name.decode('utf-8')
                    self.export_users[start] = set()
                    self.export_bind[name] = symbol_bind
                    self.exported_names[name] = start
                    self.exported_addrs[start].append(name)

                    if self.defines_versions:
                        # Check for special cases with this statement. We add
                        # an unversioned name with STB_GLOBAL binding to the
                        # list of defined versions. This should be used if
                        # we only find one version during the lookup.
                        if symbol.name not in self.version_descriptions:
                            self.version_descriptions[symbol.name] = []
                        version_index = self._version_indices[idx]
                        if version_index == 1:
                            self.version_descriptions[symbol.name].append((1, True, symbol.name))
                        if idx in self._version_names:
                            # index, hidden
                            descr = (version_index & 0x7fff,
                                     version_index & 0x8000 == 0x8000,
                                     '{}@@{}'.format(symbol.name, self._version_names[idx]))
                            # If there are actual versions defined, put them
                            # before the unversioned global definition
                            if descr not in self.version_descriptions[symbol.name]:
                                self.version_descriptions[symbol.name].insert(0, descr)

                    size = symbol['st_size']
                    if symbol.name == '_init':
                        # Sometimes, the _init symbol only has a size of 1 in
                        # .dynsym but the section header of the underlying
                        # .init section can tell us how long the whole section
                        # is -> take the maximum of those two values.
                        size = self._fixup_init_size(symbol, size, shndx)
                        # Also add plain '.init' name in addition to
                        # possibly versioned name
                        if symbol.name not in self.exported_addrs[start]:
                            self.exported_addrs[start].append(symbol.name)
                        if start not in self.init_functions:
                            self.init_functions.append(start)
                    elif symbol.name == '_fini':
                        size = self._fixup_fini_size(symbol, size, shndx)
                        if symbol.name not in self.exported_addrs[start]:
                            self.exported_addrs[start].append(symbol.name)
                        if start not in self.fini_functions:
                            self.fini_functions.append(start)
                    if start in self.ranges and self.ranges[start] != size:
                        logging.warning("differing range %s:%x:(%x <-> %x)",
                                        self.fullname, start,
                                        self.ranges[start], size)
                        size = max(self.ranges[start], size)
                    self.ranges[start] = size

        for idx, symbol in self._get_object_symbols(section):
            shndx = symbol['st_shndx']
            symbol_bind = symbol['st_info']['bind']
            if shndx == 'SHN_UNDEF':
                name = self._get_versioned_name(symbol, idx)
                if isinstance(name, bytes):
                    name = name.decode('utf-8')
                pass
                #TODO: what to do here?
                #self.imported_objs_locations[name] = None
            else:
                addr = symbol['st_value']
                if not addr:
                    continue
                # STB_LOOS objects are of type STB_GNU_UNIQUE for SYSV binaries
                if symbol_bind in ('STB_GLOBAL', 'STB_WEAK', 'STB_LOOS'):
                    name = self._get_versioned_name(symbol, idx)
                    size = symbol['st_size']
                    self.exported_objs[addr].append(name)
                    self.exported_obj_names[name] = addr
                    self.object_ranges[addr] = max(self.object_ranges.get(addr, 0), size)
                else:
                    logging.debug('Symbol %s:%s has type %s', self.fullname,
                                  symbol.name, symbol_bind)

    def parse_dynamic(self):
        section = self._elffile.get_section_by_name('.dynamic')
        if not section:
            # Try to get segment if no section was found
            for segment in self._elffile.iter_segments():
                if isinstance(segment, DynamicSegment):
                    section = segment
                    break

        if not section:
            return

        init_array = None
        init_arraysz = 0
        fini_array = None
        fini_arraysz = 0

        for tag in section.iter_tags():
            if tag.entry.d_tag == 'DT_NEEDED':
                if isinstance(tag.needed, bytes):
                    tag.needed = tag.needed.decode('utf-8')
                self.needed_libs[tag.needed] = None
            elif tag.entry.d_tag == 'DT_RPATH':
                if isinstance(tag.rpath, bytes):
                    tag.rpath = tag.rpath.decode('utf-8')
                self.rpaths = [rpath.replace("$ORIGIN",
                                             os.path.dirname(self.fullname))
                               for rpath in tag.rpath.split(':')]
            elif tag.entry.d_tag == 'DT_RUNPATH':
                if isinstance(tag.runpath, bytes):
                    tag.runpath = tag.runpath.decode('utf-8')
                self.runpaths = [rpath.replace("$ORIGIN",
                                               os.path.dirname(self.fullname))
                                 for rpath in tag.runpath.split(':')]
            elif tag.entry.d_tag == 'DT_SONAME':
                if isinstance(tag.soname, bytes):
                    tag.soname = tag.soname.decode('utf-8')
                self.soname = tag.soname
            elif tag.entry.d_tag == 'DT_FLAGS_1':
                # PIE
                if tag.entry.d_val & 0x8000000:
                    logging.info('\'%s\' is PIE', self.fullname)
                    self.entrypoint = self.elfheader['e_entry']
            elif tag.entry.d_tag == 'DT_INIT_ARRAY':
                init_array = next(self._elffile.address_offsets(tag.entry.d_ptr))
            elif tag.entry.d_tag == 'DT_INIT_ARRAYSZ':
                init_arraysz = tag.entry.d_val
            elif tag.entry.d_tag == 'DT_FINI_ARRAY':
                fini_array = next(self._elffile.address_offsets(tag.entry.d_ptr))
            elif tag.entry.d_tag == 'DT_FINI_ARRAYSZ':
                fini_arraysz = tag.entry.d_val

        def _process_function_array(array, array_size, target_list):
            if self._elffile.elfclass == 32:
                fmt = '<I'
                pointer_size = 4
            else:
                fmt = '<Q'
                pointer_size = 8
            cur_offset = array
            while cur_offset < array + array_size:
                self.fd.seek(cur_offset)
                target_list.append(struct.unpack(fmt, self.fd.read(pointer_size))[0] - self.load_offset)
                cur_offset += pointer_size

        if init_array is not None and init_arraysz != 0:
            logging.debug('DT_INIT_ARRAY at %x, length %d', init_array, init_arraysz)
            _process_function_array(init_array, init_arraysz, self.init_functions)

        if fini_array is not None and fini_arraysz != 0:
            logging.debug('DT_FINI_ARRAY at %x, length %d', fini_array, fini_arraysz)
            _process_function_array(fini_array, fini_arraysz, self.fini_functions)

    def _get_addend(self, reloc):
        if reloc.is_RELA():
            return reloc['r_addend']
        else:
            # R_386_RELATIVE (or more precisely, DT_REL type) relocations
            # store an implicit addend at the location of the relocation
            # entry so we need to access that offset
            target = reloc['r_offset']
            off = next(self._elffile.address_offsets(target))
            self.fd.seek(off)
            addend = struct.unpack('<I', self.fd.read(4))[0]
            logging.debug('Relocation for offset %x has addend %x',
                          target, addend)
            return addend

    def parse_plt(self):
        if self.is_i386():
            relaplt = self._elffile.get_section_by_name('.rel.plt')
        else:
            relaplt = self._elffile.get_section_by_name('.rela.plt')
        if not relaplt:
            relaplt = self._create_mock_rela_plt()
        plt = self._elffile.get_section_by_name('.plt.sec')
        if not plt:
            plt = self._elffile.get_section_by_name('.plt')
        if not plt:
            plt = self._search_for_plt()
        dynsym = self._get_dynsym()
        if relaplt and plt and dynsym:
            plt_base = plt['sh_offset']

            if self.is_aarch64():
                increment = 16
                # The offset of the first real PLT entry is actually 32 bytes
                # but we increment in the loop before accessing the entry.
                plt_offset = 16
                # For 32 bit ARM, this would be increment 12, plt_offset 8
            else:
                # On x86 32-bit binaries, sh_entsize might be 4 even though an
                # entry in the .plt is in fact 16 bytes long, so round up to
                # sh_addralign (see https://reviews.llvm.org/D9560).
                increment = _round_up_to_alignment(plt['sh_entsize'], plt['sh_addralign'])
                if plt.name == '.plt.sec':
                    # .plt.sec does not contain a special first entry so the
                    # first entry (after incrementing) starts at offset 0.
                    plt_offset = -increment
                else:
                    plt_offset = 0

            for reloc in sorted(relaplt.iter_relocations(), key=lambda rel: rel['r_offset']):
                # The first entry in .plt is special, it contains the logic for
                # all other entries to jump into the loader. Real functions come
                # after that.
                plt_offset += increment

                symbol = None
                symbol_index = reloc['r_info_sym']
                if (self.is_i386() and reloc['r_info_type'] == ENUM_RELOC_TYPE_i386['R_386_IRELATIVE']) or \
                   (self.is_x86_64() and reloc['r_info_type'] == ENUM_RELOC_TYPE_x64['R_X86_64_IRELATIVE']):
                    # Locate a pyelftools Symbol object with the an offset equal
                    # to reloc['r_addend'], based on the symbol names. This is
                    # quite paranoid, for regular cases the following should
                    # be enough, but with symbol versioning get_symbol_by_name()
                    # could return different offsets for the same function name:
                    # symbol = dynsym.get_symbol_by_name(unversioned_names[0])[0]
                    addend = self._get_addend(reloc)
                    sym_names = self.exported_addrs[addend]
                    if sym_names:
                        unversioned_names = [x.split('@@')[0] for x in sym_names]
                        symbols = [sym for name in unversioned_names
                                   for sym in dynsym.get_symbol_by_name(name)]
                        symbol = next(sym for sym in symbols
                                      if self._get_symbol_offset(sym) == addend)
                elif hasattr(dynsym, 'get_symbol'):
                    if symbol_index < dynsym.num_symbols():
                        symbol = dynsym.get_symbol(symbol_index)
                else:
                    symbol_list = list(dynsym.iter_symbols())
                    if symbol_index < len(symbol_list):
                        symbol = symbol_list[symbol_index]
                if not symbol or not symbol.name:
                    continue

                plt_addr = plt_base + plt_offset
                if symbol['st_shndx'] == 'SHN_UNDEF':
                    self.imports_plt[plt_addr] = \
                        self._get_versioned_name(symbol, symbol_index)
                else:
                    self.exports_plt[plt_addr] = \
                        self._get_symbol_offset(symbol)
        else:
            logging.debug('missing sections (.rel{a}.plt, .plt., .dynsym) for %s',
                          self.fullname)

    def parse_plt_got(self):
        if not self.is_i386() and not self.is_x86_64():
            return

        pltgot = self._elffile.get_section_by_name('.plt.got')
        if not pltgot:
            return

        entrysize = _round_up_to_alignment(pltgot['sh_entsize'],
                                           pltgot['sh_addralign'])
        count = pltgot['sh_size'] // entrysize

        # We only need the .got/.got.plt offset for 32 bit binaries
        if self.is_i386():
            got = self._elffile.get_section_by_name('.got.plt')
            if not got:
                got = self._elffile.get_section_by_name('.got')
            if not got:
                logging.debug('no .got section found')
                return

        # The names are different for 32 vs 64 bit binaries
        if self.is_i386():
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
            if self.is_i386():
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
                if symbol['st_shndx'] == 'SHN_UNDEF':
                    self.imports_plt[cur_entry] = \
                        self._get_versioned_name(symbol, symbol_index)
                else:
                    self.exports_plt[cur_entry] = \
                        self._get_symbol_offset(symbol)

    def parse_rela_dyn(self):
        if self.is_i386():
            dynrel = self._elffile.get_section_by_name('.rel.dyn')
        else:
            dynrel = self._elffile.get_section_by_name('.rela.got')
            if not dynrel:
                dynrel = self._elffile.get_section_by_name('.rela.dyn')
        if not dynrel:
            return
        dynsym = self._get_dynsym()
        if not dynsym:
            return
        if self.is_i386():
            target_reloc_type = ENUM_RELOC_TYPE_i386['R_386_GLOB_DAT']
            fptr_reloc_type = ENUM_RELOC_TYPE_i386['R_386_RELATIVE']
            ptr_reloc_type = ENUM_RELOC_TYPE_i386['R_386_32']
        elif self.is_x86_64():
            target_reloc_type = ENUM_RELOC_TYPE_x64['R_X86_64_GLOB_DAT']
            fptr_reloc_type = ENUM_RELOC_TYPE_x64['R_X86_64_RELATIVE']
            ptr_reloc_type = ENUM_RELOC_TYPE_x64['R_X86_64_64']
        else:
            target_reloc_type = ENUM_RELOC_TYPE_AARCH64['R_AARCH64_GLOB_DAT']
            fptr_reloc_type = ENUM_RELOC_TYPE_AARCH64['R_AARCH64_RELATIVE']
            ptr_reloc_type = None

        sorted_obj_ranges = sorted(self.object_ranges.keys())
        for reloc in dynrel.iter_relocations():
            got_offset = reloc['r_offset']
            symbol_idx = reloc['r_info_sym']
            reloc_type = reloc['r_info_type']
            if reloc_type in (target_reloc_type, ptr_reloc_type):
                symbol = dynsym.get_symbol(symbol_idx)
                obj = False
                if symbol['st_info']['type'] == 'STT_OBJECT':
                    obj = True
                if not obj and symbol['st_info']['type'] != 'STT_FUNC':
                    continue

                if symbol['st_shndx'] == 'SHN_UNDEF':
                    if obj:
                        target = self.imported_objs
                    else:
                        target = self.imports_plt
                    target[got_offset] = self._get_versioned_name(symbol,
                                                                  symbol_idx)
                    if obj:
                        self.imported_objs_locations[target[got_offset]] = None
                else:
                    # Relocations might point into the middle of an object,
                    # so we fix up the offset to the beginning of the
                    # corresponding object to mark the reference
                    orig_offset = got_offset
                    start_of_object = True
                    ins_point = bisect.bisect(sorted_obj_ranges, got_offset)
                    if ins_point != 0:
                        left_offset = sorted_obj_ranges[ins_point-1]
                        start, size = (left_offset, self.object_ranges[left_offset])
                        if start != got_offset and got_offset in range(start, start + size):
                            logging.debug('fix offset %x to object at %x',
                                          got_offset, start)
                            got_offset = start
                            start_of_object = False

                    if obj:
                        # References from the code might be to relocation address
                        # in the GOT, so we add a pseudo entry to exported_objs
                        # which represents the underlying symbol. But we only
                        # need to do this if the relocation did not point into
                        # another object and the name did not exist previously
                        if start_of_object and got_offset not in self.exported_objs:
                            self.exported_objs[got_offset].append(self._get_versioned_name(symbol, symbol_idx))
                        # Additionally, we mark a connection between the GOT
                        # enty and the object behind it
                        self.object_to_objects[got_offset].add(symbol['st_value'])
                    else:
                        self.object_to_functions[got_offset].add(self._get_symbol_offset(symbol))
                        self.exports_plt[orig_offset] = self._get_symbol_offset(symbol)

        # This needs to be in a separate loop as the other relocation types
        # might have added entries to self.exported_objs, and the relocations
        # processed in this loop might reference such new entries.
        for reloc in dynrel.iter_relocations():
            got_offset = reloc['r_offset']
            reloc_type = reloc['r_info_type']
            if reloc_type == fptr_reloc_type:
                location = self._get_addend(reloc)
                ins_point = bisect.bisect(sorted_obj_ranges, got_offset)
                if ins_point != 0:
                    left_offset = sorted_obj_ranges[ins_point-1]
                    start, size = (left_offset, self.object_ranges[left_offset])
                    if got_offset not in range(start, start + size):
                        continue
                    if location in self.exported_addrs:
                        self.object_to_functions[start].add(location)
                        self.reloc_to_exported[got_offset] = location
                    elif location in self.local_functions:
                        self.object_to_functions[start].add(location)
                        self.reloc_to_local[got_offset] = location
                    elif location in self.exported_objs or \
                            location in self.local_objs:
                        self.object_to_objects[start].add(location)


    def parse_versions(self):
        versions = self._elffile.get_section_by_name('.gnu.version')
        if not versions:
            return

        idx_to_names = {}

        # Parse version definitions for version index -> name mapping
        verdefs = self._elffile.get_section_by_name('.gnu.version_d')
        if verdefs:
            self.defines_versions = True
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
            if version_idx == 'VER_NDX_GLOBAL':
                version_idx = 1
            if isinstance(version_idx, int):
                self._version_indices[idx] = version_idx

    def parse_symtab(self):
        external_elf = None
        external_path = None
        build_id = None
        symtab = self._elffile.get_section_by_name('.symtab')
        if not symtab:
            logging.debug('looking for external file with .symtab')
            paths = [os.path.join(DEBUG_DIR, self.fullname[1:])]
            if EXTERNAL_DEBUG_DIR:
                for debug_path in EXTERNAL_DEBUG_DIR.split(':'):
                    paths.insert(0, os.path.join(debug_path, self.fullname[1:]))
                    paths.insert(1, os.path.join(debug_path,
                                                 self.fullname[1:] + '.debug'))
                    paths.insert(2, os.path.join(debug_path,
                                                 os.path.basename(self.fullname)))
                    paths.insert(3, os.path.join(debug_path,
                                                 os.path.basename(self.fullname) + '.debug'))
            id_section = self._elffile.get_section_by_name('.note.gnu.build-id')
            if id_section:
                for note in id_section.iter_notes():
                    if note['n_type'] != 'NT_GNU_BUILD_ID':
                        continue
                    build_id = note['n_desc']
                    build_id_folder = build_id[:2]
                    build_id_file = build_id[2:] + '.debug'
                    paths.insert(0, os.path.join(BUILDID_DIR, build_id_folder,
                                                 build_id_file))
                    if EXTERNAL_BUILDID_DIR:
                        paths.insert(0, os.path.join(EXTERNAL_BUILDID_DIR,
                                                     build_id_folder,
                                                     build_id_file))

            for path in paths:
                if not os.path.isfile(path):
                    continue
                try:
                    external_elf = ELFFile(open(path, 'rb'))
                    symtab = external_elf.get_section_by_name('.symtab')
                    if symtab:
                        external_path = path
                        break
                except (ELFError, OSError) as err:
                    logging.debug('Failed to open external symbol table for %s at %s: %s',
                                  self.fullname, path, err)
                    continue

        # If local paths failed, try debuginfod if requested
        if not symtab and USE_DEBUGINFOD and build_id:
            logging.debug('No local .symtab file, trying to query debuginfod')
            try:
                with DebugInfoD() as debuginfod:
                    fd, path = debuginfod.find_debuginfo(build_id)
                    if fd > 0:
                        external_elf = ELFFile(os.fdopen(fd, 'rb'))
                        symtab = external_elf.get_section_by_name('.symtab')
                        external_path = path
            except (ELFError, OSError, FileNotFoundError) as e:
                logging.debug('debuginfod query failed: %s', e)

        if not symtab:
            return False
        else:
            logging.debug('Found external symtab for %s at %s', self.fullname,
                          external_path)

        sorted_ranges = sorted(self.ranges.items())
        for _, symbol in self._get_function_symbols(symtab, prefix_local=True):
            shndx = symbol['st_shndx']
            if shndx != 'SHN_UNDEF':
                start = self._get_symbol_offset(symbol)
                self.function_addrs.add(start)
                size = symbol['st_size']
                if start not in self.exported_addrs:
                    # Check if this function overlapping with another function
                    ins_point = bisect.bisect(sorted_ranges, (start, size))
                    if ins_point != 0:
                        prev_start, prev_size = sorted_ranges[ins_point-1]
                        if start in range(prev_start, prev_start + prev_size) \
                                and prev_start != start:
                            prev_name = ''
                            if prev_start in self.exported_addrs:
                                prev_name = self.exported_addrs[prev_start]
                            elif prev_start in self.local_functions:
                                prev_name = self.local_functions[prev_start]
                            symbol_bind = symbol['st_info']['bind']
                            if symbol_bind == 'STB_LOCAL':
                                self.local_calls[prev_start].add(start)
                                logging.debug('local function \'%s\' inside symbol \'%s\'' \
                                              ', %x:%d contains %x:%d', symbol.name,
                                              prev_name, prev_start, prev_size,
                                              start, size)
                    size = symbol['st_size']
                    name = symbol.name
                    if symbol.name == 'main':
                        self.export_users[start] = set()
                        self.export_bind[name] = 'STB_GLOBAL'
                        self.exported_names[name] = start
                        self.exported_addrs[start].append(name)
                    else:
                        if name == '_init':
                            size = self._fixup_init_size(symbol, size, shndx)
                            self.init_functions.append(start)
                        elif name == '_fini':
                            size = self._fixup_fini_size(symbol, size, shndx)
                            self.fini_functions.append(start)
                        self.local_functions[start].append(name)
                        self.local_users[start] = set()
                    self.ranges[start] = size
                    bisect.insort(sorted_ranges, (start, size))

        for idx, symbol in self._get_object_symbols(symtab, prefix_local=True):
            shndx = symbol['st_shndx']
            symbol_bind = symbol['st_info']['bind']
            if shndx == 'SHN_UNDEF':
                name = self._get_versioned_name(symbol, idx)
                if isinstance(name, bytes):
                    name = name.decode('utf-8')
                pass
                #TODO: what to do here?
                #self.imported_objs_locations[name] = None
            else:
                addr = symbol['st_value']
                if not addr:
                    continue
                if symbol_bind in ('STB_GLOBAL', 'STB_WEAK', 'STB_LOOS'):
                    name = symbol.name
                    size = symbol['st_size']
                    if addr not in self.exported_objs:
                        self.exported_objs[addr].append(name)
                        self.exported_obj_names[name] = addr
                        self.object_ranges[addr] = max(self.object_ranges.get(addr, 0), size)
                elif symbol_bind == 'STB_LOCAL':
                    self.local_objs[addr].append(symbol.name)
                    # Names are not unique for local objects!
                    self.object_ranges[addr] = max(self.object_ranges.get(addr, 0), symbol['st_size'])

        if external_elf:
            external_elf.stream.close()
            del external_elf

        return True

    def get_capstone_object(self):
        # Create a Cs object with the right machine type
        arch = capstone.CS_ARCH_X86
        if self.is_x86_64():
            mode = capstone.CS_MODE_64
        elif self.is_i386():
            mode = capstone.CS_MODE_32
        elif self.is_aarch64():
            arch = capstone.CS_ARCH_ARM64
            mode = capstone.CS_MODE_ARM

        cs_obj = capstone.Cs(arch, mode)
        cs_obj.detail = True
        return cs_obj

    def _postprocess_ranges(self):
        # Check the gaps between recognized functions. If they only consist of
        # NOPs, extend the previous function to include the NOPs as well and
        # hence close the 'useless' gap between consecutive functions.
        ranges_list = sorted(self.ranges.items())
        for idx, (start, size) in enumerate(ranges_list[:-1]):
            cur_end = start + size
            next_start = ranges_list[idx + 1][0]
            gap = next_start - cur_end
            if gap < 0:
                logging.debug('possibly overlapping functions at %x:%d/%x',
                              start, size, next_start)
            elif gap > 0:
                only_nops = True

                cs_obj = self.get_capstone_object()
                self.fd.seek(cur_end)
                code = self.fd.read(gap)
                disas = list(cs_obj.disasm(code, start))

                if sum(instr.size for instr in disas) != gap:
                    logging.debug('error disassembling NOPs at %x:%d, continuing',
                                  cur_end, gap)
                    continue

                for instr in disas:
                    if instr.mnemonic != 'nop':
                        only_nops = False
                        break

                if only_nops:
                    logging.debug('fixing nop gap at %x: %d bytes', cur_end, gap)
                    self.ranges[start] += gap

    def parse_functions(self, release=False):
        self.parse_versions()
        self.parse_dynamic()
        self.parse_dynsym()
        self.parse_plt()
        self.parse_plt_got()
        has_symtab = self.parse_symtab()
        self.parse_rela_dyn()
        if self.entrypoint:
            self.function_addrs.add(self.entrypoint)
        if has_symtab:
            self._postprocess_ranges()
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

    def add_export_user(self, addr, user_path):
        if addr not in self.export_users:
            if addr in self.local_functions:
                logging.debug('%s: adding user to local function %x: %s',
                              self.fullname, addr, user_path)
                if addr not in self.local_users:
                    self.local_users[addr] = set()
                if user_path not in self.local_users[addr]:
                    self.local_users[addr].add(user_path)
                    return True
            else:
                logging.error('%s not found in %s (user would be %s)', addr,
                              self.fullname, user_path)
        elif user_path not in self.export_users[addr]:
            logging.debug('%s: adding user to export function %x: %s',
                          self.fullname, addr, user_path)
            self.export_users[addr].add(user_path)
            return True
        return False

    def add_object_user(self, addr, user_path):
        if addr not in self.object_users:
            self.object_users[addr] = set()
        if user_path not in self.object_users[addr]:
            self.object_users[addr].add(user_path)

    def get_users_by_name(self, name):
        addr = self.find_export(name)
        if not addr:
            return []
        return self.export_users.get(addr, [])

    def find_object(self, requested_name):
        if requested_name in self.exported_obj_names:
            return self.exported_obj_names[requested_name]
        for name, addr in self.exported_obj_names.items():
            if name.split('@@')[0] == requested_name:
                return addr

        if requested_name.split('@@')[0] in self.exported_obj_names:
            return self.exported_obj_names[requested_name.split('@@')[0]]
        return None

    def find_local_functions(self, requested_name):
        return set(addr for addr, names in self.local_functions.items() \
                   if requested_name in names)

    def find_export(self, requested_name):
        # Direct match, name + version
        if requested_name in self.exported_names:
            return self.exported_names[requested_name]
        # No version requested, but version defined
        # TODO: check uniqueness of split name
        for name, addr in self.exported_names.items():
            if name.split('@@')[0] == requested_name:
                return addr
        # Version requested, but no version defined -> base version
        if requested_name.split('@@')[0] in self.exported_names:
            return self.exported_names[requested_name.split('@@')[0]]
        return None

    def _get_names_for_addrs(self, addrs, name_dict):
        return set(name for addr in addrs for name in name_dict[addr])

    def get_used_exported_functions(self):
        return set(addr for addr, users in self.export_users.items() if users)

    def get_used_exported_function_names(self):
        return self._get_names_for_addrs(self.get_used_exported_functions(),
                                         self.exported_addrs)

    def get_unused_exported_functions(self):
        return set(addr for addr in self.exported_addrs \
                   if not self.export_users.get(addr, set()))

    def get_unused_exported_function_names(self):
        return self._get_names_for_addrs(self.get_unused_exported_functions(),
                                         self.exported_addrs)

    def get_used_local_functions(self):
        return set(addr for addr, users in self.local_users.items() if users)

    def get_used_local_function_names(self):
        return self._get_names_for_addrs(self.get_used_local_functions(),
                                         self.local_functions)

    def get_unused_local_functions(self):
        return set(addr for addr in self.local_functions \
                   if not self.local_users.get(addr, set()))

    def get_unused_local_function_names(self):
        return self._get_names_for_addrs(self.get_unused_local_functions(),
                                         self.local_functions)

    def get_function_ranges(self):
        return self.ranges

    def summary(self):
        return '{}: {} imports, {} exports, {} needed libs, ' \
                   '{} rpaths, {} runpaths' \
                   .format(self.fullname, len(self.imports),
                           len(self.exported_names), len(self.needed_libs),
                           len(self.rpaths), len(self.runpaths))

    def __str__(self):
        return self.summary()
