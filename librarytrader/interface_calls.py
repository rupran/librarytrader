#!/usr/bin/env python3
#
# Copyright 2018, Andreas Ziegler <andreas.ziegler@fau.de>
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

from bisect import bisect_right
from collections import defaultdict
from distutils.spawn import find_executable
import logging
import multiprocessing
import os
import re
import subprocess
import sys
import time

import capstone
from elftools.common.exceptions import ELFError
from elftools.common.utils import parse_cstring_from_stream

# In order to be able to use librarytrader from git without having installed it,
# add top level directory to PYTHONPATH
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..'))

from librarytrader.library import Library

def disassemble_objdump(library, start, length, obj=None):
    disassembly = []
    if length == 0:
        return (disassembly, find_calls_from_objdump)

    # objdump requires addresses, not offsets
    start += library.load_offset

    objdump_prefix = ''
    if library.is_aarch64():
        objdump_prefix = 'aarch64-linux-gnu-'
    elif library.is_i386() or library.is_x86_64():
        objdump_prefix = 'x86_64-linux-gnu-'
    objdump = '{}objdump'.format(objdump_prefix)

    if find_executable(objdump) is None:
        logging.warning('%s does not exist, using generic path', objdump)
        objdump = 'objdump'

    cmdline = [objdump, '-d', '--no-show-raw-insn',
               '--start-address={}'.format(hex(start)),
               '--stop-address={}'.format(hex(start + length)),
               library.fullname]
    proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE)
    out, _ = proc.communicate()
    instrs = out.decode().split('\n')[7:-1]
    for instr in instrs:
        try:
            pre, post = instr.split('\t')
            addr = pre[:-1].lstrip()
            decoded = post
            disassembly.append((addr, decoded))
        except ValueError as err:
            logging.error('%s %s %d %d %s', library.fullname, instr, start,
                                            length, err)

    return (disassembly, find_calls_from_objdump)

def find_calls_from_objdump(library, disas):
    calls_to_exports = set()
    calls_to_imports = set()
    calls_to_locals = set()

    if library.is_aarch64():
        logging.error('objdump for AArch64 not supported yet!')
        return (calls_to_exports, calls_to_imports, calls_to_locals)
    elif library.is_i386() or library.is_x86_64():
        CALL_REGEX = re.compile(r'^call[q]?\s+([0-9a-f]+).*$')
        JMP_REGEX = re.compile(r'^jmp[q]?\s+([0-9a-f]+).*$')
        JNE_REGEX = re.compile(r'^j[n]?e\s+([0-9a-f]+).*$')

    for _, decoded in disas:
        match = CALL_REGEX.match(decoded)
        if not match:
            match = JMP_REGEX.match(decoded)
        if not match:
            match = JNE_REGEX.match(decoded)

        if match:
            # Symbols are offsets into the file, so we need to subtract the
            # load_offset from the call target again to properly match it
            target = int(match.group(1), 16) - library.load_offset
            if target in library.exported_addrs:
                calls_to_exports.add(target)
            elif target in library.exports_plt:
                calls_to_exports.add(library.exports_plt[target])
            elif target in library.imports_plt:
                calls_to_imports.add(library.imports_plt[target])
            elif target in library.local_functions:
                calls_to_locals.add(target)

    return (calls_to_exports, calls_to_imports, calls_to_locals, {}, {}, {},
            {}, {}, {})

def disassemble_capstone(library, start, length, cs_obj):
    disassembly = []
    if length == 0:
        return (disassembly, find_calls_from_capstone)

    # Seek to right address and get code bytes
    library.fd.seek(start)
    code = library.fd.read(length)

    disas = list(cs_obj.disasm(code, start))

    # If capstone didn't disassemble everything, try objdump instead
    if len(code) != sum(instr.size for instr in disas):
        logging.warning('incomplete disassembly for %s:%x: %d/%d bytes!',
                        library.fullname, start,
                        sum(instr.size for instr in disas), len(code))
        return disassemble_objdump(library, start, length)

    return (disas, find_calls_from_capstone)

def _locate_parameter(library, disas, start_idx, target_register, mem_tag):
    retval = None
    idx = start_idx
    while idx > 0:
        idx -= 1
        earlier_insn = disas[idx]
        read, written = earlier_insn.regs_access()
        if target_register not in written:
            continue
        elif earlier_insn.id != capstone.x86_const.X86_INS_LEA:
            break
        # Here we know it was a <lea ..., %rsi>, and these
        # accesses will mostly be RIP-relative on x86_64 so we only support
        # <lea xxx(%rip), %rsi> for now.
        to, val = list(earlier_insn.operands)
        if val.type == mem_tag and val.value.mem.base == capstone.x86.X86_REG_RIP:
            stroff = earlier_insn.address + val.value.mem.disp + earlier_insn.size
            # Does this need library._elffile.address_offsets()?
            # In mariadb's glibc, .rodata is 1:1 mapped...
            strval = parse_cstring_from_stream(library.fd, stroff)
            retval = strval.decode('utf-8')
            break
    return retval

def find_calls_from_capstone(library, disas):
    calls_to_exports = set()
    calls_to_imports = set()
    calls_to_locals = set()
    indirect_calls = set()
    imported_object_refs = set()
    exported_object_refs = set()
    local_object_refs = set()
    dlsym_refs = set()
    dlopen_refs = set()
    if library.is_aarch64():
        call_group = capstone.arm64_const.ARM64_GRP_CALL
        jump_group = capstone.arm64_const.ARM64_GRP_JUMP
        imm_tag = capstone.arm64.ARM64_OP_IMM
        mem_tag = None #TODO: not implemented
    elif library.is_i386() or library.is_x86_64():
        call_group = capstone.x86_const.X86_GRP_CALL
        jump_group = capstone.x86_const.X86_GRP_JUMP
        imm_tag = capstone.x86.X86_OP_IMM
        mem_tag = capstone.x86.X86_OP_MEM
    else:
        logging.error('Unsupported machine type: %s', library.elfheader['e_machine'])
        return (calls_to_exports, calls_to_imports, calls_to_locals)

    thunk_reg = None
    thunk_val = None

    for idx, instr in enumerate(disas):
        if instr.group(call_group) or instr.group(jump_group):
            operand = instr.operands[-1]
            if operand.type == imm_tag:
                target = operand.value.imm
            elif operand.type == mem_tag and \
                    operand.value.mem.base == capstone.x86.X86_REG_RIP:
                target = instr.address + operand.value.mem.disp + instr.size
            else:
                indirect_calls.add((instr.address, '{} {}'.format(instr.mnemonic, instr.op_str)))
                continue
            if target in library.exported_addrs:
                for name in library.exported_addrs[target]:
                    if 'dlsym' in name:
                        logging.debug('%s: call to %s at offset %x',
                                      library.fullname, name, instr.address)
                        param = _locate_parameter(library, disas, idx,
                                                  capstone.x86_const.X86_REG_RSI,
                                                  mem_tag)
                        if param:
                            dlsym_refs.add(param)
                        break
                    elif 'dlopen' in name:
                        param = _locate_parameter(library, disas, idx,
                                                capstone.x86_const.X86_REG_RDI,
                                                mem_tag)
                        if param:
                            dlopen_refs.add(param)
                        break
                calls_to_exports.add(target)
            elif target in library.exports_plt:
                calls_to_exports.add(library.exports_plt[target])
            elif target in library.imports_plt:
                if 'dlsym' in library.imports_plt[target]:
                    logging.debug('%s: call to imported %s at offset %x',
                                  library.fullname, library.imports_plt[target],
                                  instr.address)
                    param = _locate_parameter(library, disas, idx,
                                              capstone.x86_const.X86_REG_RSI,
                                              mem_tag)
                    if param:
                        dlsym_refs.add(param)
                elif 'dlopen' in library.imports_plt[target]:
                    param = _locate_parameter(library, disas, idx,
                                              capstone.x86_const.X86_REG_RDI,
                                              mem_tag)
                    if param:
                        dlopen_refs.add(param)
                calls_to_imports.add(library.imports_plt[target])
            elif target in library.local_functions:
                # Note: this might only work for gcc-compiled libraries, as
                # clang sometimes uses the 'call next address + pop <thunk_reg>'
                # pattern to load the thunk register
                if '__x86.get_pc_thunk.ax' in library.local_functions[target]:
                    thunk_reg = capstone.x86.X86_REG_EAX
                    thunk_val = instr.address + instr.size
                elif '__x86.get_pc_thunk.bx' in library.local_functions[target]:
                    thunk_reg = capstone.x86.X86_REG_EBX
                    thunk_val = instr.address + instr.size
                elif '__x86.get_pc_thunk.cx' in library.local_functions[target]:
                    thunk_reg = capstone.x86.X86_REG_ECX
                    thunk_val = instr.address + instr.size
                elif '__x86.get_pc_thunk.dx' in library.local_functions[target]:
                    thunk_reg = capstone.x86.X86_REG_EDX
                    thunk_val = instr.address + instr.size
                calls_to_locals.add(target)
            elif target in library.reloc_to_local:
                calls_to_locals.add(library.reloc_to_local[target])
            elif target in library.reloc_to_exported:
                calls_to_exports.add(library.reloc_to_exported[target])
            else:
                # Some handwritten assembly code might jump into a function
                # range (for example, to skip the function prologue).
                i = bisect_right(library.sorted_ranges, (target,))
                # lower and upper bound
                if i == 0 or i == len(library.sorted_ranges) + 1:
                    continue
                start, size = library.sorted_ranges[i-1]
                # jump into same range we're coming from
                if instr.address in range(start, start + size):
                    continue
                # jump goes somewhere close to the target but outside the given
                # size (happens for libgcc)
                if target not in range(start, start + size):
                    continue
                if start in library.local_functions:
                    calls_to_locals.add(start)
                elif start in library.exported_addrs:
                    calls_to_exports.add(start)
                else:
                    continue
                logging.debug('%s: jump into function! %x -> %x (inside %x:%d)',
                              library.fullname, instr.address, target, start,
                              size)
        elif mem_tag is not None:
            mem_through_thunk = None
            if thunk_reg is not None:
                read, written = instr.regs_access()
                if thunk_reg in read:
                    # If we're adding to the thunk register...
                    if instr.id == capstone.x86_const.X86_INS_ADD:
                        target, val = list(instr.operands)
                        # ... and the addend is an immediate, update the
                        # current value of the thunk register
                        if target.type == capstone.x86.X86_OP_REG and \
                                target.reg == thunk_reg and \
                                val.type == capstone.x86.X86_OP_IMM:
                            thunk_val += val.imm
                            continue
                    # otherwise, if we're using the thunk register in a mov
                    # oder lea instruction....
                    elif instr.id == capstone.x86_const.X86_INS_MOV or \
                            instr.id == capstone.x86_const.X86_INS_LEA:
                        target, val = list(instr.operands)
                        # if the base register is the thunk register, calculate
                        # and save the accessed address for use below
                        if val.type == capstone.x86.X86_OP_MEM and \
                                val.mem.base == thunk_reg:
                            mem_through_thunk = thunk_val + val.mem.disp
                # Reset the thunk register if it is written to
                if thunk_reg in written:
                    thunk_reg = None
                    thunk_val = 0

            # detect memory references relative to RIP -> function pointers
            for operand in instr.operands:
                # Immediate accesses can directly be used
                if operand.type == capstone.x86.X86_OP_IMM:
                    addr = operand.value.imm - library.load_offset
                # Accesses relative to RIP need to be calculated with respect
                # to the address of the current instruction. As the offset is
                # always relative to the *next* instruction, we also need to
                # add the size of the current instruction
                elif operand.type == mem_tag and \
                        operand.value.mem.base == capstone.x86.X86_REG_RIP:
                    addr = instr.address + operand.value.mem.disp + instr.size
                # Lastly, if we had an access through a thunk register, use the
                # value calculated above and reset the access - otherwise, we
                # have unnecessary duplicate overhead (for all operands).
                elif mem_through_thunk:
                    addr = mem_through_thunk
                    # Reset mem_through_thunk as we already determined the
                    # target address in the thunk evaluation above
                    mem_through_thunk = None
                else:
                    continue
                if addr in library.exported_addrs:
                    calls_to_exports.add(addr)
                elif addr in library.local_functions:
                    calls_to_locals.add(addr)
                elif addr in library.imports_plt:
                    calls_to_imports.add(library.imports_plt[addr])
                elif addr in library.exported_objs:
                    exported_object_refs.add(addr)
                elif addr in library.imported_objs:
                    imported_object_refs.add(addr)
                elif addr in library.local_objs:
                    local_object_refs.add(addr)

    return (calls_to_exports, calls_to_imports, calls_to_locals, indirect_calls,
            imported_object_refs, exported_object_refs, local_object_refs,
            dlsym_refs, dlopen_refs)

def resolve_calls_in_library(library, start, size, disas_function=disassemble_capstone):
    logging.debug('Processing %s:%x', library.fullname, start)
    before = time.time()

    cs_obj = library.get_capstone_object()

    indir = {}
    disas, resolution_function = disas_function(library, start, size, cs_obj)
    calls_to_exports, calls_to_imports, calls_to_locals, indirect_calls, \
        uses_of_imports, uses_of_exports, uses_of_locals, dlsym_refs, \
        dlopen_refs = resolution_function(library, disas)

    indir[start] = indirect_calls

    after = time.time()
    return (calls_to_exports, calls_to_imports, calls_to_locals, indir,
            uses_of_imports, uses_of_exports, uses_of_locals, dlsym_refs,
            dlopen_refs, (after - before))

def map_wrapper(input_tuple):
    path, start, size = input_tuple
    try:
        if isinstance(path, str):
            lib = Library(path, parse=True)
        else:
            lib = path
            lib.fd = open(lib.fullname, 'rb')
    except Exception as err:
        logging.error('%s: %s', lib.fullname, err)
        return (None, -1, None, None, None, None, None, None, None, None, None, 0)

    internal_calls, external_calls, local_calls, indirect_calls, \
        imported_uses, exported_uses, local_uses, dlsym_refs, \
        dlopen_refs, duration = resolve_calls_in_library(lib, start, size)
    lib.fd.close()
    del lib.fd
    return (lib.fullname, start, internal_calls, external_calls, local_calls,
            indirect_calls, imported_uses, exported_uses, local_uses, dlsym_refs,
            dlopen_refs, duration)

def resolve_calls(store, n_procs=int(multiprocessing.cpu_count() * 1.5)):
    # Pass by path (-> threads have to reconstruct)
    #libs = [(lib.fullname, start, size) for lib in store.get_library_objects() \
    #            for start, size in lib.ranges.items()]
    # Pass by object (-> threads need to open only)
    logging.info('Searching for calls in %d libraries...', len(store.get_library_objects()))
    # Sort the range keys once to allow efficient searching for jumps into
    # function boundaries
    for lib in store.get_library_objects():
        lib.sorted_ranges = sorted(lib.ranges.items())

    pool = multiprocessing.Pool(n_procs)
    result = pool.imap_unordered(map_wrapper,
                                 ((lib, start, size) \
                                    for lib in store.get_library_objects() \
                                        for start, size in lib.ranges.items()),
                                 chunksize=2000)
    pool.close()

    indir = {}
    calls = 0
    for fullname, start, internal_calls, external_calls, local_calls, indirect_calls, \
            imported_uses, exported_uses, local_uses, dlsym_refs, dlopen_refs, \
            duration in result:
        if not fullname:
            continue
        store[fullname].internal_calls[start].update(internal_calls)
        store[fullname].external_calls[start].update(external_calls)
        store[fullname].local_calls[start].update(local_calls)
        store[fullname].import_object_refs[start].update(imported_uses)
        store[fullname].export_object_refs[start].update(exported_uses)
        store[fullname].local_object_refs[start].update(local_uses)
        if fullname not in indir:
            indir[fullname] = set()
        indir[fullname].update(indirect_calls)
        calls += len(internal_calls) + len(external_calls) + len(local_calls)
        store[fullname].dlsym_refs[start].update(dlsym_refs)
        store[fullname].dlopen_refs[start].update(dlopen_refs)
        store[fullname].total_disas_time += duration

    pool.join()
    # Clean up library objects
    for lib in store.get_library_objects():
        del lib.sorted_ranges
    logging.info('... done!')
    logging.info('total number of calls: %d', calls)
    logging.info('indirect calls: %d', sum(len(x) for x in indir.values()))
