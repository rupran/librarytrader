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
    if library.elfheader['e_machine'] == 'EM_AARCH64':
        objdump_prefix = 'aarch64-linux-gnu-'
    elif library.elfheader['e_machine'] == 'EM_386' or \
            library.elfheader['e_machine'] == 'EM_X86_64':
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

    if library.elfheader['e_machine'] == 'EM_AARCH64':
        logging.error('objdump for AArch64 not supported yet!')
        return (calls_to_exports, calls_to_imports, calls_to_locals)
    elif library.elfheader['e_machine'] == 'EM_386' or \
            library.elfheader['e_machine'] == 'EM_X86_64':
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

    return (calls_to_exports, calls_to_imports, calls_to_locals, {}, {}, {}, {})

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

def find_calls_from_capstone(library, disas):
    calls_to_exports = set()
    calls_to_imports = set()
    calls_to_locals = set()
    indirect_calls = set()
    imported_object_refs = set()
    exported_object_refs = set()
    local_object_refs = set()
    if library.elfheader['e_machine'] == 'EM_AARCH64':
        call_group = capstone.arm64_const.ARM64_GRP_CALL
        jump_group = capstone.arm64_const.ARM64_GRP_JUMP
        imm_tag = capstone.arm64.ARM64_OP_IMM
        mem_tag = None #TODO: not implemented
    elif library.elfheader['e_machine'] == 'EM_386' or \
            library.elfheader['e_machine'] == 'EM_X86_64':
        call_group = capstone.x86_const.X86_GRP_CALL
        jump_group = capstone.x86_const.X86_GRP_JUMP
        imm_tag = capstone.x86.X86_OP_IMM
        mem_tag = capstone.x86.X86_OP_MEM
    else:
        logging.error('Unsupported machine type: %s', library.elfheader['e_machine'])
        return (calls_to_exports, calls_to_imports, calls_to_locals)

    thunk_reg = None
    thunk_val = None

    for instr in disas:
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
                calls_to_exports.add(target)
            elif target in library.exports_plt:
                calls_to_exports.add(library.exports_plt[target])
            elif target in library.imports_plt:
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
            else:
                # Some handwritten assembly code might jump into a function
                # range (for example, to skip the function prologue).
                ranges = library.get_function_ranges()
                sorted_range = sorted(ranges.keys())
                i = bisect_right(sorted_range, target)
                # lower and upper bound
                if i == 0 or i == len(sorted_range) + 1:
                    continue
                start, size = (sorted_range[i-1], ranges[sorted_range[i-1]])
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
            imported_object_refs, exported_object_refs, local_object_refs)

def resolve_calls_in_library(library, disas_function=disassemble_capstone):
    logging.debug('Processing %s', library.fullname)
    before = time.time()
    internal_calls = defaultdict(set)
    external_calls = defaultdict(set)
    local_calls = defaultdict(set)
    ranges = library.get_function_ranges()
    imported_uses = defaultdict(set)
    exported_uses = defaultdict(set)
    local_uses = defaultdict(set)

    # Disassemble with the right machine type
    arch = capstone.CS_ARCH_X86
    mode = capstone.CS_MODE_64
    if library.elfheader['e_machine'] == 'EM_386':
        mode = capstone.CS_MODE_32
    if library.elfheader['e_machine'] == 'EM_AARCH64':
        arch = capstone.CS_ARCH_ARM64
        mode = capstone.CS_MODE_ARM

    cs_obj = capstone.Cs(arch, mode)
    cs_obj.detail = True

    indir = {}
    for start, size in ranges.items():
        disas, resolution_function = disas_function(library, start, size, cs_obj)
        calls_to_exports, calls_to_imports, calls_to_locals, indirect_calls, \
            uses_of_imports, uses_of_exports, uses_of_locals = resolution_function(library, disas)
        if calls_to_exports:
            internal_calls[start] = calls_to_exports
        if calls_to_imports:
            external_calls[start] = calls_to_imports
        if calls_to_locals:
            local_calls[start] = calls_to_locals
        if uses_of_imports:
            imported_uses[start] = uses_of_imports
        if uses_of_exports:
            exported_uses[start] = uses_of_exports
        if uses_of_locals:
            local_uses[start] = uses_of_locals

        indir[start] = indirect_calls

    after = time.time()
    duration = after - before
    logging.info('Thread %d: %s took %.3f s', os.getpid(),
                                              library.fullname,
                                              duration)
    return (internal_calls, external_calls, local_calls, indir,
            imported_uses, exported_uses, local_uses, (after - before))

def map_wrapper(path):
    try:
        if isinstance(path, str):
            lib = Library(path, parse=True)
        else:
            lib = path
            lib.fd = open(lib.fullname, 'rb')
    except Exception as err:
        logging.error('%s: %s', lib.fullname, err)
        return (None, None, None, None, None, None, None, None, 0)

    internal_calls, external_calls, local_calls, indirect_calls, \
        imported_uses, exported_uses, local_uses, duration = resolve_calls_in_library(lib)
    lib.fd.close()
    del lib.fd
    return (lib.fullname, internal_calls, external_calls, local_calls, indirect_calls,
            imported_uses, exported_uses, local_uses, duration)

def resolve_calls(store, n_procs=int(multiprocessing.cpu_count() * 1.5)):
    # Pass by path (-> threads have to reconstruct)
    #libs = [lib.fullname for lib in sorted(store.get_library_objects(),
    #                                       key=lambda x: -len(x.exported_addrs))]
    # Pass by object (-> threads need to open only)
    libs = [lib for lib in sorted(store.get_library_objects(),
                                  key=lambda x: -len(x.exported_addrs))]
    logging.info('Searching for calls in %d libraries...', len(libs))
    pool = multiprocessing.Pool(n_procs)
    result = pool.map(map_wrapper, libs, chunksize=1)
    pool.close()

    indir = {}

    for fullname, internal_calls, external_calls, local_calls, indirect_calls, \
            imported_uses, exported_uses, local_uses, _ in result:
        store[fullname].internal_calls = internal_calls
        store[fullname].external_calls = external_calls
        store[fullname].local_calls = local_calls
        store[fullname].import_object_refs = imported_uses
        store[fullname].export_object_refs = exported_uses
        store[fullname].local_object_refs = local_uses
        indir[fullname] = indirect_calls


    logging.info('... done!')
    longest = [(v[0], v[8]) for v in sorted(result, key=lambda x: -x[8])]
    logging.info(longest[:20])
    calls = 0
    for v in result:
        calls += len(v[1].values())
        calls += len(v[2].values())
        calls += len(v[3].values())
    logging.info('total number of calls: %d', calls)
#    logging.info('total number of calls: %d', sum(len(v[3].values()) +
#                                                  len(v[2].values()) +
#                                                  len(v[1].values())
#                                                  for v in result))
    #for p, i in sorted(indir.items(), key=lambda x: -len(x[1])):
    #    logging.info('indir[%s] = %d', p, len(i))
    logging.info('indirect calls: %d', sum(len(x) for x in indir.values()))
    return result
