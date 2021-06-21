#!/usr/bin/env python3

import os
import sys

from librarytrader.librarystore import LibraryStore

def format_node(library, addr):
    name = '{:x}'.format(addr)
    options = []
    # Category of nodes: local/static objects/functions
    if addr in library.init_functions:
        if addr in library.local_functions:
            name = library.local_functions[addr][0]
        elif addr in library.exported_addrs:
            name = library.exported_addrs[addr][0]
        options.append('shape=house')
    elif addr in library.local_functions:
        name = library.local_functions[addr][0]
        options.append('shape=box')
    elif addr in library.exported_addrs:
        name = library.exported_addrs[addr][0]
        options.append('shape=diamond')
    elif addr in library.local_objs:
        name = library.local_objs[addr][0]
        options.append('shape=ellipse')
    elif addr in library.exported_objs:
        name = library.exported_objs[addr][0]
        options.append('shape=hexagon')
    # Usage:
    if addr in library.object_users and library.object_users[addr]:
        options.append('color=green')
    elif addr in library.local_users and library.local_users[addr]:
        options.append('color=green')
    elif addr in library.export_users and library.export_users[addr]:
        options.append('color=green')
    options.append('label="{}"'.format(name))
    return '"{:x}" '.format(addr) + '[' + ', '.join(options) + ']'

def format_edge(library, source, target):
    retval = '"{:x}" -> "{:x}"'.format(source, target)
    source_used = False
    target_used = False
    if source in library.local_users and library.local_users[source]:
        source_used = True
    elif source in library.export_users and library.export_users[source]:
        source_used = True
    elif source in library.object_users and library.object_users[source]:
        source_used = True

    if source_used:
        if target in library.local_users and library.local_users[target]:
            target_used = True
        elif target in library.export_users and library.export_users[target]:
            target_used = True
        elif target in library.object_users and library.object_users[target]:
            target_used = True

    if target_used:
        retval += ' [color=green]'
    retval += '\n'
    return retval

def check_seen(library, addr, seen, outfd):
    if addr not in seen:
        seen.add(addr)
        outfd.write(format_node(library, addr) + '\n')

def print_edges(library, source, targets, seen, outfd):
    check_seen(library, source, seen, outfd)
    for target in targets:
        check_seen(library, target, seen, outfd)
        outfd.write(format_edge(library, source, target))

s = LibraryStore()
s.load(sys.argv[1])

for l in s.get_library_objects():
    outname = os.path.basename(l.fullname) + '.dot'

    with open(outname, 'w') as outfd:
        print('writing to {}'.format(outname))
        seen = set()
        seen_import = set()

        outfd.write('digraph D {' + '\n')

        for function in l.exported_addrs:
            outfd.write(format_node(l, function))
            outfd.write('\n')

        for function in l.local_functions:
            outfd.write(format_node(l, function))
            outfd.write('\n')

        for source, targets in l.local_calls.items():
            print_edges(l, source, targets, seen, outfd)

        for source, targets in l.internal_calls.items():
            print_edges(l, source, targets, seen, outfd)

        for source, targets in l.external_calls.items():
            check_seen(l, source, seen, outfd)
            for target in targets:
                if target not in seen_import:
                    seen_import.add(target)
                    outfd.write('"{}" [shape=doubleoctagon]'.format(target))
                outfd.write('"{:x}" -> "{}"'.format(source, target))
                outfd.write('\n')

        for source, targets in l.local_object_refs.items():
            print_edges(l, source, targets, seen, outfd)

        for source, targets in l.object_to_functions.items():
            if source in l.exports_plt:
                continue
            print_edges(l, source, targets, seen, outfd)

        for f in l.init_functions:
            check_seen(l, f, seen, outfd)

        outfd.write('}' + '\n')
