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

def maybe_print_node(library, addr, seen, outfd):
    if addr not in seen:
        seen.add(addr)
        outfd.write(format_node(library, addr) + '\n')

def print_edges(library, source, targets, seen, seen_edges, outfd):
    maybe_print_node(library, source, seen, outfd)
    for target in targets:
        maybe_print_node(library, target, seen, outfd)
        if (source, target) not in seen_edges:
            seen_edges.add((source, target))
            outfd.write(format_edge(library, source, target))


s = LibraryStore()
s.load(sys.argv[1])
lname = sys.argv[2]
addr = int(sys.argv[3])
depth = int(sys.argv[4])

l = s[lname]
outname = os.path.basename(l.fullname) + '_' + hex(addr) + '_' + str(depth) + '.dot'

with open(outname, 'w') as outfd:
    print('writing to {}'.format(outname))
    seen = set()
    seen_edges = set()
    seen_import = set()

    outfd.write('digraph D {' + '\n')

    # Get all function nodes reachable from given address
    nodes = set(k for k, v in s.get_transitive_calls(l, addr, target_depth=depth) if
                v.fullname == lname)
    # Add the initial node itself as it is not part of the transitive call chain
    nodes.add(addr)
    # Additionally, extract the visited objects from the LibraryStore to allow
    # a reconstruction of the dependency flow through these objects.
    for (src, subl), targets in s._object_cache.items():
        if subl.fullname != lname:
            continue
        nodes.add(src)
        nodes.update(targets)

    i = 1
    prev_nodes = set()
    while nodes != prev_nodes:
        print('round {}'.format(i))
        i += 1
        prev_nodes = nodes.copy()

        # Add nodes to output
        for addr in nodes:
            maybe_print_node(l, addr, seen, outfd)

        # Add edges through local calls
        for source, targets in l.local_calls.items():
            if source in nodes:
                for target in targets:
                    if target not in nodes:
                        continue
                    print_edges(l, source, [target], seen, seen_edges, outfd)

        # Add edges through calls to exported functions
        for source, targets in l.internal_calls.items():
            if source in nodes:
                for target in targets:
                    if target not in nodes:
                        continue
                    print_edges(l, source, [target], seen, seen_edges, outfd)

        # Add edges to imported (== external) functions
        for source, targets in l.external_calls.items():
            if source not in nodes:
                continue
            maybe_print_node(l, source, seen, outfd)
            for target in targets:
                if target not in seen_import:
                    seen_import.add(target)
                    outfd.write('"{}" [shape=doubleoctagon]\n'.format(target))
                outfd.write('"{:x}" -> "{}"'.format(source, target))
                outfd.write('\n')

        # Same for local objects
        for source, targets in l.local_object_refs.items():
            if source in nodes:
                print_edges(l, source, targets, seen, seen_edges, outfd)
                nodes.update(targets)

        # ... exported objects
        for source, targets in l.export_object_refs.items():
            if source in nodes:
                print_edges(l, source, targets, seen, seen_edges, outfd)
                nodes.update(targets)

        # ... references between objects themselves
        for source, targets in l.object_to_objects.items():
            if source not in nodes:
                continue
            print_edges(l, source, targets, seen, seen_edges, outfd)
            nodes.update(targets)

        # ... and outgoing edges from objects to functions
        for source, targets in l.object_to_functions.items():
            if source not in nodes:
                continue
            if source in l.exports_plt:
                continue
            print_edges(l, source, targets, seen, seen_edges, outfd)

    outfd.write('}' + '\n')
