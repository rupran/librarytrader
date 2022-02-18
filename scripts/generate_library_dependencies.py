#!/usr/bin/env python3

import os
import sys

from librarytrader.librarystore import LibraryStore

s = LibraryStore()
s.load(sys.argv[1])

seen = set()

with open(sys.argv[1] + '_dependencies.dot', 'w') as outfd:
    outfd.write('digraph D {\n')
    for l in s.get_library_objects():
        this_base = os.path.basename(l.fullname)
        outfd.write('"{}" [shape=box]\n'.format(this_base))

        for outgoing in l.needed_libs.values():
            if outgoing in seen:
                continue
            outgoing_base = os.path.basename(outgoing)
            outfd.write('"{}" [shape=box]\n'.format(outgoing_base))
            outfd.write('"{}" -> "{}"\n'.format(this_base, outgoing_base))

    outfd.write('}\n')
