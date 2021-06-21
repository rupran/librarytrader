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
        outfd.write('"{}" [shape=box]\n'.format(l.fullname))

        for outgoing in l.needed_libs.values():
            if outgoing in seen:
                continue
            outfd.write('"{}" [shape=box]\n'.format(outgoing))
            outfd.write('"{}" -> "{}"\n'.format(l.fullname, outgoing))

    outfd.write('}\n')
