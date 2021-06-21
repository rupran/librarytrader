#!/usr/bin/env python3

import collections
import os
import sys

from librarytrader.librarystore import LibraryStore

s = LibraryStore()
s.load(sys.argv[1])
n = 20

if len(sys.argv) > 2:
    n = int(sys.argv[2])

outgoing_calls = set()
incoming_calls = collections.defaultdict(int)

for l in s.get_library_objects():
    for f, names in l.exported_addrs.items():
        s = 0
        name = '{}:{}'.format(l.fullname, names[0])
        s += len(l.internal_calls.get(f, []))
        s += len(l.external_calls.get(f, []))
        s += len(l.local_calls.get(f, []))
        outgoing_calls.add((name, s))

    for f, names in l.local_functions.items():
        s = 0
        name = '{}:LOCAL_{}'.format(l.fullname, names[0])
        s += len(l.internal_calls.get(f, []))
        s += len(l.external_calls.get(f, []))
        s += len(l.local_calls.get(f, []))
        outgoing_calls.add((name, s))

    for source, targets in l.internal_calls.items():
        for target in targets:
            key = '{}:{}'.format(l.fullname, l.exported_addrs[target][0])
            incoming_calls[key] += 1
    for source, targets in l.local_calls.items():
        for target in targets:
            key = '{}:LOCAL_{}'.format(l.fullname, l.local_functions[target][0])
            incoming_calls[key] += 1


out_sorted = sorted(outgoing_calls, key=lambda x: x[1])
print('Top {} outgoing calls'.format(n))
for tp in out_sorted[-n:]:
    print(tp[0], tp[1])

print('')
print('Top {} incoming calls (direct)'.format(n))
in_sorted = sorted(incoming_calls.items(), key=lambda x:x[1])
for tp in in_sorted[-n:]:
    print(tp[0], tp[1])
