#!/usr/bin/env python3

import re
import os
import sys

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..'))
from librarytrader.ldresolve import LDResolve

used_set = set()
ldresolver = LDResolve()

with open(sys.argv[1], 'r') as trace:
    name_for_pid = {}
    handles = {}
    for line in trace:
        if 'dlopen:' in line:
            m = re.match(r'^\s*.+-(\d+)\s+.+arg1=\"(.+)\"$', line)
            if m:
                pid = m.group(1)
                filename = m.group(2)
                if not os.path.isabs(filename):
                    possible = ldresolver.get(filename, None)
                    if not possible:
                        #print('Resolver does not know {}'.format(filename))
                        continue
                    elif len(possible) > 1:
                        #print('Multiple libraries for {}: {}'.format(filename, possible))
                        continue
                    else:
                        filename = possible[0]
                if os.access(filename, os.R_OK):
                    name_for_pid[pid] = filename
                else:
                    #print('No such file: {}'.format(filename))
                    continue
        elif 'dlopen_ret:' in line:
            m = re.match(r'^\s*.+-(\d+)\s+.+arg1=(.+)$', line)
            if m:
                pid = m.group(1)
                handle = m.group(2)
                if pid in name_for_pid and handle != '0x0':
                    handles[handle] = name_for_pid[pid]
                else:
                    #print('Do not know handle/pid {}/{}'.format(handle, pid))
                    pass
        elif 'dlsym:' in line:
            m = re.match(r'.*arg1=(.*)\s+arg2=\"(.*)\"$', line)
            if m:
                handle = m.group(1)
                function = m.group(2)
                if handle in handles:
                    used_set.add((handles[handle], function))
                else:
                    #print('dlsym for unknown handle: {}'.format(handle))
                    pass

for lib, function in used_set:
    print('{}:{}'.format(lib, function))
