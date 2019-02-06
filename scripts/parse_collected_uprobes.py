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

import collections
import os
import re
import sys

# In order to be able to use librarytrader from git without having installed it,
# add top level directory to PYTHONPATH

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..'))

from librarytrader.librarystore import LibraryStore

def normalize(path):
    return re.sub(r'\W', '_', path[1:])

storepath = sys.argv[1]
collectpath = sys.argv[2]

store = LibraryStore()
store.load(storepath)

parsed_mapping = collections.defaultdict(set)
matches_global = 0
matches_local = 0
traced_only_binaries = 0
traced_only_libraries = 0
histo_by_lib_global = collections.defaultdict(int)
histo_by_lib_local = collections.defaultdict(int)

with open(collectpath, 'r') as collectfd:
    for line in collectfd:
        line = line.strip()
        path, offset = line.rsplit('_', 1)
        for lib in store.get_library_objects():
            if normalize(lib.fullname) == path:
                offset = int(offset, 16)
                # Note: that misses LOCAL functions, so we would need the
                # opportunity to add users to functions by offset
                fnames = lib.exported_addrs[offset]
                if not fnames:
                    if offset in lib.local_functions:
                        matches_local += 1
                        if offset not in lib.local_users or len(lib.local_users[offset]) == 0:
                            print('LOCAL: traced usage but no static user: {}:{}'.format(lib.fullname, hex(offset)))
                            histo_by_lib_local[lib.fullname] += 1
                            if ".so" in lib.fullname:
                                traced_only_libraries += 1
                            else:
                                traced_only_binaries += 1
                        parsed_mapping[lib.fullname].add('LOCAL_{}'.format(offset))
                    else:
                        print('no functions for {}:{}'.format(lib.fullname, hex(offset)))
                    break
                matches_global += 1
                if offset not in lib.export_users or len(lib.export_users[offset]) == 0:
                    print('EXPORT: traced usage but no static user: {}:{}'.format(lib.fullname, fnames))
                    if fnames[0] != '_init' and fnames[0] != '_fini':
                        histo_by_lib_global[lib.fullname] += 1

                    if ".so" in lib.fullname:
                        traced_only_libraries += 1
                    else:
                        traced_only_binaries += 1
                parsed_mapping[lib.fullname].add(fnames[0])
                break

n_export = 0
n_local = 0
n_lib = 0
for library in store.get_library_objects():
    if ".so" in library.fullname:
        n_lib += 1
        n_export += len(library.exported_addrs)
        n_local += len(library.local_functions)
mittel = n_export // n_lib
mittel_local = n_local // n_lib

print('global matches: {}, local matches: {}, traced only: bin {}, lib {}, avg exports {}, local {}, n_lib {}'.format(matches_global,
    matches_local, traced_only_binaries, traced_only_libraries, mittel, mittel_local, n_lib))
with open(collectpath + '.matched', 'w') as outfd:
    for lib, names in parsed_mapping.items():
        for name in names:
            outfd.write('{}:{}\n'.format(lib, name))
with open(collectpath + '.missed.local', 'w') as outfd:
    for path, num in sorted(histo_by_lib_local.items(), key=lambda x:x[1]):
        local_hit_path = len([x for x in parsed_mapping[path] if x.startswith("LOCAL_")])
        outfd.write('{}:{}:{}:{}\n'.format(num, len(store[path].local_functions), local_hit_path, path))
with open(collectpath + '.missed.global', 'w') as outfd:
    for path, num in sorted(histo_by_lib_global.items(), key=lambda x:x[1]):
        global_hit_path = len([x for x in parsed_mapping[path] if not x.startswith("LOCAL_")])
        outfd.write('{}:{}:{}:{}\n'.format(num, len(store[path].exported_addrs), global_hit_path, path))
