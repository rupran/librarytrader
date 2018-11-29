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
matches = 0
traced_only = 0

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
                    print('no names for {}:{}'.format(lib.fullname, hex(offset)))
                    continue
                matches += 1
                if offset not in lib.export_users or len(lib.export_users[offset]) == 0:
                    print('Traced usage but no static user: {}:{}'.format(lib.fullname, fnames))
                    traced_only += 1
                parsed_mapping[lib.fullname].add(fnames[0])
                break

print(matches, traced_only)
with open(collectpath + '.matched', 'w') as outfd:
    for lib, names in parsed_mapping.items():
        for name in names:
            outfd.write('{}:{}\n'.format(lib, name))
