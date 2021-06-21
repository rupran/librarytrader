#!/usr/bin/env python3

import os
import sys

from librarytrader.librarystore import LibraryStore

s = LibraryStore()
s.load(sys.argv[1])

for l in s.get_library_objects():
    called_imports = set()
    for k, v in l.local_users.items():
        if not v:
            continue
        l_c = l.external_calls.get(k, set())
        called_imports.update(l_c)
    for k, v in l.export_users.items():
        if not v:
            continue
        l_c = l.external_calls.get(k, set())
        called_imports.update(l_c)
    m = l.exported_names.get('main')
    if m:
        l_c = l.external_calls.get(m, set())
        called_imports.update(l_c)
    unused_imports = set(l.imports.keys()).difference(called_imports)
#    print('{}: imports {}, unused {}'.format(l.fullname, len(l.imports),
#                                             len(unused_imports)))
#    print(unused_imports)
    for imp, path in l.imports.items():
        if imp in unused_imports:
            continue
        if path is None:
            print('XXX {}: import {} is None'.format(l.fullname, imp))
            continue
        target_func = s[path].exported_names.get(imp)
        if target_func:
            if not s[path].export_users[target_func]:
                print('{}: import with no users: {}/{}'.format(l.fullname, path, imp))
