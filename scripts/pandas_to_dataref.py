#!/usr/bin/python3

import os
import sys
import re
import pandas as pd

from versuchung.tex import DatarefDict

infile = sys.argv[1]
outfile = sys.argv[2]
index = sys.argv[3]
store_path = None
if len(sys.argv) > 4:
    store_path = sys.argv[4]

csv = pd.read_csv(infile)
csv['filename'] = csv['filename'].apply(lambda x: os.path.basename(x))
csv['latex filename'] = csv['filename'].apply(lambda x: re.sub('_', '\\_', x))
csv['functions before'] = csv['exported functions before'] + csv['local functions before']
csv['functions after'] = csv['exported functions after'] + csv['local functions after']

csv = csv.set_index(index)
print(csv)
dref = DatarefDict(outfile)
dref.pandas(csv, verbose=True)

# Totals for ELF csv files (from ELFRemove)
dref['total/filesize before'] = csv['filesize before'].sum()
dref['total/filesize after'] = csv['filesize after'].sum()

dref['total/code size before'] = csv['code size before'].sum()
dref['total/code size after'] = csv['code size after'].sum()

dref['total/local functions before'] = csv['local functions before'].sum()
dref['total/local functions after'] = csv['local functions after'].sum()

dref['total/exported functions before'] = csv['exported functions before'].sum()
dref['total/exported functions after'] = csv['exported functions after'].sum()

dref['total/functions before'] = csv['exported functions before'].sum() + csv['local functions before'].sum()
dref['total/functions after'] = csv['exported functions after'].sum() + csv['local functions after'].sum()

dref['total/number of libraries'] = len(csv)
# The following are for the kernel CSV files
#dref['total/number of files original'] = csv['number of files original'].sum()
#dref['total/number of files tailored'] = csv['number of files tailored'].sum()
#dref['total/number of features original'] = csv['number of features original'].sum()
#dref['total/number of features tailored'] = csv['number of features tailored'].sum()

if store_path:
    from librarytrader.librarystore import LibraryStore
    s = LibraryStore()
    s.load(store_path)
    non_libraries = 0
    for l in s.get_library_objects():
        if '.so' in l.fullname or os.path.basename(l.fullname).startswith('lib'):
            continue
        non_libraries += 1
    dref['total/number of binaries'] = non_libraries

dref.flush()
