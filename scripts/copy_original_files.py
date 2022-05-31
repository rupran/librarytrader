#!/usr/bin/python3
import sys
import os
import shutil

from librarytrader.librarystore import LibraryStore

s = LibraryStore()
s.load(sys.argv[1])
outpath = sys.argv[2]

for key, value in s.items():
    full_outpath = os.path.join(outpath, key.lstrip('/'))
    os.makedirs(os.path.dirname(full_outpath), exist_ok=True)
    if isinstance(value, str):
        dirs_up_to_root = full_outpath.count('/') - 1
        link_target = os.path.join('../' * dirs_up_to_root, value.lstrip('/'))
        os.symlink(link_target, full_outpath)
    else:
        shutil.copy(key, full_outpath, follow_symlinks=False)
