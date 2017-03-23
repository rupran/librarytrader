#!/usr/bin/env python3

import os
import sys

from elftools.common.exceptions import ELFError

from librarytrader.library import Library
from librarytrader.container import LibraryArchive, LDResolve

def parse_arguments():
    paths = []
    for path in sys.argv[1:]:
        if os.path.isdir(path):
            paths.extend([os.path.join(os.path.abspath(path), entry.name)
                          for entry in os.scandir(path)
                          if entry.is_file()])
        else:
            paths.append(path)
    return paths

if __name__ == '__main__':

    resolver = LDResolve()
    libbox = LibraryArchive(resolver)

    paths = parse_arguments()

    for path in paths:
        print("Processing {}".format(path), file=sys.stderr)

        if os.path.islink(path):
            # If we get a symlink, note in in the cache and process target
            print("{} is a symlink to {}".format(path, os.readlink(path)),
                  file=sys.stderr)
            target = os.readlink(path)
            if not os.path.isabs(target):
                target = os.path.join(os.path.dirname(path), target)
            libbox.add_library(path, target)
            path = target
        elif not os.path.isfile(path):
            continue
        elif path in libbox:
            # skip potentially processed libraries
            continue

        try:
            item = Library(path)
        except ELFError as e:
            print("ERR: {} => {}".format(path, e), file=sys.stderr)
            continue

        libbox.resolve_libs_recursive(item)

    print(len(libbox))

    lib = libbox[paths[0]]
    libbox.resolve_functions(lib)
