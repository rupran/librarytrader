#!/usr/bin/env python3

import os
import sys

from librarytrader.container import LibraryArchive

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

    libbox = LibraryArchive()
    paths = parse_arguments()

    for path in paths:
        print("Processing {}".format(path), file=sys.stderr)

        libbox.resolve_libs_recursive_by_path(path)

    print(len(libbox))

#    lib = libbox[paths[0]]
#    if lib:
#        resolved = libbox.resolve_functions(lib)
#        for key, value in resolved.items():
#            print("Found {} in {}".format(key, value))
