#!/usr/bin/env python3

import logging
import os
import sys

from librarytrader.container import LibraryStore

def parse_arguments():
    paths = []
    for path in sys.argv[1:]:
        if os.path.isdir(path):
            paths.extend([os.path.realpath(os.path.join(os.path.abspath(path),
                                                        entry.name))
                          for entry in os.scandir(path)
                          if entry.is_file()])
        else:
            paths.append(os.path.realpath(path))
    return paths

if __name__ == '__main__':

    logging.basicConfig(level=logging.INFO)

    store = LibraryStore()
    paths = parse_arguments()

    for path in paths:
        logging.info("Processing {}".format(path))

        store.resolve_libs_recursive_by_path(path)

    print(len(store))

#    lib = store[paths[0]]
#    if lib:
#        resolved = store.resolve_functions(lib)
#        for key, value in resolved.items():
#            print("Found {} in {}".format(key, value))
