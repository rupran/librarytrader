#!/usr/bin/env python3

import argparse
import logging
import os
import sys

from librarytrader.container import LibraryStore

def parse_arguments():
    parser = argparse.ArgumentParser(description='Evaluate imports and ' \
        'exports of .so libraries and ELF executables.')
    parser.add_argument('paths', type=str, nargs='+',
                        help='the paths to process')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose output')
    parser.add_argument('--debug', action='store_true',
                        help=argparse.SUPPRESS)
    args = parser.parse_args()

    loglevel = logging.WARNING
    if args.verbose:
        loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG

    logging.basicConfig(level=loglevel)

    paths = []
    for path in args.paths:
        if os.path.isdir(path):
            paths.extend([os.path.realpath(os.path.join(os.path.abspath(path),
                                                        entry.name))
                          for entry in os.scandir(path)
                          if entry.is_file()])
        else:
            paths.append(os.path.realpath(path))
    return paths

if __name__ == '__main__':

    store = LibraryStore()
    paths = parse_arguments()

    logging.info('Processing {} paths in total'.format(len(paths)))

    for path in paths:
        logging.info('Processing {}'.format(path))

        store.resolve_libs_recursive_by_path(path)

    logging.info(len(store))

    print(len(store))
#    lib = store[paths[0]]
#    if lib:
#        resolved = store.resolve_functions(lib)
#        for key, value in resolved.items():
#            print("Found {} in {}".format(key, value))
