#!/usr/bin/env python3

import argparse
import logging
import os
import sys

from librarytrader.container import LibraryStore

def parse_arguments():
    parser = argparse.ArgumentParser(description='Evaluate imports and ' \
        'exports of .so libraries and ELF executables.')
    parser.add_argument('paths', type=str, nargs='*',
                        help='the paths to process')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose output')
    parser.add_argument('--debug', action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument('-l', '--load', action='store',
                        help='JSON file to load previously exported mapping')
    parser.add_argument('-s', '--store', action='store',
                        help='Store calculated mapping to JSON file')
    args = parser.parse_args()

    loglevel = logging.WARNING
    if args.verbose:
        loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG

    logging.basicConfig(level=loglevel)

    return args

def get_paths(args):
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

    args = parse_arguments()
    if args.load:
        store.load(args.load)
    elif not args.paths:
        logging.error('Either import results or provide paths to analyze')
        sys.exit(1)
    else:
        paths = get_paths(args)

        logging.info('Processing {} paths in total'.format(len(paths)))

        for path in paths:
            logging.info('Processing {}'.format(path))

            store.resolve_libs_recursive_by_path(path)

    logging.info('Number of entries: {}'.format(len(store)))

    if args.store:
        store.dump(args.store)

    # Demonstration for resolving
    lst = list(store.keys())
    lib = store.get_library(lst[0])

    print('Resolving functions in {}'.format(lst[0]))
    resolved = store.resolve_functions(lib)
    for key, value in resolved.items():
        print("Found {} in {}".format(key, value))
