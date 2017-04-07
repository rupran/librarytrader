#!/usr/bin/env python3
#
# Copyright 2017, Andreas Ziegler <andreas.ziegler@fau.de>
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

import argparse
import logging
import os
import sys

from librarytrader.container import LibraryStore

class Runner():

    def __init__(self):
        self.parse_arguments()
        self.store = LibraryStore()
        self.paths = self.get_paths()

    def parse_arguments(self):
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
        parser.add_argument('--single', action='store_true',
                            help='Do not recursively resolve libraries')
        self.args = parser.parse_args()

        loglevel = logging.WARNING
        if self.args.verbose:
            loglevel = logging.INFO
        if self.args.debug:
            loglevel = logging.DEBUG

        logging.basicConfig(level=loglevel)

    def get_paths(self):
        result = []
        for arg in self.args.paths:
            if os.path.isdir(arg):
                result.extend([os.path.join(os.path.abspath(arg), entry.name)
                               for entry in os.scandir(arg)
                               if entry.is_file()])
            else:
                result.append(arg)
        return result

    def process(self):
        if self.args.load:
            self.store.load(self.args.load)
        elif not self.args.paths:
            logging.error('Please import results and/or provide paths to analyze')
            sys.exit(1)

        logging.info('Processing %d paths in total', len(self.paths))

        for path in self.paths:
            logging.info('Processing %s', path)
            if self.args.single:
                self.store.resolve_libs_single_by_path(path)
            else:
                self.store.resolve_libs_recursive_by_path(path)

        logging.info('Number of entries: %d', len(self.store))

        if self.args.store:
            self.store.dump(self.args.store)

    def _get_library_objects(self):
        return list(val for (key, val) in self.store.items()
                    if not isinstance(val, str))

    def print_needed_paths(self):
        # Demonstration for needed paths resolution
        libobjs = self._get_library_objects()
        lib = libobjs[0]

        print('= Needed libraries for {}'.format(lib.fullname))
        for name, path in lib.needed_libs.items():
            print('-- {} => {}'.format(name, path))

    def resolve_and_print_one(self):
        # Demonstration for resolving
        libobjs = self._get_library_objects()
        lib = libobjs[0]

        print('= Resolving functions in {}'.format(lib.fullname))
        resolved = self.store.resolve_functions(lib)
        for key, value in resolved.items():
            print("-- Found {} in {}".format(key, value))

    def count_and_print_resolved(self):
        collection = {}
        libobjs = self._get_library_objects()

        # Initialize data for known libraries
        for lib in libobjs:
            collection[lib.fullname] = {}
            for function in lib.exports:
                collection[lib.fullname][function] = []

        # Count references across libraries
        for lib in libobjs:
            resolved = self.store.resolve_functions(lib)
            for function, fullname in resolved.items():
                collection[fullname][function].append(lib.fullname)

        print('= Count of all external function uses:')
        # Print sorted overview
        for lib, functions in collection.items():
            print('- Function uses in \'{}\''.format(lib))
            for function, importers in sorted(functions.items(),
                                          key=lambda x: (-len(x[1]), x[0])):
                print('-- {}: {}: {}'.format(function, len(importers),
                                             importers))

    def print_store_keys(self):
        for key, _ in sorted(self.store.items()):
            print(key)

if __name__ == '__main__':
    runner = Runner()
    runner.process()
    runner.print_needed_paths()

    # Resolving functions only makes sense if all libraries have been processed
    if not runner.args.single:
        runner.resolve_and_print_one()

    runner.count_and_print_resolved()
