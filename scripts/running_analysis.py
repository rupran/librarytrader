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
import collections
import logging
import os
import sys

# In order to be able to use librarytrader from git without having installed it,
# add top level directory to PYTHONPATH
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..'))

from librarytrader.librarystore import LibraryStore

class Runner():

    def __init__(self):
        self._parse_arguments()
        self.store = LibraryStore()
        self.paths = self._get_paths()

    def _parse_arguments(self):
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

        if not self.args.load and not self.args.paths:
            logging.error('Please load results and/or provide paths to analyze')
            parser.print_help()
            sys.exit(1)

    def _get_paths(self):
        result = []
        for arg in self.args.paths:
            if os.path.isdir(arg):
                for entry in os.listdir(arg):
                    fullpath = os.path.join(os.path.abspath(arg), entry)
                    if os.path.isfile(fullpath):
                        result.append(fullpath)
            else:
                result.append(arg)
        return result

    def process(self):
        if self.args.load:
            self.store.load(self.args.load)

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

        print('= All imported libraries for {}'.format(lib.fullname))
        for name, path in lib.all_imported_libs.items():
            print('-- {} => {}'.format(name, path))

        histo = collections.defaultdict(int)
        for lib in libobjs:
            histo[len(list(lib.needed_libs.keys()))] += 1

        with open('needed_histo.csv', 'w') as fd:
            for num, count in sorted(histo.items()):
                fd.write('{},{}\n'.format(num, count))

    def resolve_and_print_one(self):
        # Demonstration for resolving
        libobjs = self._get_library_objects()
        lib = libobjs[0]

        print('= Resolving functions in {}'.format(lib.fullname))
        resolved = self.store.resolve_functions(lib)
        for key, value in resolved.items():
            print("-- Found {} in {}".format(key, value))

    def count_and_print_resolved(self, do_print=True):
        collection = self.store.resolve_all_functions()
        histo_percent = collections.defaultdict(int)
        if do_print:
            print('= Count of all external function uses:')
        # Print sorted overview
        for lib, functions in collection.items():
            if do_print:
                print('- Function uses in \'{}\''.format(lib))
            for function, importers in sorted(functions.items(),
                                              key=lambda x: (-len(x[1]), x[0])):
                if do_print:
                    print('-- {}: {}: {}'.format(function, len(importers),
                                                 importers))
            if len(self.store[lib].exports) > 0 and ".so" in lib:
                pctg = len(list(x for (x, y) in functions.items() if len(y) > 0)) \
                       / len(self.store[lib].exports)
                pctg = int(pctg * 100)
                if 'x32/libc-2.23.so' in lib and do_print:
                    print(pctg, lib)
                histo_percent[pctg] += 1

        with open('import_use_histo.csv', 'w') as fd:
            for key, value in sorted(histo_percent.items()):
                fd.write('{},{}\n'.format(key, value))

    def do_import_export_histograms(self):
        libobjs = self._get_library_objects()

        histo_in = collections.defaultdict(int)
        histo_out = collections.defaultdict(int)
        for lib in libobjs:
            num_imports = len(list(lib.imports))
            num_exports = len(list(lib.exports))
            histo_in[num_imports] += 1
            histo_out[num_exports] += 1
            if num_exports > 20000:
                print('Exporter {}: {}'.format(lib.fullname, num_exports))
            if num_imports > 3000:
                print('Importer {}: {}'.format(lib.fullname, num_imports))

        with open('imports_histo.csv', 'w') as fd:
            for key, value in sorted(histo_in.items()):
                fd.write('{},{}\n'.format(key, value))

        with open('exports_histo.csv', 'w') as fd:
            for key, value in sorted(histo_out.items()):
                fd.write('{},{}\n'.format(key, value))

    def print_store_keys(self):
        for key, _ in sorted(self.store.items()):
            print(key)

if __name__ == '__main__':
    runner = Runner()
    runner.process()
#    runner.print_needed_paths()

    # Resolving functions only makes sense if all libraries have been processed
#    if not runner.args.single:
#        runner.resolve_and_print_one()

#    runner.count_and_print_resolved(do_print=False)
    runner.do_import_export_histograms()
