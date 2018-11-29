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
from librarytrader.interface_calls import resolve_calls

class Runner():

    def __init__(self):
        self._parse_arguments()
        self.store = LibraryStore()
        self.paths = self._get_paths()

        for arg in [self.args.entry_list, self.args.used_functions]:
            if arg:
                entry_points = []
                with open(arg, 'r') as fdesc:
                    for line in fdesc:
                        # .split(':') is only required for used_functions but
                        # doesn't harm in entry_list as we need the first
                        # element anyway (which is the full match if ':' does
                        # not exist in the input line)
                        cur_lib = line.strip().split(':')[0]
                        if os.path.isfile(cur_lib):
                            entry_points.append(cur_lib)
                entry_points = list(sorted(set(entry_points)))
                self.store.set_additional_entry_points(entry_points)
                self.paths.extend(entry_points)

        self.all_resolved_functions = None

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
        parser.add_argument('-r', '--resolve-functions', action='store_true',
                            help='Resolve imported functions to their origin')
        parser.add_argument('-i', '--interface_calls', action='store_true',
                            help='Calculate calls between interface functions')
        parser.add_argument('-t', '--transitive-users', action='store_true',
                            help='Propagate users over interface calls ' \
                            '(implies -r)')
        parser.add_argument('-a', '--all-entries', action='store_true',
                            help='Use all libraries as entry points for ' \
                            'function resolution. Default: only executables')
        parser.add_argument('-e', '--entry-list', action='store',
                            help='Use paths inside the given file as entry ' \
                            'points regardless of their executable status')
        parser.add_argument('-u', '--used-functions', action='store',
                            help='A file with path:name tuples which are ' \
                            'referenced symbols from dlsym')
        parser.add_argument('--single', action='store_true',
                            help='Do not recursively resolve libraries')
        parser.add_argument('--uprobe-strings', action='store_true',
                            help='Generate uprobe strings into a file')
        parser.add_argument('--loaderlike', action='store_true',
                            help='Resolve functions only from executables ' \
                            'while respecting weak symbols')
        self.args = parser.parse_args()

        loglevel = logging.WARNING
        if self.args.verbose:
            loglevel = logging.INFO
        if self.args.debug:
            loglevel = logging.DEBUG

        logging.basicConfig(format='%(asctime)s %(levelname)-7s %(message)s',
                            level=loglevel)

        if not self.args.store:
            self.args.store = ""

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
#        print([x.fullname for x in self.store.get_executable_objects() if '.so' in x.fullname])
#        print(len(self.store.get_all_reachable_from_executables()))
#        print([x.fullname for x in self.store.get_library_objects() if 'libgcj.so.16' in x.needed_libs])
#        print(len([x for (x, y) in self.store['/lib/x86_64-linux-gnu/libc-2.23.so'].exports.items() if y and len(y) > 0]))
        for path in self.paths:
            logging.info('Processing %s', path)
            if self.args.single:
                self.store.resolve_libs_single_by_path(path)
            else:
                self.store.resolve_libs_recursive_by_path(path)

        logging.info('Number of entries: %d', len(self.store))

        if self.args.interface_calls:
            self._process_interface_calls()

        if self.args.used_functions:
            self._mark_extra_functions_as_used()

        if self.args.resolve_functions:
            self.get_all_resolved_functions()

        if self.args.transitive_users and not self.args.loaderlike:
            self._propagate_users_through_calls()

        if self.args.store:
            self.store.dump(self.args.store)

        if self.args.uprobe_strings:
            self.store.generate_uprobe_strings('{}_uprobe_strings'.format(self.args.store))

    def _create_export_user_mapping(self):
        result = {}
        libobjs = self.store.get_entry_points(self.args.all_entries)

        for lib in libobjs:
            result[lib.fullname] = {}
            for function, users in lib.export_users.items():
                result[lib.fullname][function] = users

        return result

    def _process_interface_calls(self):
        return resolve_calls(self.store)

    def get_all_resolved_functions(self):
        if self.all_resolved_functions is None:
            if self.args.loaderlike:
                self.store.resolve_all_functions_from_binaries()
            else:
                self.store.resolve_all_functions(self.args.all_entries)
            self.all_resolved_functions = self._create_export_user_mapping()
        return self.all_resolved_functions

    def _mark_extra_functions_as_used(self):
        with open(self.args.used_functions, 'r') as infd:
            for line in infd:
                path, function = line.strip().split(':')
                if not os.path.isfile(path):
                    continue
                library = self.store.get_from_path(path)
                if not library:
                    continue
                addr = library.find_export(function)
                if addr is None:
                    logging.warning('mark_extra: %s not found in %s', function,
                                    library.fullname)
                    continue
                library.add_export_user(addr, 'EXTERNAL')

    def _propagate_users_through_calls(self):
        self.get_all_resolved_functions()
        self.store.propagate_call_usage(self.args.all_entries)
        self.all_resolved_functions = self._create_export_user_mapping()
        return self.all_resolved_functions

    def print_needed_paths(self):
        # Demonstration for needed paths resolution
        libobjs = self.store.get_library_objects()
        lib = next(iter(libobjs))

        print('= Needed libraries for {}'.format(lib.fullname))
        for name, path in lib.needed_libs.items():
            print('-- {} => {}'.format(name, path))

        print('= All imported libraries for {}'.format(lib.fullname))
        for name, path in lib.all_imported_libs.items():
            print('-- {} => {}'.format(name, path))

        histo = collections.defaultdict(int)
        for lib in libobjs:
            histo[len(list(lib.needed_libs.keys()))] += 1

        with open('{}_needed_histo.csv'.format(self.args.store), 'w') as outfd:
            for num, count in sorted(histo.items()):
                outfd.write('{},{}\n'.format(num, count))

    def resolve_and_print_one(self):
        # Demonstration for resolving
        libobjs = self.store.get_library_objects()
        lib = next(iter(libobjs))

        print('= Resolving functions in {}'.format(lib.fullname))
        self.store.resolve_functions(lib)
        for function, path in lib.imports.items():
            print("-- Found {} in {}".format(function, path))

    def count_and_print_resolved(self, do_print=True):
        collection = self.get_all_resolved_functions()
        histo_percent = collections.defaultdict(list)
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
            if self.store[lib].exported_addrs and ".so" in lib:
                pctg = len(list(x for (x, y) in functions.items() if y)) \
                       / len(self.store[lib].exported_addrs)
                ipctg = int(pctg * 100)
                if 'libc-2.2' in lib or 'libstdc++' in lib or 'libgcj' in lib: #and do_print:
                    print(ipctg, pctg, len(list(x for (x, y) in functions.items() if y)), lib)
#                if pctg == 0:
#                    print('0 percent: {}'.format(lib))
                histo_percent[ipctg].append(lib)

        with open('{}_import_use_histo.csv'.format(self.args.store), 'w') as outfd:
#            for key, value in sorted(histo_percent.items()):
            for key in range(101):
                outfd.write('{},{},{}\n'.format(key, len(histo_percent[key]), histo_percent[key]))

    def do_import_export_histograms(self):
        libobjs = self.store.get_entry_points(self.args.all_entries)

        histo_in = collections.defaultdict(int)
        histo_out = collections.defaultdict(int)
        for lib in libobjs:
            num_imports = len(list(lib.imports.keys()))
            num_exports = len(list(lib.exported_addrs.keys()))
            histo_in[num_imports] += 1
            histo_out[num_exports] += 1
#            if num_exports > 20000:
#                print('Exporter {}: {}'.format(lib.fullname, num_exports))
#            if num_imports > 3000:
#                print('Importer {}: {}'.format(lib.fullname, num_imports))

        print('Most called functions (directly and transitively):')
        res = []
        for library in libobjs:
            for function, callers in library.export_users.items():
                count = len(callers)
                res.append(('{}:{}'.format(library.fullname, library.exported_addrs[function]), count))

        sorted_callees = list(sorted(res, key=lambda x: x[1], reverse=True))
        for name, count in sorted_callees[:10]:
            print('{}\t{}'.format(name, count))

        with open('{}_called_functions.csv'.format(self.args.store), 'w') as outfd:
            for name, count in sorted_callees:
                outfd.write('{},{}\n'.format(name, count))

        print('Top 10 NEEDED')
        sorted_needed = list(sorted(libobjs, key=lambda x: len(list(x.needed_libs)), reverse=True))
        for library in sorted_needed[:10]:
            print('{}: {}'.format(library.fullname, len(list(library.needed_libs))))

        with open('{}_needed_libraries.csv'.format(self.args.store), 'w') as outfd:
            for library in sorted_needed:
                outfd.write('{},{}\n'.format(library.fullname, len(list(library.needed_libs))))

        print('Top 10 importers:')
        top_importers = list(sorted(libobjs, key=lambda x: len(list(x.imports)), reverse=True))
        for library in top_importers[:10]:
            print('{}: {}'.format(library.fullname, len(list(library.imports))))

        with open('{}_number_of_imports.csv'.format(self.args.store), 'w') as outfd:
            for library in top_importers:
                outfd.write('{},{}\n'.format(library.fullname, len(list(library.imports))))

        with open('{}_imports_histo.csv'.format(self.args.store), 'w') as outfd:
            for key, value in sorted(histo_in.items()):
                outfd.write('{},{}\n'.format(key, value))

        print('Top 10 exporters:')
        top_exporters = list(sorted(libobjs, key=lambda x: len(list(x.exported_addrs)), reverse=True))
        for library in top_exporters[:10]:
            print('{}: {}'.format(library.fullname, len(list(library.exported_addrs))))

        with open('{}_number_of_exports.csv'.format(self.args.store), 'w') as outfd:
            for library in top_exporters:
                outfd.write('{},{}\n'.format(library.fullname, len(list(library.exported_addrs))))

        with open('{}_exports_histo.csv'.format(self.args.store), 'w') as outfd:
            for key, value in sorted(histo_out.items()):
                outfd.write('{},{}\n'.format(key, value))

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

    runner.count_and_print_resolved(do_print=False)
    runner.do_import_export_histograms()
