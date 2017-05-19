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

from elftools.common.exceptions import ELFError

from librarytrader.library import Library

class DirectoryScan:

    def __init__(self, basedir):
        self.basedir = os.path.realpath(basedir)
        self.libraries = []

    def _strip_basedir(self, path):
        if path.startswith(self.basedir):
            # +1 for the / at the end of basedir
            return path[len(self.basedir)+1:]

    def read_libraries(self):
        for path in os.scandir(self.basedir):
            if not path.is_file():
                continue
            fullpath = os.path.join(self.basedir, path.name)
            try:
                lib = Library(fullpath)
            except (ELFError, OSError) as err:
                logging.error('\'%s\' => %s', path, err)
                continue
            lib.parse_functions(release=True)
            logging.debug('Adding %s', lib.fullname)
            self.libraries.append(lib)

    def try_resolve(self):
        assert len(self.libraries) > 0
        exporter = {}
        for lib in self.libraries:
            for exp_function in lib.exports:
                if exp_function in exporter:
                    logging.warning('Function %s already exported by %s',
                                    exp_function,
                                    exporter[exp_function].fullname)
                    continue
                exporter[exp_function] = lib

        for lib in self.libraries:
            for imported in lib.imports.keys():
                if imported in exporter:
                    # note on importers side where the import comes from
                    lib.imports[imported] = exporter[imported].fullname
                    logging.debug('Function \'%s\' in %s imported from %s',
                                  imported, lib.fullname,
                                  exporter[imported].fullname)
                    # note on exporters side who import 'us'
                    if exporter[imported].exports[imported] is None:
                        exporter[imported].exports[imported] = []
                    exporter[imported].exports[imported].append(lib.fullname)
                else:
                    logging.debug('No match for function \'%s\'', imported)

    def print_imports_exports(self, name_match=None):
        for lib in self.libraries:
            shortname = self._strip_basedir(lib.fullname)
            if name_match and name_match in shortname:
                # Check exporter side
                print('Used exports of \'{}\':'.format(shortname))
                for key, value in lib.exports.items():
                    if value is None:
                        continue
                    print('  {}: {}'.format(key, [self._strip_basedir(v)
                                                  for v in value]))
                # Check importer side
                print('Imports of \'{}\':'.format(shortname))
                for key, value in lib.imports.items():
                    if value is None:
                        continue
                    print('  {}: {}'.format(key, self._strip_basedir(value)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan a directory and ' \
        'resolve functions between libraries inside the directory.')
    parser.add_argument('target', type=str,
                        help='the directory containing all libraries')
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

    if not os.path.isdir(args.target):
        sys.exit("Error: {} is not a directory!".format(args.target))

    scanner = DirectoryScan(args.target)
    scanner.read_libraries()
    scanner.try_resolve()
    scanner.print_imports_exports('libc')
