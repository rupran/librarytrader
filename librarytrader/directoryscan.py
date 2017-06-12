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

import logging
import os

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
            for function in lib.imports.keys():
                if function in exporter:
                    if exporter[function].soname not in lib.needed_libs.keys():
                        logging.warning('Found %s in %s, but no DT_NEEDED in %s',
                                        function, exporter[function].fullname,
                                        lib.fullname)
                    exporting_lib = exporter[function]
                    # note on importers side where the import comes from
                    lib.imports[function] = exporting_lib.fullname
                    logging.debug('Function \'%s\' in %s imported from %s',
                                  function, lib.fullname,
                                  exporting_lib.fullname)
                    # note on exporters side that we imported the function
                    if exporting_lib.exports[function] is None:
                        exporting_lib.exports[function] = []
                    exporting_lib.exports[function].append(lib.fullname)
                else:
                    logging.debug('No match for function \'%s\'',
                                  function)

    def print_imports_exports(self, name_match=None):
        for lib in self.libraries:
            shortname = self._strip_basedir(lib.fullname)
            if not name_match or name_match in shortname:
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
