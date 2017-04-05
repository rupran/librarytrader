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

import collections
import json
import logging
import os
import re

from elftools.common.exceptions import ELFError

from librarytrader.common.datatypes import BaseStore
from librarytrader.library import Library


class LibraryStore(BaseStore):

    def __init__(self):
        super(LibraryStore, self).__init__()
        self.resolver = LDResolve()

    def _get_or_create_library(self, path):
        lib = None
        link_path = None

        if os.path.islink(path):
            link_path = path
            path = os.path.realpath(path)

        if path in self:
            lib = self.get_from_path(path)

        try:
            if not lib:
                lib = Library(path)
            return (lib, link_path)
        except (ELFError, FileNotFoundError) as err:
            logging.error('\'%s\' => %s', path, err)
            return (None, None)

    def get_from_path(self, path):
        result = self.get(path)
        # Symlink-like behaviour with strings
        while isinstance(result, str):
            result = self.get(result)
        return result

    def _add_library(self, path, library):
        self[path] = library

    def _find_compatible_libs(self, target, callback):
        for needed_name in target.needed_libs:
            for path in self.resolver.get_paths(needed_name, target.rpaths):
                needed, link_path = self._get_or_create_library(path)
                if not needed:
                    continue

                if target.is_compatible(needed):
                    # If path was a symlink, add link to full name to store
                    if link_path:
                        self._add_library(link_path, needed.fullname)
                    # Enter full path to library for DT_NEEDED name
                    target.needed_libs[needed_name] = needed.fullname

                    # If we should continue processing, do the needed one next
                    if callback:
                        callback(needed)

                    # We found the compatible one, continue with next needed lib
                    break

    def _resolve_libs(self, library, path="", callback=None):
        if not library:
            library, link_path = self._get_or_create_library(path)
            if not library:
                # We had an error, so nothing can be processed
                return
            elif link_path:
                self._add_library(link_path, library.fullname)

        if library.fullname in self:
            # We were already here once, no need to go further
            return

        # Process this library
        library.parse_functions(release=True)

        # Add ourselves before processing imports
        self._add_library(library.fullname, library)

        # Find and resolve imports
        self._find_compatible_libs(library, callback)

    def resolve_libs_single(self, library, path=""):
        self._resolve_libs(library, path)

    def resolve_libs_single_by_path(self, path):
        self.resolve_libs_single(None, path)

    def resolve_libs_recursive(self, library, path=""):
        self._resolve_libs(library, path, callback=self.resolve_libs_recursive)

    def resolve_libs_recursive_by_path(self, path):
        self.resolve_libs_recursive(None, path)

    def resolve_functions(self, library):
        if isinstance(library, str):
            name = library
            library = self.get_from_path(library)
            if library is None:
                logging.error('Did not find library \'%s\'', name)
                return

        if library.fullname not in self:
            #TODO: self.resolve_libs_recursive(library)?
            raise ValueError(library.fullname)

        result = collections.OrderedDict()

        for function in library.imports:
            found = False
            for _, imp_lib_path in library.needed_libs.items():
                imp_lib = self.get_from_path(imp_lib_path)
                if not imp_lib:
                    logging.warning('Data for \'%s\' not available!',
                                    imp_lib_path)
                    continue

                if function in imp_lib.exports:
                    result[function] = imp_lib_path
                    found = True
                    break

            if not found:
                # TODO: consider symbol versioning?
                logging.warning('Did not find function \'%s\'', function)

        return result

    def dump(self, output_file):
        logging.debug('Saving results to \'%s\'', output_file)

        output = {}
        for key, value in self.items():
            lib_dict = {}
            if isinstance(value, str):
                lib_dict["type"] = "link"
                lib_dict["target"] = value
            else:
                lib_dict["type"] = "library"
                #TODO: json does not keep order of OrderedDicts... relevant?
                lib_dict["imports"] = value.imports
                lib_dict["exports"] = value.exports
                lib_dict["needed_libs"] = value.needed_libs
                lib_dict["rpaths"] = value.rpaths

            output[key] = lib_dict

        with open(output_file, 'w') as outfd:
            json.dump(output, outfd)

    def load(self, input_file):
        self.reset()

        logging.debug('loading input from \'%s\'...', input_file)
        with open(input_file, 'r') as infd:
            in_dict = json.load(infd)
            for key, value in in_dict.items():
                logging.debug("loading %s -> %s", key, value["type"])
                if value["type"] == "link":
                    self._add_library(key, value["target"])
                else:
                    library = Library(key, load_elffile=False)
                    library.imports = value["imports"]
                    library.exports = value["exports"]
                    library.needed_libs = value["needed_libs"]
                    library.rpaths = value["rpaths"]
                    self._add_library(key, library)

        logging.debug('... done with %s entries', len(self))


class LDResolve(BaseStore):

    def __init__(self, from_file=None):
        super(LDResolve, self).__init__()
        self.reload(from_file)

    def reload(self, from_file):
        self.reset()

        if from_file:
            lines = open(from_file, 'r')
        else:
            lines = os.popen('/sbin/ldconfig -p')

        for line in lines:
            line = line.strip()
            match = re.match(r'(\S+)\s+\((.+)\)\s+=>\ (.+)$', line)
            if match:
                libname, fullpath = match.group(1), match.group(3)
                if libname in self:
                    self[libname].append(fullpath)
                else:
                    self[libname] = [fullpath]
            else:
                logging.info('ill-formed line \'%s\'', line)

        if not len(self):
            logging.error('ldconfig info is missing!')
        else:
            logging.debug('Loaded %d entries from ldconfig', len(self))

    def get_paths(self, libname, rpaths):
        retval = []

        # Check rpaths first
        if rpaths:
            for rpath in rpaths:
                fullpath = os.path.abspath(os.path.join(rpath, libname))
                if not os.path.isfile(fullpath):
                    continue
                retval.append(fullpath)

        # ld.so.cache lookup
        ldsocache = self.get(libname, [])
        if not ldsocache:
            logging.warning("ldconfig doesn't know %s...", libname)
        retval.extend(ldsocache)

        if not retval:
            logging.warning("no file for '%s'...", libname)
        return retval