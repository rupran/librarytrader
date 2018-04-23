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

from elftools.common.exceptions import ELFError

from librarytrader.common.datatypes import BaseStore
from librarytrader.library import Library
from librarytrader.ldresolve import LDResolve

class LibraryStore(BaseStore):

    def __init__(self, ldconfig_file=None):
        super(LibraryStore, self).__init__()
        self.resolver = LDResolve(ldconfig_file)

    def _get_or_create_library(self, path):
        link_path = None

        try:
            if os.path.islink(path) or \
                    os.path.abspath(os.path.dirname(path)) != \
                    os.path.realpath(os.path.abspath(os.path.dirname(path))):
                link_path = path
                path = os.path.realpath(path)

            if path in self:
                return (self.get_from_path(path), link_path)

            return (Library(path), link_path)
        except (ELFError, OSError) as err:
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

    def _get_compatible_libs(self, target, paths):
        retval = []
        for path in paths:
            needed, link_path = self._get_or_create_library(path)
            if not needed:
                continue

            if target.is_compatible(needed):
                retval.append((needed, link_path))

        return retval

    def _find_compatible_libs(self, target, callback, inherited_rpaths=None,
                              ld_library_paths=None):
        for needed_name in target.needed_libs:
            rpaths = self.resolver.get_paths(needed_name, target.rpaths,
                                             inherited_rpaths, target.runpaths,
                                             ld_library_paths)

            # Try to find compatible libs from ldconfig and rpath alone
            possible_libs = self._get_compatible_libs(target, rpaths)

            # If that fails, try directly probing filenames in the directories
            # ldconfig shows as containing libraries
            if not possible_libs:
                logging.debug('File system search needed for \'%s\'', needed_name)
                fs_paths = self.resolver.search_in_ldd_paths(needed_name)
                possible_libs = self._get_compatible_libs(target, fs_paths)

            for needed, link_path in possible_libs:
                # If path was a symlink and we are in recursive mode,
                # add link to full name to store
                if link_path and callback:
                    self._add_library(link_path, needed.fullname)
                # Enter full path to library for DT_NEEDED name
                target.needed_libs[needed_name] = needed.fullname
                target.all_imported_libs[needed_name] = needed.fullname

                # If we should continue processing, do the needed one next
                if callback:
                    next_rpaths = []
                    #TODO correct passdown behaviour if DT_RUNPATH is set?
                    if not target.runpaths:
                        if inherited_rpaths:
                            next_rpaths.extend(inherited_rpaths)
                        if target.rpaths:
                            next_rpaths.extend(target.rpaths)

                    callback(needed, inherited_rpaths=next_rpaths,
                             ld_library_paths=ld_library_paths)

                    target.all_imported_libs.update(needed.all_imported_libs)

                # We found the compatible one, continue with next needed lib
                break

    def _resolve_libs(self, library, path="", callback=None,
                      inherited_rpaths=None, ld_library_paths=None):
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

        logging.debug('Resolving %s', library.fullname)

        # Process this library
        library.parse_functions(release=True)

        # Add ourselves before processing imports
        self._add_library(library.fullname, library)

        # Only add LD_LIBRARY_PATH for top level calls, as $ORIGIN must be
        # resolved to the path of the analyzed binary
        if ld_library_paths is None:
            ld_library_paths = []
            if 'LD_LIBRARY_PATH' in os.environ:
                ld_library_paths = [p.replace('$ORIGIN', os.path.dirname(library.fullname))
                                    for p in os.environ['LD_LIBRARY_PATH'].split(':')]

        # Find and resolve imports
        self._find_compatible_libs(library, callback, inherited_rpaths,
                                   ld_library_paths)

    def resolve_libs_single(self, library, path=""):
        self._resolve_libs(library, path)

    def resolve_libs_single_by_path(self, path):
        self.resolve_libs_single(None, path)

    def resolve_libs_recursive(self, library, path="", inherited_rpaths=None,
                               ld_library_paths=None):
        self._resolve_libs(library, path, callback=self.resolve_libs_recursive,
                           inherited_rpaths=inherited_rpaths,
                           ld_library_paths=ld_library_paths)

    def resolve_libs_recursive_by_path(self, path):
        self.resolve_libs_recursive(None, path)

    def get_library_objects(self):
        return list(val for (key, val) in self.items()
                    if not isinstance(val, str))

    def get_executable_objects(self):
        return list(library for library in self.get_library_objects()
                    if os.access(library.fullname, os.X_OK))

    def get_all_reachable_from_executables(self):
        retval = set()
        workset = set(self.get_executable_objects())
        while workset:
            cur = workset.pop()
            retval.add(cur)
            workset.update(self[child] for child in cur.needed_libs.values()
                           if child and self[child] not in retval)
        return list(retval)

    def get_transitive_calls(self, library, function, cache=None, working_on=None):
        if cache is None:
            cache = {}
        if working_on is None:
            working_on = set()

        libname = library.fullname
        if libname not in cache:
            cache[libname] = {}
        if function in cache[libname]:
            return cache[libname][function]

        # No cache hit, calculate it
        local_cache = set()

        # If there are no calls, return the empty set
        if function not in library.calls:
            cache[libname][function] = set()
            return set()

        working_on.add(function)
        for callee in library.calls[function]:
            if callee in working_on:
                continue
            local_cache.add(callee)
            subcalls = self.get_transitive_calls(library, callee, cache,
                                                 working_on)
            local_cache.update(subcalls)
        working_on.remove(function)

        cache[libname][function] = local_cache
        return cache[libname][function]

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

        logging.debug('Resolving functions in %s', library.fullname)

        result = collections.OrderedDict()

        for function in library.imports:
            found = False
            for needed_name, needed_path in library.all_imported_libs.items():
                imp_lib = self.get_from_path(needed_path)
                if not imp_lib:
                    logging.warning('|- data for \'%s\' not available in %s!',
                                    needed_name, library.fullname)
                    continue

                if function in imp_lib.exports:
                    result[function] = needed_path
                    library.imports[function] = needed_path
                    imp_lib.add_export_user(function, library.fullname)

                    logging.debug('|- found \'%s\' in %s', function,
                                  needed_path)
                    found = True
                    break

            if not found:
                # TODO: consider symbol versioning?
                logging.warning('|- did not find function \'%s\' from %s',
                                function, library.fullname)

        return result

    def resolve_all_functions(self, all_entries=False):
        result = {}
        if all_entries:
            libobjs = self.get_library_objects()
        else:
            libobjs = self.get_all_reachable_from_executables()

        # Initialize data for known libraries
        for lib in libobjs:
            result[lib.fullname] = {}
            for function in lib.exports:
                result[lib.fullname][function] = []

        logging.info('Resolving functions between libraries...')
        # Count references across libraries
        for lib in libobjs:
            import_to_path = self.resolve_functions(lib)
            for function, fullname in import_to_path.items():
                result[fullname][function].append(lib.fullname)
        logging.info('... done!')

        return result

    def propagate_call_usage(self, result=None, all_entries=False):
        if result is None:
            result = self.resolve_all_functions(all_entries)

        logging.info('Propagating export users through calls...')
        if all_entries:
            libobjs = self.get_library_objects()
        else:
            libobjs = self.get_all_reachable_from_executables()
        # Propagate usage information inside libraries
        for lib in libobjs:
            logging.debug('Propagating in %s', lib.fullname)
            # Starting points are all referenced exports
            worklist = collections.deque(function for function, users
                                         in lib.exports.items() if users)
            while worklist:
                # Take one function and get its current users
                cur = worklist.popleft()
                users = lib.exports[cur]
                # Add users to transitively called functions
                for trans_callee in self.get_transitive_calls(lib, cur):
                    for user in users:
                        # Draw internal reference
                        lib.add_export_user(trans_callee, lib.fullname)
                        # Add connection to result
                        if user not in result[lib.fullname][trans_callee]:
                            result[lib.fullname][trans_callee].append(user)
                        # Add user to callee if not already present
                        if not lib.add_export_user(trans_callee, user):
                            continue
                        # Only add to worklist if not queued already
                        if trans_callee not in worklist:
                            worklist.append(trans_callee)
        logging.info('... done!')

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
                lib_dict["imports"] = value.imports
                lib_dict["exports"] = value.exports
                lib_dict["needed_libs"] = []
                # Order is relevant for needed_libs traversal, so convert
                # dictionary to a list to preserve ordering in JSON
                for lib, path in value.needed_libs.items():
                    lib_dict["needed_libs"].append([lib, path])
                lib_dict["all_imported_libs"] = []
                for lib, path in value.all_imported_libs.items():
                    lib_dict["all_imported_libs"].append([lib, path])
                lib_dict["rpaths"] = value.rpaths
                # We can't dump sets, so convert to a list
                calls_dict = {}
                for caller, calls in value.calls.items():
                    calls_dict[caller] = list(calls)
                lib_dict["calls"] = calls_dict

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
                    # Recreate order from list
                    needed_libs = value["needed_libs"]
                    needed_libs_dict = collections.OrderedDict()
                    for lib, path in needed_libs:
                        needed_libs_dict[lib] = path
                    library.needed_libs = needed_libs_dict
                    all_imported_libs = value["all_imported_libs"]
                    all_imported_libs_dict = collections.OrderedDict()
                    for lib, path in all_imported_libs:
                        all_imported_libs_dict[lib] = path
                    library.all_imported_libs = all_imported_libs_dict
                    library.rpaths = value["rpaths"]
                    for caller, calls in value["calls"].items():
                        library.calls[caller] = set(calls)
                    #print('{}: {}'.format(key, sorted(value["calls"].items())))
                    self._add_library(key, library)

        logging.debug('... done with %s entries', len(self))
