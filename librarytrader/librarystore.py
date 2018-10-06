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
from librarytrader.ldresolve import LDResolve

class LibraryStore(BaseStore):

    def __init__(self, ldconfig_file=None):
        super(LibraryStore, self).__init__()
        self._entrylist = []
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
        next_level_needed = collections.OrderedDict()
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

                    # Keep track of the recursively needed libraries
                    next_level_needed.update(needed.all_imported_libs)

                # We found the compatible one, continue with next needed lib
                break
        # Only add the recursively needed libraries after all directly needed
        # libraries have been added, as symbol resolution is breadth-first
        # (see ELF specification, Dynamic Linking / Shared Object Dependencies)
        target.all_imported_libs.update(next_level_needed)

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

    def set_additional_entry_points(self, entrylist):
        self._entrylist.extend(entrylist)

    def get_library_objects(self):
        retval = set(val for (key, val) in self.items()
                     if isinstance(val, Library))
        retval.update(lib for lib in (self.get_from_path(path)
                                      for path in self._entrylist)
                      if lib)
        return retval

    def get_executable_objects(self):
        return list(library for library in self.get_library_objects()
                    if os.access(library.fullname, os.X_OK))

    def get_all_reachable_from_executables(self):
        retval = set()
        workset = set(self.get_executable_objects())
        workset.update(lib for lib in (self.get_from_path(path)
                                       for path in self._entrylist)
                       if lib)
        while workset:
            cur = workset.pop()
            retval.add(cur)
            workset.update(self[child] for child in cur.needed_libs.values()
                           if child and self[child] not in retval)
        return list(retval)

    def get_entry_points(self, all_entries=False):
        if all_entries:
            return self.get_library_objects()
        else:
            return self.get_all_reachable_from_executables()

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

        if function in library.internal_calls:
            working_on.add(function)
            for callee in library.internal_calls[function]:
                local_cache.add((callee, library))
                if callee in working_on:
                    continue
                subcalls = self.get_transitive_calls(library, callee, cache,
                                                     working_on)
                local_cache.update(subcalls)
            working_on.remove(function)

        if function in library.external_calls:
            for callee in library.external_calls[function]:
                if callee in library.imports:
                    target_lib = self.get_from_path(library.imports[callee])
                else:
                    logging.debug('external_calls: no target for \'%s\'', callee)
                    continue
                if target_lib is None:
                    logging.warning('%s: call to unknown target for function %s',
                                    libname, callee)
                    continue
                local_cache.add((callee, target_lib))

        cache[libname][function] = local_cache
        return cache[libname][function]

    def _find_imported_function(self, function, library, map_func=None):
        for needed_name, needed_path in library.all_imported_libs.items():
            imp_lib = self.get_from_path(needed_path)
            if not imp_lib:
                logging.warning('|- data for \'%s\' not available in %s!',
                                needed_name, library.fullname)
                continue

            exported_functions = imp_lib.exports
            if map_func:
                exported_functions = [map_func(x) for x in imp_lib.exports]
            if function in exported_functions:
                library.imports[function] = needed_path
                imp_lib.add_export_user(function, library.fullname)

                logging.debug('|- found \'%s\' in %s', function, needed_path)
                return True
        return False

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

        for function in library.imports:
            # Try to find the exact name in all imported libraries...
            found = self._find_imported_function(function, library)
            if not found:
                # ...if that didn't come up with anything, try again, but strip
                # the version names off all exports of the imported libraries.
                found = self._find_imported_function(function, library,
                                                     lambda x: x.split('@@')[0])

            if not found:
                logging.warning('|- did not find function \'%s\' from %s',
                                function, library.fullname)

    def resolve_all_functions(self, all_entries=False):
        libobjs = self.get_entry_points(all_entries)

        # Count references across libraries
        logging.info('Resolving functions between libraries...')
        for lib in libobjs:
            self.resolve_functions(lib)

        logging.info('... done!')

    def propagate_call_usage(self, all_entries=False):
        logging.info('Propagating export users through calls...')
        libobjs = self.get_entry_points(all_entries)

        lib_worklist = set(libobjs)
        # Propagate usage information inside libraries
        while lib_worklist:
            lib = lib_worklist.pop()
            logging.debug('Propagating in %s, worklist length: %d', lib.fullname,
                          len(lib_worklist))
            # Starting points are all referenced exports
            worklist = collections.deque(function for function, users
                                         in lib.exports.items() if users)
            while worklist:
                # Take one function and get its current users
                cur = worklist.popleft()
                users = lib.exports[cur]
                # Add users to transitively called functions
                for (trans_callee, called_lib) in self.get_transitive_calls(lib, cur):
                    # Draw direct reference
                    called_lib.add_export_user(trans_callee, lib.fullname)
                    if lib != called_lib:
                        lib_worklist.add(called_lib)
                    for user in users:
                        # Add user to callee if not already present
                        if not called_lib.add_export_user(trans_callee, user):
                            continue
                        # Only add to worklist if the callee is in the current
                        # library and it is not queued already
                        if called_lib == lib and trans_callee not in worklist:
                            worklist.append(trans_callee)

        logging.info('... done!')

    def dump(self, output_file):
        logging.debug('Saving results to \'%s\'', output_file)

        output = {}
        for path, content in self.items():
            lib_dict = {}
            if isinstance(value, str):
                lib_dict["type"] = "link"
                lib_dict["target"] = content
            else:
                def dump_dict_with_set_value(target_dict, library, name):
                    res = {}
                    for key, value in getattr(library, name).items():
                        res[key] = list(value)
                    target_dict[name] = res
                def dump_ordered_dict_as_list(target_dict, library, name):
                    res = []
                    for key, value in getattr(library, name).items():
                        res.append([key, value])
                    target_dict[name] = res

                lib_dict["type"] = "library"
                lib_dict["imports"] = content.imports
                dump_dict_with_set_value(lib_dict, content, "exports")
                lib_dict["function_addrs"] = list(content.function_addrs)
                dump_ordered_dict_as_list(lib_dict, content, "imports_plt")
                dump_ordered_dict_as_list(lib_dict, content, "exports_plt")
                dump_ordered_dict_as_list(lib_dict, content, "needed_libs")
                dump_ordered_dict_as_list(lib_dict, content, "all_imported_libs")
                lib_dict["rpaths"] = content.rpaths
                dump_dict_with_set_value(lib_dict, content, "internal_calls")
                dump_dict_with_set_value(lib_dict, content, "external_calls")

            output[path] = lib_dict

        with open(output_file, 'w') as outfd:
            json.dump(output, outfd)

    def load(self, input_file):
        self.reset()

        logging.debug('loading input from \'%s\'...', input_file)
        with open(input_file, 'r') as infd:
            in_dict = json.load(infd)
            for path, content in in_dict.items():
                logging.debug("loading %s -> %s", path, content["type"])
                if content["type"] == "link":
                    self._add_library(path, content["target"])
                else:
                    library = Library(path, load_elffile=False)
                    def load_dict_with_set_values(from_dict, library, name):
                        for key, value in from_dict[library.fullname][name].items():
                            getattr(library, name)[key] = set(value)
                    def load_ordered_dict_from_list(from_dict, library, name):
                        # Recreate order from list
                        for key, value in from_dict[library.fullname][name]:
                            getattr(library, name)[key] = value

                    library.imports = content["imports"]
                    load_dict_with_set_values(in_dict, library, "exports")
                    library.function_addrs = set(content["function_addrs"])
                    load_ordered_dict_from_list(in_dict, library, "imports_plt")
                    load_ordered_dict_from_list(in_dict, library, "exports_plt")
                    load_ordered_dict_from_list(in_dict, library, "needed_libs")
                    load_ordered_dict_from_list(in_dict, library, "all_imported_libs")
                    library.rpaths = content["rpaths"]
                    load_dict_with_set_values(in_dict, library, "internal_calls")
                    load_dict_with_set_values(in_dict, library, "external_calls")
                    #print('{}: {}'.format(path, sorted(["calls"].items())))
                    self._add_library(path, library)

        logging.debug('... done with %s entries', len(self))

    def generate_uprobe_strings(self, output_name, all_entries=True):
        logging.info('Generating uprobe strings to %s...', output_name)
        with open(output_name, 'w') as outfd:
            for lib in self.get_entry_points(all_entries):
                for address in lib.function_addrs:
                    hex_address = hex(address)
                    event_name = re.sub(r'\W', '_', lib.fullname[1:]) + '_' \
                        + str(hex_address)
                    outfd.write('u:{} {}:{}\n'.format(event_name,
                                                      lib.fullname,
                                                      hex_address))
        logging.info('... done!')
