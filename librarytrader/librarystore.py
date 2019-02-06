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
        while result is not None and not isinstance(result, Library):
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

        # Work on calls to exported and local functions...
        for calls in (library.internal_calls, library.local_calls):
            if function in calls:
                working_on.add(function)
                for callee in calls[function]:
                    local_cache.add((callee, library))
                    if callee in working_on:
                        continue
                    subcalls = self.get_transitive_calls(library, callee, cache,
                                                         working_on)
                    local_cache.update(subcalls)
                working_on.remove(function)

        # ... and add calls to imported functions last
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
                callee_addr = target_lib.find_export(callee)
                local_cache.add((callee_addr, target_lib))

        cache[libname][function] = local_cache
        return cache[libname][function]

    def _find_imported_function(self, function, library, map_func=None, users=None, add=True):
        for needed_name, needed_path in library.all_imported_libs.items():
            imp_lib = self.get_from_path(needed_path)
            if not imp_lib:
                logging.warning('|- data for \'%s\' not available in %s!',
                                needed_name, library.fullname)
                continue

            exported_functions = imp_lib.exported_names
            if map_func:
                exported_functions = {map_func(key): val for key, val in
                                      imp_lib.exported_names.items()}
            if function in exported_functions:
                library.imports[function] = needed_path
                if add:
                    addr = exported_functions[function]
                    imp_lib.add_export_user(addr, library.fullname)
                    if users is not None:
                        users[(imp_lib.fullname, addr)].add(library.fullname)

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

    def resolve_functions_loaderlike(self, library):
        users = collections.defaultdict(set)

        if isinstance(library, str):
            name = library
            library = self.get_from_path(library)
            if library is None:
                logging.error('Did not find library \'%s\'', name)
                return users, False

        logging.debug('Resolving functions from %s (loader-like)', library.fullname)

        for addr, export_users in library.export_users.items():
            if 'EXTERNAL' in export_users:
                users[(library.fullname, addr)].add('EXTERNAL')

        already_defined = {}
        for name, addr in library.exported_names.items():
            already_defined[name] = (library.fullname, addr, library.export_bind[name])
            # TODO: here we mark all exported names of entrypoints as used even
            # if only one specific function was used (and already marked as
            # EXTERNAL) -> maybe we should check that as well
            library.export_users[addr].add('TOPLEVEL')
            users[(library.fullname, addr)].add('TOPLEVEL')

        overload = False

        worklist = collections.deque()
        worklist.append((library.fullname, library.fullname))
        worklist.extend(library.all_imported_libs.items())
        while worklist:
            cur_name, cur_path = worklist.popleft()
            logging.debug('... working on %s', cur_path)
            cur_lib = self.get_from_path(cur_path)
            toplevel = cur_lib == library
            for imp_name in cur_lib.imports:
                # FIXME: real behaviour with versions?
                # Crossreferencing here only makes sense for single binaries
                # as starting points, doesn't it?
                found = False
                for name in (imp_name, imp_name.split('@@')[0]):
                    if name in already_defined:
                        logging.debug('in %s: %s already defined from %s',
                                      cur_name, name, already_defined[name])
                        def_lib_path, addr, bind = already_defined[name]
                        cur_lib.imports[imp_name] = def_lib_path
                        found = True
                        overload = True
                        break

                if not found:
                    found = self._find_imported_function(imp_name, cur_lib,
                                                         users=users, add=toplevel)
                if not found:
                    found = self._find_imported_function(imp_name, cur_lib,
                                                         map_func=lambda x: x.split('@@')[0],
                                                         users=users, add=toplevel)
                if not found:
                    logging.info('absolutely no match for %s:%s:%s (working on %s)',
                                 cur_name, cur_path, imp_name, library.fullname)
            for name, addr in cur_lib.exported_names.items():
                if name not in already_defined:
                    pass
                elif already_defined[name][2] == 'STB_WEAK' and \
                        cur_lib.export_bind[name] != 'STB_WEAK':
                    logging.debug('previous weak definition override for %s@%x in %s (was in %s)',
                                  name, addr, cur_lib.fullname,
                                  already_defined[name][0])
                    pass
                else:
                    continue
                already_defined[name] = (cur_lib.fullname, addr, cur_lib.export_bind[name])

        return users, overload

    def resolve_all_functions_from_binaries(self):
        objs = [lib for lib in self.get_executable_objects()
                if not '.so' in lib.fullname]
        objs.extend(lib for lib in (self.get_from_path(path) for path
                                    in self._entrylist) if lib and not lib in objs)

        logging.info('Resolving functions from executables...')
        for lib in objs:
            logging.info('... in %s', lib.fullname)
            users, overload = self.resolve_functions_loaderlike(lib)
            self.propagate_call_usage(user_dict=users, overload=overload)

        logging.info('... done!')

    def resolve_all_functions(self, all_entries=False):
        libobjs = self.get_entry_points(all_entries)

        # Count references across libraries
        logging.info('Resolving functions between libraries...')
        for lib in libobjs:
            self.resolve_functions(lib)

        logging.info('... done!')

    def propagate_call_usage(self, all_entries=False, user_dict=None, overload=False):
        logging.info('Propagating export users through calls...')
        if user_dict is not None:
            lib_worklist = set(lib for lib in (self.get_from_path(path)
                                               for path, addr in user_dict.keys())
                               if lib)
        else:
            libobjs = self.get_entry_points(all_entries)
            lib_worklist = set(libobjs)
            user_dict = collections.defaultdict(set)
            for lib in lib_worklist:
                for addr, users in lib.export_users.items():
                    user_dict[(lib.fullname, addr)] = users.copy()
                for sublib in [self.get_from_path(x) for _, x in
                               lib.all_imported_libs.items() if x]:
                    for addr, users in sublib.export_users.items():
                        user_dict[(sublib.fullname, addr)] = users.copy()

        # Starting points are all referenced exports
        worklist = set()
        for (name, addr), user_libs in user_dict.items():
            if user_libs:
                worklist.add((self.get_from_path(name), addr))

        logging.debug('initial worklist: %s', str([(l.fullname, a) for l, a in worklist]))

        # Propagate usage information inside libraries
        while worklist:
            # Take one function and get its current users
            lib, cur = worklist.pop()
            users = user_dict.get((lib.fullname, cur), [])
            logging.debug('Propagating from %s:%x, worklist length: %d',
                          lib.fullname, cur, len(worklist))
            # Add users to transitively called functions
            for (trans_callee, called_lib) in self.get_transitive_calls(lib, cur):
                # Draw direct reference
                added = called_lib.add_export_user(trans_callee, lib.fullname)
                key = (called_lib.fullname, trans_callee)
                if overload and lib.fullname not in user_dict[key]:
                    added = True
                user_dict[key].add(lib.fullname)
                if added:
                    worklist.add((called_lib, trans_callee))

                for user in users:
                    # Add user to callee if not already present
                    added = called_lib.add_export_user(trans_callee, user)
                    key = (called_lib.fullname, trans_callee)
                    if overload and user not in user_dict[key]:
                        added = True
                    user_dict[key].add(user)
                    if not added:
                        continue
                    # Only insert callee if users have changed
                    worklist.add((called_lib, trans_callee))

        logging.info('... done!')

    def dump(self, output_file):
        logging.debug('Saving results to \'%s\'', output_file)

        output = {}
        for path, content in self.items():
            lib_dict = {}
            if not isinstance(content, Library):
                lib_dict["type"] = "link"
                lib_dict["target"] = content
            else:
                def dump_dict_with_set_value(target_dict, library, name):
                    res = {}
                    for key, value in getattr(library, name).items():
                        if not value:
                            continue
                        res[key] = list(sorted(value))
                    target_dict[name] = res
                def dump_ordered_dict_as_list(target_dict, library, name):
                    res = []
                    for key, value in getattr(library, name).items():
                        res.append([key, value])
                    target_dict[name] = res

                lib_dict["type"] = "library"
                lib_dict["entrypoint"] = content.entrypoint
                lib_dict["imports"] = content.imports
                dump_ordered_dict_as_list(lib_dict, content, "exported_names")
                lib_dict["export_bind"] = content.export_bind
                dump_dict_with_set_value(lib_dict, content, "export_users")
                lib_dict["function_addrs"] = list(sorted(content.function_addrs))
                dump_ordered_dict_as_list(lib_dict, content, "imports_plt")
                dump_ordered_dict_as_list(lib_dict, content, "exports_plt")
                lib_dict["local_functions"] = list(content.local_functions)
                dump_ordered_dict_as_list(lib_dict, content, "needed_libs")
                dump_ordered_dict_as_list(lib_dict, content, "all_imported_libs")
                lib_dict["rpaths"] = content.rpaths
                dump_dict_with_set_value(lib_dict, content, "internal_calls")
                dump_dict_with_set_value(lib_dict, content, "external_calls")
                dump_dict_with_set_value(lib_dict, content, "local_calls")
                lib_dict["ranges"] = content.ranges

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
                    def load_dict_with_set_values(from_dict, library, name, convert_key=None):
                        for key, value in from_dict[name].items():
                            key = convert_key(key) if convert_key else key
                            getattr(library, name)[key] = set(value)
                    def load_ordered_dict_from_list(from_dict, library, name):
                        # Recreate order from list
                        for key, value in from_dict[name]:
                            getattr(library, name)[key] = value

                    library.entrypoint = content["entrypoint"]
                    library.imports = content["imports"]
                    load_ordered_dict_from_list(content, library, "exported_names")
                    library.exported_addrs = collections.defaultdict(list)
                    for name, addr in library.exported_names.items():
                        library.exported_addrs[addr].append(name)
                    library.export_bind = content["export_bind"]
                    load_dict_with_set_values(content, library, "export_users", int)
                    for key in library.exported_addrs.keys():
                        if key not in library.export_users:
                            library.export_users[key] = set()
                    library.function_addrs = set(content["function_addrs"])
                    load_ordered_dict_from_list(content, library, "imports_plt")
                    load_ordered_dict_from_list(content, library, "exports_plt")
                    library.local_functions = set(content["local_functions"])
                    load_ordered_dict_from_list(content, library, "needed_libs")
                    load_ordered_dict_from_list(content, library, "all_imported_libs")
                    library.rpaths = content["rpaths"]
                    load_dict_with_set_values(content, library, "internal_calls", int)
                    load_dict_with_set_values(content, library, "external_calls", int)
                    load_dict_with_set_values(content, library, "local_calls", int)
                    library.ranges = {int(key):value for key, value in content["ranges"].items()}
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
