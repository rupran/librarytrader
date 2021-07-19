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
        self._object_cache = {}
        self._callee_cache = {}

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
            if 'EXTRA_LIBRARY_PATH' in os.environ:
                ld_library_paths.extend(os.environ['EXTRA_LIBRARY_PATH'].split(':'))

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

    def _resolve_object_to_functions(self, library, source_object):
        worklist = set([source_object])
        worked_on = set()
        result = set()
        ptr_size = 4 if library.is_i386() else 8
        while worklist:
            cur_obj = worklist.pop()
            # If we do not want all functions pulled in, check if the object
            # is one single pointer long. if this is not the case, ignore this
            # object, otherwise pull other objects and functions in. Note that
            # relocations get entries in the object_to_* dictionaries but not
            # in object_ranges, so default to ptr_size if we do not have a size
            # for the currently processed object.
            if 'ALL_FUNCTIONS_FROM_OBJECTS' not in os.environ and \
                    library.object_ranges.get(cur_obj, ptr_size) != ptr_size:
                continue
            # Recursive reference to object -> add to worklist and process later
            if cur_obj in library.object_to_objects and cur_obj not in worked_on:
                worklist.update(library.object_to_objects[cur_obj])
            # Direct reference to a function -> add to result
            if cur_obj in library.object_to_functions:
                result.update(library.object_to_functions[cur_obj])
            worked_on.add(cur_obj)
        return result

    def get_transitive_calls(self, library, function, working_on=None):
        if working_on is None:
            working_on = set()

        libname = library.fullname
        if libname not in self._callee_cache:
            self._callee_cache[libname] = {}
        if function in self._callee_cache[libname]:
            return self._callee_cache[libname][function]

        # No cache hit, calculate it
        local_cache = set()

        # Work on calls to exported and local functions...
        for calls in (library.internal_calls, library.local_calls):
            if function in calls:
                working_on.add(function)
                for callee in calls[function]:
                    local_cache.add((callee, library))
                    logging.debug('internal call: %x -> %x in %s', function,
                                  callee, library.fullname)
                    if callee in working_on:
                        continue
                    subcalls = self.get_transitive_calls(library, callee, working_on)
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

        # Additionally, add local references through objects...
        for object_refs in (library.export_object_refs, library.local_object_refs):
            if function in object_refs:
                working_on.add(function)
                for intermediate_object in object_refs[function]:
                    if (intermediate_object, library) not in self._object_cache:
                        self._object_cache[(intermediate_object, library)] = \
                            self._resolve_object_to_functions(library, intermediate_object)
                    for callee in self._object_cache[(intermediate_object, library)]:
                        local_cache.add((callee, library))
                        logging.debug('transitive internal call to %x through object %d in %s',
                                      callee, intermediate_object, library.fullname)
                        if callee in working_on:
                            continue
                        subcalls = self.get_transitive_calls(library, callee, working_on)
                        local_cache.update(subcalls)

                working_on.remove(function)

        # ... and references to imported objects
        if function in library.import_object_refs:
            for callee in library.import_object_refs[function]:
                if callee in library.imported_objs:
                    name = library.imported_objs[callee]
                    target_lib = self.get_from_path(library.imported_objs_locations[name])
                else:
                    continue
                if target_lib is None:
                    logging.warning('%s: reference to unknown target for object %s in function %x',
                                    libname, callee, function)
                    continue
                callee_addr = target_lib.find_object(name)
                if callee_addr is None:
                    logging.debug('no addr found for object %s:%s, '\
                                  'referenced from %s:%x', target_lib.fullname,
                                  name, library.fullname, function)
                    continue

                for dependent_function in target_lib.object_to_functions[callee_addr]:
                    logging.debug('transitive call to %s:%x through object %s from %s',
                                  target_lib.fullname, dependent_function, name,
                                  library.fullname)
                    local_cache.add((dependent_function, target_lib))

        self._callee_cache[libname][function] = local_cache
        return self._callee_cache[libname][function]

    def _find_imported_function(self, function, library, map_func=None,
                                users=None, add=True, lookup_iterable=None):
        found = None
        if lookup_iterable is None:
            lookup_iterable = library.all_imported_libs.items()
        version_requested = '@@' in function

        map_func_passed = map_func

        for needed_name, needed_path in lookup_iterable:
            imp_lib = self.get_from_path(needed_path)
            if not imp_lib:
                logging.warning('|- data for \'%s\' not available in %s!',
                                needed_name, library.fullname)
                continue

            versions_defined = imp_lib.defines_versions

            lookup_function = function
            # We need to map if we passed a map_func
            need_map = map_func_passed is not None
            if version_requested and not versions_defined:
                # TODO: glibc mandates a check if the requested version does not
                # mention the implementing object in its Verneed entry.
                # Otherwise, we accept a same name match -> strip version name
                lookup_function = function.split('@@')[0]
            elif (not version_requested and versions_defined):
                # TODO: In this case, we need to check that the defined version
                # for the symbol name is 1 (global) or 2 (baseline of symbols)
                # or we have exactly one matching, non-hidden version of the
                # symbol
                need_map = True
                map_func = lambda x: x.split('@@')[0]

            # Check against the versioned names of exports...
            exported_functions = imp_lib.exported_names
            # ... except if we need to check for an unversioned function name
            if need_map:
                #exported_functions = {map_func(key): val for key, val in
                #                      imp_lib.exported_names.items()}
                exported_functions = imp_lib.version_descriptions

            # Do the actual lookup
            if lookup_function in exported_functions:
                # If we're looking for an unversioned function in a versioned
                # library, we need to adjust the unversioned name to the correct
                # versioned implementation as there could be multiple ones.
                if (not version_requested and versions_defined):
                    # Get all descriptors of functions with the requested name
                    attrs = imp_lib.version_descriptions.get(lookup_function, None)
                    if attrs is not None:
                        selected = None
                        # We found the right symbol if:
                        for idx, hidden, versioned_name in attrs:
                            # it's either the base definition...
                            if idx in (1, 2): #and selected is None:
                                selected = versioned_name
                                break
                            # or if it is not hidden and we have exactly one
                            # matching symbol name
                            if hidden:
                                continue
                            if selected:
                                # multiple unhidden symbols -> ambiguous
                                logging.error('multiple non-hidden versioned symbols '\
                                              'for function %s in %s',
                                              lookup_function, imp_lib.fullname)
                                selected = None
                                break
                            else:
                                selected = versioned_name
                                logging.debug('selected %s as the matching function in %s',
                                              selected, imp_lib.fullname)

                        # If selected is None, we either didn't find a version
                        # at all or we found multiple ones. In this case we must
                        # continue the search in the next object.
                        if selected is None:
                            continue
                        # If we found the right version, mark this as the target
                        # function for the following steps
                        lookup_function = selected
                        # For this lookup, we need the original exported names
                        # back as we're now dealing with versions again
                        exported_functions = imp_lib.exported_names

                # TODO: case where version was requested and defined (dl-lookup:120)

                logging.debug('|- found \'%s\' in %s', function, needed_path)
                # End the search if we find a strong definition...
                if imp_lib.export_bind[lookup_function] == 'STB_GLOBAL':
                    found = (imp_lib, exported_functions[lookup_function])
                    break
                # ... otherwise keep the first weak definition
                elif found is None and imp_lib.export_bind[lookup_function] == 'STB_WEAK':
                    found = (imp_lib, exported_functions[lookup_function])

        if found is not None:
            imp_lib, addr = found
            library.imports[function] = imp_lib.fullname
            if add:
                imp_lib.add_export_user(addr, library.fullname)
                if users is not None:
                    users[(imp_lib.fullname, addr)].add(library.fullname)

            return True
        return False

    def _find_imported_object(self, obj, library, lookup_iterable=None,
                              map_func=None, users=None, add=True):
        if lookup_iterable is None:
            lookup_iterable = library.all_imported_libs.items()

        for needed_name, needed_path in lookup_iterable:
            imp_lib = self.get_from_path(needed_path)
            if not imp_lib:
                logging.warning('|- data for \'%s\' not available in %s!',
                                needed_name, library.fullname)
                continue

            exported_objs = imp_lib.exported_obj_names
            if map_func:
                exported_objs = {map_func(key): val for key, val in
                                 imp_lib.exported_obj_names.items()}
            if obj in exported_objs:
                library.imported_objs_locations[obj] = needed_path
                if add:
                    addr = exported_objs[obj]
                    imp_lib.add_object_user(addr, library.fullname)
                    if users is not None:
                        users[(imp_lib.fullname, addr)].add(library.fullname)

                logging.debug('|- found object \'%s\' in %s', obj, needed_path)
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
                # Hack: search function in all libraries in the store
                for other_lib in self.get_library_objects():
                    if function in other_lib.exported_names:
                        target = other_lib.exported_names
                    else:
                        to_search = [x.split('@@')[0] for x in other_lib.exported_names]
                        if function in to_search:
                            target = {x.split('@@')[0] : val for x, val in other_lib.exported_names.items()}
                        else:
                            continue
                    target_name = other_lib.fullname
                    target_addr = target[function]
                    library.imports[function] = target_name
                    other_lib.add_export_user(target_addr, library.fullname)
                    logging.info('hard search for %s, found at %s:%x', function,
                                 target_name, target_addr)
                    found = True

            if not found:
                logging.warning('|- did not find function \'%s\' from %s',
                                function, library.fullname)

        for obj in library.imported_objs_locations:
            found = self._find_imported_object(obj, library)
            if not found:
                found = self._find_imported_object(obj, library,
                                                   map_func=lambda x: x.split('@@')[0])
            if not found:
                logging.warning('|- did not find object \'%s\' from %s',
                                obj, library.fullname)

    def resolve_functions_loaderlike(self, library, force_add_to_exports=False):
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

        for name, addr in library.exported_names.items():
            # TODO: here we mark all exported names of entrypoints as used even
            # if only one specific function was used (and already marked as
            # EXTERNAL) -> maybe we should check that as well
            library.export_users[addr].add('TOPLEVEL')
            users[(library.fullname, addr)].add('TOPLEVEL')


        worklist = collections.deque()
        worklist.append((library.fullname, library.fullname))
        worklist.extend(library.all_imported_libs.items())

        lookup_list = list(worklist)

        while worklist:
            cur_name, cur_path = worklist.popleft()
            logging.debug('... working on %s', cur_path)
            cur_lib = self.get_from_path(cur_path)
            add_export = cur_lib == library
            if force_add_to_exports:
                add_export = True
            #print(cur_lib.fullname, library.fullname, add_export)
            for imp_name in cur_lib.imports:
                # FIXME: real behaviour with versions?
                # Crossreferencing here only makes sense for single binaries
                # as starting points, doesn't it?
                found = self._find_imported_function(imp_name, cur_lib,
                                                     users=users, add=add_export,
                                                     lookup_iterable=lookup_list)
                if not found:
                    logging.debug('absolutely no match for %s:%s:%s (working on %s)',
                                  cur_name, cur_path, imp_name, library.fullname)

            #TODO: Treat objects with correct version lookup (like functions above)
            for imp_name in cur_lib.imported_objs_locations:
                found = self._find_imported_object(imp_name, cur_lib,
                                                   lookup_iterable=lookup_list,
                                                   users=users, add=add_export)
                if not found:
                    found = self._find_imported_object(imp_name, cur_lib,
                                                       lookup_iterable=lookup_list,
                                                       map_func=lambda x: x.split('@@')[0],
                                                       users=users, add=add_export)
                if not found:
                    logging.warning('|- did not find object \'%s\' from %s',
                                    imp_name, cur_lib.fullname)

            for addr in cur_lib.init_functions:
                cur_lib.add_export_user(addr, 'INITUSER')
                users[(cur_lib.fullname, addr)].add('INITUSER')
            for addr in cur_lib.fini_functions:
                cur_lib.add_export_user(addr, 'FINIUSER')
                users[(cur_lib.fullname, addr)].add('FINIUSER')

        return users

    def resolve_all_functions_from_binaries(self, force_add_to_exports=False):
        objs = [lib for lib in self.get_executable_objects()
                if not '.so' in lib.fullname]
        objs.extend(lib for lib in (self.get_from_path(path) for path
                                    in self._entrylist) if lib and not lib in objs)

        logging.info('Resolving functions from executables...')
        for lib in objs:
            logging.info('... in %s', lib.fullname)
            users = self.resolve_functions_loaderlike(lib, force_add_to_exports)
            self._callee_cache = {}
            self.propagate_call_usage(user_dict=users)

        logging.info('... done!')

    def resolve_all_functions(self, all_entries=False):
        libobjs = self.get_entry_points(all_entries)

        # Count references across libraries
        logging.info('Resolving functions between libraries...')
        for lib in libobjs:
            self.resolve_functions(lib)

        logging.info('... done!')

    def propagate_call_usage(self, all_entries=False, user_dict=None):
        logging.info('Propagating export users through calls...')
        if user_dict is not None:
            user_dict_passed = True
            lib_worklist = set(lib for lib in (self.get_from_path(path)
                                               for path, addr in user_dict.keys())
                               if lib)
        else:
            libobjs = self.get_entry_points(all_entries)
            lib_worklist = set(libobjs)
            user_dict = collections.defaultdict(set)
            user_dict_passed = False
            for lib in lib_worklist:
                for addr, users in lib.export_users.items():
                    user_dict[(lib.fullname, addr)] = users.copy()
                for addr, users in lib.local_users.items():
                    user_dict[(lib.fullname, addr)] = users.copy()

        # Starting points are all referenced exports...
        worklist = set()
        for (name, addr), user_libs in user_dict.items():
            if user_libs:
                worklist.add((self.get_from_path(name), addr))

        for lib in set(name for name, addr in user_dict.keys()):
            library_object = self.get_from_path(lib)
            # ... the main function...
            if 'main' in library_object.exported_names:
                addr = library_object.exported_names['main']
                logging.debug('adding %s:main to worklist', lib)
                worklist.add((library_object, addr))
                #user_dict[(lib, addr)].add('MAINUSER')
            # ... the entry point address if we're not looking at a library
            if '.so' not in library_object.fullname and \
                    library_object.entrypoint in library_object.local_functions:
                logging.debug('adding %s:entrypoint (%x/%s) to worklist', lib,
                              library_object.entrypoint,
                              library_object.local_functions[library_object.entrypoint])
                worklist.add((library_object, library_object.entrypoint))
                library_object.add_export_user(library_object.entrypoint, 'ENTRYUSER')
            # ... (the entry point function can also be global) ...
            if '.so' not in library_object.fullname and \
                    library_object.entrypoint in library_object.exported_addrs:
                logging.debug('adding %s:entrypoint (%x/%s) to worklist', lib,
                              library_object.entrypoint,
                              library_object.exported_addrs[library_object.entrypoint])
                worklist.add((library_object, library_object.entrypoint))
                library_object.add_export_user(library_object.entrypoint, 'ENTRYUSER')
            # ... all initialization functions...
            for addr in library_object.init_functions:
                library_object.add_export_user(addr, 'INITUSER')
                worklist.add((library_object, addr))
                user_dict[(lib, addr)].add('INITUSER')
            # ... and ll deconstruction functions.
            for addr in library_object.fini_functions:
                library_object.add_export_user(addr, 'FINIUSER')
                worklist.add((library_object, addr))
                user_dict[(lib, addr)].add('FINIUSER')

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
                if user_dict_passed and lib.fullname not in user_dict[key]:
                    added = True
                user_dict[key].add(lib.fullname)
                if added:
                    worklist.add((called_lib, trans_callee))

                for user in users:
                    # Add user to callee if not already present
                    added = called_lib.add_export_user(trans_callee, user)
                    key = (called_lib.fullname, trans_callee)
                    if user_dict_passed and user not in user_dict[key]:
                        added = True
                    user_dict[key].add(user)
                    if not added:
                        continue
                    # Only insert callee if users have changed
                    worklist.add((called_lib, trans_callee))
            # Add users to accessed exported objects
            for object_addr in lib.export_object_refs[cur]:
                for user in users:
                    lib.add_object_user(object_addr, user)
            # Add users to accessed local objects
            for object_addr in lib.local_object_refs[cur]:
                for user in users:
                    lib.add_object_user(object_addr, user)
            # Add users to imported objects
            #for object_addr in lib.import_object_refs[cur]:
                #TODO: add logic from line ~290 to add users to correct imported
                # object in the relevant library
                #pass

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
                lib_dict["e_machine"] = content.e_machine
                lib_dict["ei_class"] = content.ei_class
                lib_dict["imports"] = content.imports
                dump_ordered_dict_as_list(lib_dict, content, "exported_names")
                lib_dict["export_bind"] = content.export_bind
                dump_dict_with_set_value(lib_dict, content, "export_users")
                lib_dict["function_addrs"] = list(sorted(content.function_addrs))
                dump_ordered_dict_as_list(lib_dict, content, "imports_plt")
                dump_ordered_dict_as_list(lib_dict, content, "exports_plt")
                dump_ordered_dict_as_list(lib_dict, content, "needed_libs")
                dump_ordered_dict_as_list(lib_dict, content, "all_imported_libs")
                lib_dict["rpaths"] = content.rpaths
                lib_dict["runpaths"] = content.runpaths
                dump_dict_with_set_value(lib_dict, content, "internal_calls")
                dump_dict_with_set_value(lib_dict, content, "external_calls")
                lib_dict["local_functions"] = {addr: sorted(names) \
                                               for addr, names \
                                               in content.local_functions.items()}
                dump_dict_with_set_value(lib_dict, content, "local_functions")
                dump_dict_with_set_value(lib_dict, content, "local_calls")
                dump_dict_with_set_value(lib_dict, content, "local_users")
                dump_ordered_dict_as_list(lib_dict, content, "exported_objs")
                dump_ordered_dict_as_list(lib_dict, content, "exported_obj_names")
                dump_ordered_dict_as_list(lib_dict, content, "imported_objs")
                dump_ordered_dict_as_list(lib_dict, content, "imported_objs_locations")
                dump_ordered_dict_as_list(lib_dict, content, "local_objs")
                dump_dict_with_set_value(lib_dict, content, "object_to_functions")
                dump_dict_with_set_value(lib_dict, content, "object_to_objects")
                dump_dict_with_set_value(lib_dict, content, "export_object_refs")
                dump_dict_with_set_value(lib_dict, content, "local_object_refs")
                dump_dict_with_set_value(lib_dict, content, "import_object_refs")
                dump_dict_with_set_value(lib_dict, content, "object_users")
                dump_ordered_dict_as_list(lib_dict, content, "reloc_to_local")
                dump_ordered_dict_as_list(lib_dict, content, "reloc_to_exported")
                lib_dict["init_functions"] = content.init_functions
                lib_dict["fini_functions"] = content.fini_functions

                lib_dict["ranges"] = content.ranges
                lib_dict["object_ranges"] = content.object_ranges

                lib_dict["defines_versions"] = content.defines_versions
                lib_dict["version_descriptions"] = content.version_descriptions
                lib_dict["parse_time"] = content.parse_time
                lib_dict["total_disas_time"] = content.total_disas_time

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
                        for key, value in from_dict.get(name, {}).items():
                            key = convert_key(key) if convert_key else key
                            getattr(library, name)[key] = set(value)
                    def load_ordered_dict_from_list(from_dict, library, name):
                        # Recreate order from list
                        for key, value in from_dict.get(name, []):
                            getattr(library, name)[key] = value

                    library.entrypoint = content["entrypoint"]
                    library.e_machine = content["e_machine"]
                    library.ei_class = content["ei_class"]
                    library.imports = content.get("imports", {})
                    load_ordered_dict_from_list(content, library, "exported_names")
                    library.exported_addrs = collections.defaultdict(list)
                    for name, addr in library.exported_names.items():
                        library.exported_addrs[addr].append(name)
                    library.export_bind = content["export_bind"]
                    load_dict_with_set_values(content, library, "export_users", int)
                    for key in library.exported_addrs.keys():
                        if key not in library.export_users:
                            library.export_users[key] = set()
                    library.function_addrs = set(content.get("function_addrs", []))
                    load_ordered_dict_from_list(content, library, "imports_plt")
                    load_ordered_dict_from_list(content, library, "exports_plt")
                    load_ordered_dict_from_list(content, library, "needed_libs")
                    load_ordered_dict_from_list(content, library, "all_imported_libs")
                    library.rpaths = content.get("rpaths", [])
                    library.runpaths = content.get("runpaths", [])
                    load_dict_with_set_values(content, library, "internal_calls", int)
                    load_dict_with_set_values(content, library, "external_calls", int)
                    library.local_functions = collections.defaultdict(list)
                    for addr, names in content.get("local_functions", {}).items():
                        library.local_functions[int(addr)] = names
                    load_dict_with_set_values(content, library, "local_calls", int)
                    load_dict_with_set_values(content, library, "local_users", int)

                    load_ordered_dict_from_list(content, library, "exported_objs")
                    load_ordered_dict_from_list(content, library, "exported_obj_names")
                    load_ordered_dict_from_list(content, library, "imported_objs")
                    load_ordered_dict_from_list(content, library, "imported_objs_locations")
                    load_ordered_dict_from_list(content, library, "local_objs")
                    load_dict_with_set_values(content, library, "object_to_functions", int)
                    load_dict_with_set_values(content, library, "object_to_objects", int)
                    load_dict_with_set_values(content, library, "export_object_refs", int)
                    load_dict_with_set_values(content, library, "local_object_refs", int)
                    load_dict_with_set_values(content, library, "import_object_refs", int)
                    load_dict_with_set_values(content, library, "object_users", int)
                    load_ordered_dict_from_list(content, library, "reloc_to_local")
                    load_ordered_dict_from_list(content, library, "reloc_to_exported")
                    library.init_functions = content.get("init_functions", [])
                    library.fini_functions = content.get("fini_functions", [])

                    library.ranges = {int(key):value for key, value in content.get("ranges", {}).items()}
                    library.object_ranges = {int(key):value for key, value in content.get("object_ranges", {}).items()}
                    #print('{}: {}'.format(path, sorted(["calls"].items())))
                    library.defines_versions = content.get("defines_versions", False)
                    library.version_descriptions = content.get("version_descriptions", {})
                    library.parse_time = float(content.get("parse_time", 0))
                    library.total_disas_time = float(content.get("total_disas_time", 0))
                    self._add_library(path, library)

        logging.debug('... done with %s entries', len(self))

    def generate_uprobe_strings(self, output_name, all_entries=True):
        logging.info('Generating uprobe strings to %s...', output_name)
        with open(output_name, 'w') as outfd:
            counter = 0
            for lib in self.get_entry_points(all_entries):
                for address in lib.function_addrs:
                    event_name = 'trace_probe_{}'.format(counter)
                    counter += 1
                    outfd.write('u:{} {}:{}\n'.format(event_name,
                                                      lib.fullname,
                                                      hex(address)))
        logging.info('... done!')
