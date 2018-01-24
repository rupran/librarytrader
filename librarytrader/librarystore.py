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
from multiprocessing import Pool, Manager

from elftools.common.exceptions import ELFError
from librarytrader.library import Library
from librarytrader.ldresolve import LDResolve

def _get_or_create_library(store, path):
    link_path = None

    if os.path.islink(path) or \
            os.path.abspath(os.path.dirname(path)) != \
            os.path.realpath(os.path.abspath(os.path.dirname(path))):
        link_path = path
        path = os.path.realpath(path)

    if path in store:
        retval = (get_from_path(store, path), link_path)
        return retval

    try:
        retval = (Library(path), link_path)
        return retval
    except (ELFError, OSError) as err:
        logging.warning('\'%s\' => %s', path, err)
        return (None, None)

def get_from_path(store, path):
    result = store.get(path)
    # Symlink-like behaviour with strings
    while isinstance(result, str):
        result = store.get(result)
    return result

def _add_library(store, path, library):
    if path not in store:
        store[path] = library

def _get_compatible_libs(store, target, paths):
    retval = []
    for path in paths:
        needed, link_path = _get_or_create_library(store, path)
        if not needed:
            continue

        if target.is_compatible(needed):
            retval.append((needed, link_path))

    return retval

def _find_compatible_libs(store, resolver, target, callback, inherited_rpaths=None):
    for needed_name in target.needed_libs:
        rpaths = resolver.get_paths(needed_name, target.rpaths,
                                    inherited_rpaths, target.runpaths)

        # Try to find compatible libs from ldconfig and rpath alone
        possible_libs = _get_compatible_libs(store, target, rpaths)

        # If that fails, try directly probing filenames in the directories
        # ldconfig shows as containing libraries
        if not possible_libs:
            logging.debug('File system search needed for \'%s\'', needed_name)
            fs_paths = resolver.search_in_ldd_paths(needed_name)
            possible_libs = _get_compatible_libs(store, target, fs_paths)

        for needed, link_path in possible_libs:
            # If path was a symlink and we are in recursive mode,
            # add link to full name to store
            if link_path and callback:
                _add_library(store, link_path, needed.fullname)
            # Enter full path to library for DT_NEEDED name
            target.needed_libs[needed_name] = needed.fullname

            # If we should continue processing, do the needed one next
            if callback:
                next_rpaths = []
                #TODO correct passdown behaviour if DT_RUNPATH is set?
                if not target.runpaths:
                    if inherited_rpaths:
                        next_rpaths.extend(inherited_rpaths)
                    if target.rpaths:
                        next_rpaths.extend(target.rpaths)

                callback(store, resolver, needed, inherited_rpaths=next_rpaths)

            # We found the compatible one, continue with next needed lib
            break

def _resolve_libs(store, resolver, library, path="", callback=None,
                  inherited_rpaths=None):
    if not library:
        library, link_path = _get_or_create_library(store, path)
        if not library:
            # We had an error, so nothing can be processed
            return
        elif link_path:
            _add_library(store, link_path, library.fullname)

    if library.fullname in store:
        # We were already here once, no need to go further
        return

    logging.info('Resolving %s', library.fullname)

    # Process this library
    library.parse_functions(release=True)

    # Find and resolve imports
    _find_compatible_libs(store, resolver, library, callback, inherited_rpaths)

    # Add ourselves after processing imports (when we're really done)
    _add_library(store, library.fullname, library)

def resolve_libs_single(store, resolver, library, path=""):
    _resolve_libs(store, resolver, library, path)

def resolve_libs_single_by_path(store, resolver, path):
    resolve_libs_single(store, resolver, None, path)

def resolve_libs_recursive(store, resolver, library, path="", inherited_rpaths=None):
    _resolve_libs(store, resolver, library, path, callback=resolve_libs_recursive,
                  inherited_rpaths=inherited_rpaths)

def resolve_libs_recursive_by_path(store, resolver, path):
    resolve_libs_recursive(store, resolver, None, path)

def resolve_functions(store, library):
    if isinstance(library, str):
        name = library
        library = get_from_path(store, library)
        if library is None:
            logging.error('Did not find library \'%s\'', name)
            return

    if library.fullname not in store:
        #TODO: self.resolve_libs_recursive(library)?
        raise ValueError(library.fullname)

    logging.debug('Resolving functions in %s', library.fullname)

    result = collections.OrderedDict()

    for function in library.imports:
        found = False
        for needed_name, needed_path in library.all_imported_libs.items():
            imp_lib = get_from_path(store, needed_path)
            if not imp_lib:
                logging.warning('|- data for \'%s\' not available in %s!',
                                needed_name, library.fullname)
                continue

            if function in imp_lib.exports:
                result[function] = needed_path
                library.imports[function] = needed_path
                logging.debug('|- found \'%s\' in %s', function,
                              needed_path)
                found = True
                break

        if not found:
            # TODO: consider symbol versioning?
            logging.error('|- did not find function \'%s\' from %s',
                          function, library.fullname)

    return result

def resolve_all_functions(store):
    result = {}
    libobjs = list(val for (key, val) in store.items()
                   if not isinstance(val, str))

    # Initialize data for known libraries
    for lib in libobjs:
        result[lib.fullname] = {}
        for function in lib.exports:
            result[lib.fullname][function] = []

    # Count references across libraries
    for lib in libobjs:
        resolved = resolve_functions(store, lib)
        for function, fullname in resolved.items():
            result[fullname][function].append(lib.fullname)

    return result

def dump(input_dict, output_file):
    logging.debug('Saving results to \'%s\'', output_file)

    output = {}
    for key, value in input_dict.items():
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

        output[key] = lib_dict

    with open(output_file, 'w') as outfd:
        json.dump(output, outfd)

def load(input_file, output_dict):
    output_dict.clear()

    logging.debug('loading input from \'%s\'...', input_file)
    with open(input_file, 'r') as infd:
        in_dict = json.load(infd)
        for key, value in sorted(in_dict.items()):
            logging.debug("loading %s -> %s", key, value["type"])
            if value["type"] == "link":
                _add_library(output_dict, key, value["target"])
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
                _add_library(output_dict, key, library)

                logging.debug('%s => %s %s', key, library.needed_libs, library.all_imported_libs)

    logging.debug('... done with %s entries', len(output_dict))

def mp_launch(param):
    args, single = param
    if single:
        resolve_libs_single_by_path(*args)
    else:
        resolve_libs_recursive_by_path(*args)

def fill_all_needed(lib, store, cache):
    library = get_from_path(store, lib)
    if not library:
        return []
    if lib not in cache:
        worklist = collections.deque((k, v) for k, v in library.needed_libs.items())
        while worklist:
            cur_k, cur_v = worklist.popleft()
            if cur_k in library.all_imported_libs.keys():
                continue

            library.all_imported_libs[cur_k] = cur_v
            # appendleft attaches items in reverse order, so we need to reverse
            # the output of the recursive descent to have them in the worklist
            # in the correct (forward) order.
            worklist.extendleft(reversed(fill_all_needed(cur_v, store, cache)))

        cache[lib] = library.all_imported_libs.items()
        return cache[lib]
    else:
        return cache[lib]

def process_from_list(paths, n_procs, single=False):
    pool = Pool(n_procs)
    manager = Manager()
    store = manager.dict()
    resolver = LDResolve()
    inp = []
    for path in paths:
        inp.append(((store, resolver, path), single))

    logging.info('Starting library parsing...')
    pool.map(mp_launch, inp, chunksize=50)
    pool.close()
    pool.join()
    logging.info('... done!')

    # Convert to local dict
    store = dict(store)

    worklist = collections.deque([v for _, v in store.items() if isinstance(v, Library)])
    all_needed_cache = {}

    logging.info('Starting reconstruction of all_imported_libs...')
    initial_len = len(worklist)
    for idx, lib in enumerate(worklist):
        fill_all_needed(lib.fullname, store, all_needed_cache)
        if idx % 1000 == 0:
            logging.info('%d/%d done...', idx, initial_len)
    logging.info('... done!')

    logging.info('Crossreference all functions...')
    resolve_all_functions(store)
    logging.info('... done!')

    return store
