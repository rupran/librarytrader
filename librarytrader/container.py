import collections
import json
import logging
import os
import re
import sys

from elftools.common.exceptions import ELFError

from librarytrader.common.datatypes import BaseStore
from librarytrader.library import Library


class LibraryStore(BaseStore):

    def __init__(self):
        super(LibraryStore, self).__init__()
        self.resolver = LDResolve()

    def create_library(self, path):
        if path in self:
            return self[path]

        if os.path.islink(path):
            target = os.path.realpath(path)
            if target in self:
                self.add_library(path, target)
                return self[target]

        try:
            return Library(path)
        except (ELFError, FileNotFoundError) as err:
            logging.error("'{}' => {}".format(path, err))
            return None

    def get_library(self, path):
        result = self.get(path)
        # Symlink-like behaviour with strings
        while isinstance(result, str):
            result = self.get(result)
        return result

    def add_library(self, path, library):
        self[path] = library

    def _find_compatible_libs(self, target, callback):
        for needed_name in target.needed_libs:
            for path in self.resolver.get_paths(needed_name, target.rpaths):
                if path in self:
                    needed = self.get_library(path)
                else:
                    needed = self.create_library(path)
                    if not needed:
                        continue

                if target.is_compatible(needed):
                    # Enter full path in origin
                    target.needed_libs[needed_name] = needed.fullname

                    # If we should continue processing, do the needed one next
                    if callback:
                        callback(needed)

                    # We found the compatible one, continue with next needed lib
                    break

    def _resolve_libs(self, library, path="", callback=None):
        if not library:
            library = self.create_library(path)

        if not library or library.fullname in self:
            # We had an error or were already here once, no need to go further
            return

        library.parse_functions(release=True)

        # Check for symlink, add redirection and set name to target of symlink
        filename = library.fullname
        if os.path.islink(filename):
            target = os.path.realpath(library.fullname)

            self.add_library(filename, target)
            library.fullname = target

        # Add ourselves before processing children
        self.add_library(library.fullname, library)

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
        if library.fullname not in self:
            #TODO: self.resolve_libs_recursive(library)?
            raise ValueError(library.fullname)

        result = collections.OrderedDict()

        for function in library.imports:
            found = False
            for _, imp_lib in library.needed_libs.items():
                if function in self[imp_lib].exports:
                    result[function] = imp_lib
                    found = True
                    break
            if not found:
                # TODO: consider symbol versioning?
                logging.warning('Did not find {}'.format(function))

        return result

    def dump(self, output_file):
        logging.debug('Saving results to \'{}\''.format(output_file))

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

        logging.debug('loading input from \'{}\'...'.format(input_file))
        with open(input_file, 'r') as infd:
            in_dict = json.load(infd)
            for key, value in in_dict.items():
                logging.debug("loading {} -> {}".format(key, value["type"]))
                if value["type"] == "link":
                    self.add_library(key, value["target"])
                else:
                    library = Library(key, load_elffile=False)
                    library.imports = value["imports"]
                    library.exports = value["exports"]
                    library.needed_libs = value["needed_libs"]
                    library.rpaths = value["rpaths"]
                    self.add_library(key, library)

        logging.debug('... done with {} entries'.format(len(self)))
 

class LDResolve(BaseStore):

    def __init__(self):
        super(LDResolve, self).__init__()
        self.reload()

    def reload(self):
        self.reset()
        lines = os.popen('/sbin/ldconfig -p')
        for line in lines.readlines()[1:]:
            line = line.strip()
            match = re.match(r'(\S+)\s+\((.+)\)\s+=>\ (.+)$', line)
            if match:
                libname, fullpath = match.group(1), match.group(3)
                if libname in self:
                    self[libname].append(fullpath)
                else:
                    self[libname] = [fullpath]
            else:
                logging.warning("ill-formed line '{}'".format(line))

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
            logging.warning("ldconfig doesn't know {}...".format(libname))
        retval.extend(ldsocache)

        if not retval:
            logging.warning("no file for '{}'...".format(libname))
        return retval
