import os
import re
import sys

from librarytrader.common.datatypes import BaseStore
from librarytrader.library import Library

class LibraryArchive(BaseStore):

    def __init__(self, resolver):
        super(LibraryArchive, self).__init__()
        self.resolver = resolver

    def __getitem__(self, key):
        return self.get_library(key)

    def get_library(self, path):
        result = self.get(path)
        # Symlink-like behaviour with strings
        while isinstance(result, str):
            result = self.get(result)
        return result

    def add_library(self, path, library):
        self[path] = library

    def find_compatible_libs(self, target, callback):
        for needed_name in target.needed_libs:
            for path in self.resolver.get_paths(needed_name, target.rpaths):
                if path in self:
                    needed = self[path]
                else:
                    needed = Library(path)

                if target.is_compatible(needed):
                    # Enter full path in origin
                    target.needed_libs[needed_name] = needed.fullname

                    # If we should continue processing, do the needed one next
                    if callback:
                        callback(needed)

                    # We found the compatible one, continue with next needed lib
                    break

    def resolve_libs(self, library, callback=None):
        # We were already here once, no need to go further
        if library.fullname in self:
            return

        library.parse_functions()
        library.release_elffile()

        # Add ourselves before processing children
        self.add_library(library.fullname, library)

        self.find_compatible_libs(library, callback)

    def resolve_libs_single(self, library):
        self.resolve_libs(library)

    def resolve_libs_recursive(self, library):
        self.resolve_libs(library, callback=self.resolve_libs_recursive)

    def resolve_functions(self, library):
        if not library.fullname in self:
            raise ValueError(library.fullname)

        for function in library.undefs:
            found = False
            for imp, imp_lib in library.needed_libs.items():
                if function in self[imp_lib].exported_functions:
                    print('Found {} in {}'.format(function, imp_lib))
                    found = True
                    break
            if not found:
                # TODO: consider symbol versioning?
                print('Did not find {}'.format(function))


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
                print("WARN: ill-formed line '{}'".format(line),
                      file=sys.stderr)

    def get_paths(self, libname, rpaths):
        retval = self.get(libname, [])
        if not retval:
            print("WARN: ldconfig doesn't know {}...".format(libname),
                  file=sys.stderr)
            for rpath in rpaths:
                retval.append(os.path.abspath(os.path.join(rpath, libname)))
        if not retval:
            print("WARN: really returning nothing...", file=sys.stderr)
        return retval
