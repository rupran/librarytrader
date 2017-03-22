import os
import re
import sys

from common.datatypes import BaseStore

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


class LibraryArchive(BaseStore):

    def get_library(self, path):
        result = self.get(path)
        # Symlink-like behaviour with strings
        while isinstance(result, str):
            result = self.get(result)
        return result

    def __getitem__(self, key):
        return self.get_library(key)

    def add_library(self, path, library):
        self[path] = library
