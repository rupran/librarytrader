import os
import re
import sys

class BaseStore:

    def __init__(self):
        self.storage = {}

    def __setitem__(self, key, value):
        self.storage[key] = value

    def __getitem__(self, key):
        return self.storage[key]

    def __iter__(self):
        return iter(self.storage)

    def __len__(self):
        return len(self.storage)

    def __contains__(self, key):
        return key in self.storage

    def get(self, key, default=None):
        if key in self.storage:
            return self.storage[key]
        else:
            return default


class LDResolve(BaseStore):

    def __init__(self):
        super(LDResolve, self).__init__()

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
                print("WARN: ill-formed line '{}'".format(line), file=sys.stderr)

    def get_paths(self, libname):
        return self.get(libname)


class LibraryArchive(BaseStore):

    def get_library(self, path):
        return self.get(path)

    def add_library(self, path, library):
        self[path] = library


