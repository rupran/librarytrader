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

import logging
import os
import re

from librarytrader.common.datatypes import BaseStore

class LDResolve(BaseStore):

    def __init__(self, from_file=None):
        super(LDResolve, self).__init__()
        self.reload(from_file)

    def _add_or_append(self, libname, fullpath):
        if libname in self:
            self[libname].append(fullpath)
        else:
            self[libname] = [fullpath]

    def reload(self, from_file):
        self.reset()
        self.basepaths = set()

        if from_file:
            lines = open(from_file, 'r')
        else:
            lines = os.popen('/sbin/ldconfig -p')

        for line in lines:
            line = line.strip()
            match = re.match(r'(\S+)\s+\((.+)\)\s+=>\ (.+)$', line)
            if match:
                libname, fullpath = match.group(1), match.group(3)
                fullpath = os.path.abspath(fullpath)
                self._add_or_append(libname, fullpath)

                basepath = os.path.join(os.sep, *fullpath.split('/')[:-1])
                if basepath not in self.basepaths:
                    self.basepaths.add(basepath)
            else:
                logging.info('ill-formed line \'%s\'', line)

        if not len(self):
            logging.error('ldconfig info is missing!')
        else:
            logging.debug('Loaded %d entries from ldconfig', len(self))

    def get_paths(self, libname, rpaths, inherited_rpaths, runpaths):
        retval = []
        to_search = []

        if not runpaths:
            # Local rpaths first
            if rpaths:
                to_search.extend(path for path in rpaths)

            # ... then possible inherited rpaths
            if inherited_rpaths:
                to_search.extend(path for path in inherited_rpaths)
        else:
            to_search.extend(path for path in runpaths)

        for rpath in to_search:
            fullpath = os.path.abspath(os.path.join(rpath, libname))
            if not os.path.isfile(fullpath):
                continue
            retval.append(fullpath)

        # ld.so.cache lookup
        ldsocache = self.get(libname, [])
        if not ldsocache:
            logging.debug("ldconfig doesn't know %s...", libname)
        retval.extend(ldsocache)

        if not retval:
            logging.warning("no file for '%s'...", libname)
        return retval

    def search_in_ldd_paths(self, libname):
        retval = []
        for basepath in self.basepaths:
            fullpath = os.path.join(basepath, libname)
            if os.path.isfile(fullpath):
                # Add found library to resolver database
                self._add_or_append(libname, fullpath)
                retval.append(fullpath)

        return retval
