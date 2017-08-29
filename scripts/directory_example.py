#!/usr/bin/env python3
#
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

import argparse
import logging
import os
import sys

from librarytrader.directoryscan import DirectoryScan

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan a directory and ' \
        'resolve functions between libraries inside the directory.')
    parser.add_argument('target', type=str,
                        help='the directory containing all libraries')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose output')
    parser.add_argument('--debug', action='store_true',
                        help=argparse.SUPPRESS)

    args = parser.parse_args()

    loglevel = logging.WARNING
    if args.verbose:
        loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG

    logging.basicConfig(level=loglevel)

    if not os.path.isdir(args.target):
        sys.exit("Error: {} is not a directory!".format(args.target))

    scanner = DirectoryScan(args.target)
    scanner.read_libraries()
    scanner.try_resolve()
    scanner.print_imports_exports('libc')
