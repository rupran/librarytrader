#!/usr/bin/env python3

import collections
import matplotlib.pyplot as plt
import pandas
import statistics
import sys

from librarytrader.librarystore import LibraryStore

#if len(sys.argv) >= 4:
print('Arguments: {} <librarystore> <output_filename> [cutoff_x]'.format(sys.argv[0]))
#    sys.exit(1)

print(' * Loading LibraryStore...')
store = LibraryStore()
store.load(sys.argv[1])
print('  * ... done!')

print(' * Collecting all non-zero ranges...')
all_ranges = [size for library in store.get_library_objects()
              for size in library.ranges.values() if size > 0]
print('  * ... done!')

df = pandas.DataFrame(all_ranges, columns=["Function Size"])

if len(sys.argv) >= 4:
    max_x = int(sys.argv[3])
else:
    max_x = df["Function Size"].max()

print(' * Statistics:')
print('  * Number of ranges: {}'.format(len(all_ranges)))
print('  * .. Mean:   {}'.format(df["Function Size"].mean()))
print('  * .. Median: {}'.format(df["Function Size"].median()))
print('  * .. Max:    {}'.format(df["Function Size"].max()))

print(' * Plotting...')
xlim = (-10, max_x)
ax = df.plot.hist(xlim=xlim,
                  bins=range(0, max_x+2, 1),
                  figsize=(12.8, 9.6))
plt.xlabel('Size of function in bytes')
plt.ylabel('Number of functions with respective size')
print('  * ... done!')
print(' * Saving to {}'.format(sys.argv[2]))
plt.savefig(sys.argv[2])
print('  * ... done!')
plt.show()
