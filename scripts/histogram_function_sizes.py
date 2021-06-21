#!/usr/bin/env python3

import collections
import matplotlib.pyplot as plt
import statistics
import sys

from librarytrader.librarystore import LibraryStore

#if len(sys.argv) >= 4:
print('Arguments: {} <librarystore> <output_filename> [cutoff_x]'.format(sys.argv[0]))
#    sys.exit(1)

print(' * Loading LibraryStore...')
store = LibraryStore()
store.load(sys.argv[1])
print(' * ... done!')
hist = collections.defaultdict(int)

n = 0
print(' * Generating histogram...')
for library in store.get_library_objects():
    for value in library.ranges.values():
        if value == 0:
            continue
        hist[value] += 1
        n += 1
print(' * ... done!')

xs = []
ys = []
for x, y in sorted(hist.items()):
    xs.append(x)
    ys.append(y)

print(' * Statistics:')
listed_items = []
for size, number in sorted(hist.items()):
    listed_items.extend([size] * number)

print(len(listed_items), n)
print(' * .. Mean:   {}'.format(statistics.mean(listed_items)))
print(' * .. Median: {}'.format(statistics.median(listed_items)))
print(' * .. Max:    {}'.format(listed_items[-1]))

print(' * Plotting...')
fig, ax = plt.subplots(figsize=(12.8,9.6))
plt.bar(xs, ys, width=1.2)
if len(sys.argv) >= 4:
    max_x = int(sys.argv[3])
else:
    max_x = ax.get_xlim()[1]
ax.set_xlim(-10, max_x)
plt.xlabel('Size of function in bytes')
plt.ylabel('Number of functions with respective size')
print(' * ... done!')
print(' * Saving to {}'.format(sys.argv[2]))
plt.savefig(sys.argv[2])
plt.show()
