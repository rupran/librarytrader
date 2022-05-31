#!/usr/bin/python3

import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib

from elftools.elf.elffile import ELFFile

print('Usage: {} orig_file shrunk_file'.format(sys.argv[0]))

fd_orig = open(sys.argv[1], 'rb')
elf_orig = ELFFile(fd_orig)
fd_shrunk = open(sys.argv[2], 'rb')
elf_shrunk = ELFFile(fd_shrunk)
outfile = os.path.basename(sys.argv[1]) + '_section_sizes.pdf'

lst = []
for index, section in enumerate(elf_orig.iter_sections()):
    size_orig = section['sh_size']
    if size_orig == 0:
        continue
    section_shrunk = elf_shrunk.get_section_by_name(section.name)
    if not section_shrunk:
        break
    size_shrunk = section_shrunk['sh_size']
    print('[{}] {}: {} -> {} (-{:.3f}%)'.format(index, section.name,
                                         size_orig, size_shrunk,
                                         ((size_orig - size_shrunk) / size_orig) * 100))
    lst.append({'section': section.name, 'old size': size_orig, 'new size': size_shrunk})

last_n_equal = 0
for d in reversed(lst):
    if d['new size'] != d['old size']:
        break
    last_n_equal += 1
last_n_equal = 0

print('cutting {} last sections with matching sizes'.format(last_n_equal))
df = pd.DataFrame(lst[:len(lst) - last_n_equal], columns=['section', 'old size', 'new size'])
print(df)

fig = plt.figure()
ax1 = fig.add_subplot()
max_x = df['old size'].max()
max_x = round(max_x * 1.15)
ax3 = df.plot.barh(x='section',
#                     y=['code size after', 'code size before'],
                     y=['old size', 'new size'],
                     figsize=(7,10),
                     xlim=(0,max_x),
                     alpha=.7,
                     width=.8,
                     ax=ax1,
                     legend=True)

handles, labels = ax3.get_legend_handles_labels()
ax3.set_xlabel('Size of section in bytes')
ax3.set_ylabel('Name of ELF section')
ax3.bar_label(handles[0], padding=10, fmt='%d')
ax3.bar_label(handles[1], padding=10, fmt='%d')

ax1.invert_yaxis()
# Don't use scientific notation on the x axis
ax3.ticklabel_format(style='plain', axis='x')
ax3.get_xaxis().set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, p: '{:,}'.format(int(x)).replace(",", u"\N{thin space}")))
# Write the plot out
plt.tight_layout()
plt.savefig(outfile)
