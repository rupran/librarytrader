import matplotlib.pyplot as plt
import pandas as pd
import os
import seaborn
import sys

from matplotlib import gridspec, rcParams

def change_width(ax, new_value):
    for patch in ax.patches:
        current_width = patch.get_width()
        diff = current_width - new_value

        # we change the bar width
        patch.set_width(new_value)

        # we recenter the bar
        patch.set_x(patch.get_x() + diff * .5)

infile = 'tailored_libs_clang.json/stats.csv'
outfile = 'bla.svg'
if len(sys.argv) > 1:
    infile = sys.argv[1]
if len(sys.argv) > 2:
    outfile = sys.argv[2]

rcParams.update({'figure.figsize': (9,6)})

# Read and enhance datafile
df = pd.read_csv(infile)
df['f_after'] = df['exported functions after'] + df['local functions after']
df['f_before'] = df['exported functions before'] + df['local functions before']
df['filename'] = df['filename'].apply(lambda x: os.path.basename(x))

# Sort dataframe by code size
df_s = df.sort_values(by='code size before', ascending=False)

# seaborn:
data = df_s[['filename', 'code size before', 'code size after']].melt('filename')
ax = seaborn.barplot(x='filename',
                     y='value',
                     hue='variable',
                     data=data)
ax.ticklabel_format(style='plain', axis='y')

change_width(ax, .30)

handles, labels = ax.get_legend_handles_labels()
# Switch the order of data labels in the legend
#order = [1,0]
#plt.legend([handles[idx] for idx in order],
plt.legend(handles,
        ['Bytes of functions before removal', 'Bytes of functions after removal'],
        loc='upper right',
#        fontsize='large',
        bbox_to_anchor=(.95,.9))

ax.set_xlabel('Library filename')
ax.set_ylabel('Number of code bytes in file')
ax.set_ylim((0, 1100000))
ax.bar_label(handles[0], padding=10, fmt='%d')
ax.bar_label(handles[1], padding=10, fmt='%d')

# Write the plot out
plt.tight_layout()
plt.savefig(outfile)
