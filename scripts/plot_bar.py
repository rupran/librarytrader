import matplotlib.pyplot as plt
import pandas as pd
import os
import sys

from matplotlib import gridspec

infile = 'tailored_libs_clang.json/stats.csv'
outfile = 'bla.svg'
if len(sys.argv) > 1:
    infile = sys.argv[1]
if len(sys.argv) > 2:
    outfile = sys.argv[2]

# Read and enhance datafile
df = pd.read_csv(infile)
df = df[2:]
df['f_after'] = df['exported functions after'] + df['local functions after']
df['f_before'] = df['exported functions before'] + df['local functions before']
df['filename'] = df['filename'].apply(lambda x: os.path.basename(x))

#fig = plt.figure()
#spec = gridspec.GridSpec(ncols=1, nrows=2, height_ratios=[5,1], wspace=0.5)

# Sort dataframe by code size
df_s = df.sort_values(by='code size before', ascending=False)

# seaborn:
# data=df_s[['filename', 'code size after', 'code size before']].melt('filename')
# ax = seaborn.barplot(x='filename', y='value', hue='variable', data=data)
# ax.ticklabel_format(style='plain', axis='x')
# ax.bar_label() as below

# Generate the bar plot (TODO: try subplots)
#ax1 = fig.add_subplot(spec[0])
ax3 = df_s.plot.barh(x='filename',
#                     y=['code size after', 'code size before'],
                     y=['parse time', 'disas time', 'shrink time'],
                     figsize=(14,10),
#                     xlim=(0,1000000),
                     alpha=.7,
                     width=.8,
#                     ax=ax1,
                     legend=True,
                     stacked=True)

handles, labels = ax3.get_legend_handles_labels()
# Switch the order of data labels in the legend
order = [1,0]
#plt.legend([handles[idx] for idx in order],
#        ['Bytes of functions before removal', 'Bytes of functions after removal'],
#        loc='upper right',
#        fontsize='x-large',
#        bbox_to_anchor=(.9,.9))

#ax2 = fig.add_subplot(spec[1])
#ax4 = df_s[:2].plot.barh(x='filename',
#                         y=['code size after', 'code size before'],
#                         figsize=(14,10),
#                         xlim=(0,35000000),
#                         alpha=.7,
#                         width=.8,
#                         ax=ax2,
#                         legend=False)

# Get the current axes handles and labels
#handles, labels = ax4.get_legend_handles_labels()
# Switch the order of data labels in the legend
#order = [1,0]
#plt.legend([handles[idx] for idx in order],
#        ['Bytes of functions before removal', 'Bytes of functions after removal'],
#        loc='upper right',
#        fontsize='x-large',
#        bbox_to_anchor=(.9,.9))

for ax in (ax3,):
    handles, labels = ax.get_legend_handles_labels()
# Add the labels to both handles
#    ax.set_xlabel('Number of code bytes in file')
    ax.set_xlabel('Processing time')
    ax.set_ylabel('Library filename')
    ax.bar_label(handles[0], padding=20, fmt='%.2f')
    ax.bar_label(handles[1], padding=10, fmt='%.2f')
    ax.bar_label(handles[2], padding=40, fmt='%.2f')

# Don't use scientific notation on the x axis
    ax.ticklabel_format(style='plain', axis='x')
# Write the plot out
plt.tight_layout()
plt.savefig(outfile)
