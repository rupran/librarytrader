#!/usr/bin/python3

import os
import sys
import time

MOUNTPOINT = '/sys/kernel/debug/tracing/'

if len(sys.argv) > 1:
    outfile = sys.argv[1]
else:
    outfile = '/tmp/collected_uprobes'

max_unchanged_rounds = -1
if len(sys.argv) > 2:
    max_unchanged_rounds = int(sys.argv[2])


outfd = open(outfile, 'w')

folders = set(f.name for f in os.scandir(MOUNTPOINT + 'events/uprobes') if f.is_dir())
iteration = 1
changed = True
unchanged_rounds = 0

while folders:
    if changed:
        print('Starting round {} with {} active events'.format(iteration, len(folders)))
        sys.stdout.flush()
    changed = False
    removed = set()
    for name in folders:
        event_dir = MOUNTPOINT + 'events/uprobes/' + name + '/'
        with open(event_dir + 'enable', 'r') as fd:
            status = fd.readline().strip()
            if status == '0*':
                with open(event_dir + 'trigger', 'w') as triggerfd:
                    triggerfd.write('!disable_event:uprobes:{}'.format(name))
                    outfd.write('{}\n'.format(name))
                    #print('disabled {}'.format(name))
                    removed.add(name)
            elif status == '0':
                #print('disabled {}'.format(name))
                outfd.write('{}\n'.format(name))
                removed.add(name)

    folders = folders.difference(removed)
    outfd.flush()
    if len(removed) == 0:
        unchanged_rounds += 1
        if max_unchanged_rounds > 0 and unchanged_rounds == max_unchanged_rounds:
            break
        time.sleep(10)
    else:
        unchanged_rounds = 0
        changed = True
    iteration += 1
