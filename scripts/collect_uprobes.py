#!/usr/bin/python3

import os
import sys
import time

MOUNTPOINT = '/sys/kernel/debug/tracing/'

if len(sys.argv) > 1:
    outfile = sys.argv[1]
else:
    outfile = '/tmp/collected_uprobes'

outfd = open(outfile, 'w')

folders = set(f.name for f in os.scandir(MOUNTPOINT + 'events/uprobes') if f.is_dir())
iteration = 1
changed = True

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
        time.sleep(10)
    else:
        changed = True
    iteration += 1
