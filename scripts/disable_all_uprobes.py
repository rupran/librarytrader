#!/usr/bin/python3

import os
import sys

MOUNTPOINT='/sys/kernel/debug/tracing/'

def write_to_trace_file(path, mode, content):
    fd = os.open(MOUNTPOINT + path, mode)
    os.write(fd, content.encode())
    os.close(fd)

def disable_event(event_name):
    # print('disabling {}'.format(event_name))
    # Remove trigger
    write_to_trace_file('events/uprobes/' + event_name + '/trigger',
                        os.O_WRONLY, '!disable_event:uprobes:' + event_name)
    # Disable event
    write_to_trace_file('events/uprobes/' + event_name + '/enable',
                        os.O_WRONLY, '0')

if len(sys.argv) > 1:
    with open(sys.argv[1], 'r') as infd:
        for line in infd:
            disable_event(line.split(' ')[0][2:])
else:
    i = 0
    for folder in os.scandir(MOUNTPOINT + '/events/uprobes'):
        i += 1
        if folder.is_dir():
            disable_event(folder.name)
            if i % 1000 == 0:
                print('disabled {} events'.format(i))

write_to_trace_file('uprobe_events', os.O_WRONLY | os.O_TRUNC, '')
