#!/usr/bin/python3

import os
import sys

MOUNTPOINT = '/sys/kernel/debug/tracing/'

def read_from_trace_file(relpath):
    with open(MOUNTPOINT + relpath, 'r') as fdesc:
        return fdesc.readlines()

def write_to_trace_file(relpath, fmode, content):
    fdesc = os.open(MOUNTPOINT + relpath, fmode)
    try:
        os.write(fdesc, content.encode())
    finally:
        os.close(fdesc)

if __name__ == '__main__':
    with open(sys.argv[1], 'r') as infd:
        events = len(read_from_trace_file('uprobe_events'))
        for line in infd:
            # If there were events already in the uprobe_events file, we need to
            # append new events, otherwise we can truncate the file.
            if events:
                mode = os.O_WRONLY | os.O_APPEND
            else:
                mode = os.O_WRONLY | os.O_TRUNC

            # Write the event into the uprobe event list
            try:
                write_to_trace_file('uprobe_events', mode, line)
            except Exception:
                print('Error in line {}'.format(line))
                continue

            name = line.split(' ')[0][2:]
            try:
                # Write the self-disabling trigger - this might fail with -ENOSUPP
                # if the probe point can not be patched (e.g., there might be a
                # lock prefix in the instruction - for a detailed list, see
                # arch/x86/kernel/uprobes.c:is_prefix_bad in the Linux kernel).
                path = 'events/uprobes/' + name + '/trigger'
                trigger = 'disable_event:uprobes:{}'.format(name)
                write_to_trace_file(path, os.O_WRONLY | os.O_TRUNC, trigger)
                events += 1
            except Exception:
                print('Error at line {}'.format(line))
                # If writing the trigger for the same event has failed, enabling
                # the event would later fail as well. Let's remove it entirely here
                # so the enable call later will succeed.
                write_to_trace_file('uprobe_events', os.O_WRONLY | os.O_APPEND,
                                    '-:{}'.format(name))
                continue

        # Finally enable all uprobes at once.
        write_to_trace_file('events/uprobes/enable', os.O_WRONLY, '1')
        print('Enabled {} uprobes'.format(events))

    sys.exit(0)
