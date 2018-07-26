#!/bin/bash

TRACEDIR="/sys/kernel/debug/tracing"
LIBDL="/lib/x86_64-linux-gnu/libdl.so.2"
DLOPEN_OFFSET=$(readelf -s $LIBDL | grep dlopen | awk -e '{print $2}')
DLSYM_OFFSET=$(readelf -s $LIBDL | grep dlsym | awk -e '{print $2}')
if [ -z "$DLOPEN_OFFSET" ] || [ -z "$DLSYM_OFFSET" ]; then
	echo "dlopen/dlsym not found, exiting..."
	exit 1;
fi
HEX_DLOPEN_OFFSET="0x$DLOPEN_OFFSET"
HEX_DLSYM_OFFSET="0x$DLSYM_OFFSET"

echo 0 > "$TRACEDIR/events/uprobes/enable"
echo 65536 > "$TRACEDIR/buffer_size_kb"
echo "p:dlopen $LIBDL:$HEX_DLOPEN_OFFSET +0(%di):string" > "$TRACEDIR/uprobe_events"
echo "r:dlopen_ret $LIBDL:$HEX_DLOPEN_OFFSET %ax:x64" >> "$TRACEDIR/uprobe_events"
echo "p:dlsym $LIBDL:$HEX_DLSYM_OFFSET %di:x64 +0(%si):string" >> "$TRACEDIR/uprobe_events"
echo 1 > "$TRACEDIR/events/uprobes/enable"
