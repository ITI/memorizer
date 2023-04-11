#!/bin/bash -ex

U=robadams
D="/data/$U/data/$(uname -r)/$(date -Iseconds)"
ssh "$U@_gateway" mkdir -p "$D"

function copy() {
  # Stoopid virtual file system. scp won't copy
  # the file directly because its size is 0.
  # Here's hoping there aren't any spaces in $D, $1, or $2
  cat "$1" | ssh $U@_gateway "cat > $D/${2:-$1}"
}

cd /sys/kernel/debug/memorizer

# Turn everything off and clear stale data
echo 0 > memorizer_enabled
echo 0 > memorizer_log_access
echo 0 > cfg_log_on
echo 0 > cfgmap
echo 1 > clear_dead_objs
# Adjust following line: 0 gets less data, 1 gets more data
echo 1 > print_live_obj
echo 1 > clear_printed_list

# Given above config, kmap should be empty
# [[ $(wc -l <kmap) == 0 ]]

# Turn everything on
echo 1 > cfg_log_on
echo 1 > memorizer_enabled
echo 1 > memorizer_log_access

# Run some test.
"$@"

# Turn everything off
echo 0 > memorizer_enabled
echo 0 > memorizer_log_access
echo 0 > cfg_log_on

# If we gathered any data, kmap should be non-empty
# [[ $(wc -l <kmap) != 0 ]]

# Store the data on the server
copy kmap
copy cfgmap
copy global_table
