#!/bin/bash -ex

# Default values, can be overridden by arguments
U=robadams
D="/data/$U/data/$(uname -r)/$(date -Iseconds)"
H="_gateway"

MZ=/sys/kernel/debug/memorizer
TESTTYPE=dump

create_dir() {
  ssh "$U@$H" mkdir -p "$D"
}

copy_iter=0
copy() {
  # Stoopid virtual file system. scp won't copy
  # the file directly because its size is 0.
  # Here's hoping there aren't any spaces in $D, $1, or $2
  cat "$1" | ssh $U@_gateway "cat >> '$D/${2:-$1}.${copy_iter}'"
  copy_iter=$(( $copy_iter + 1 ))
}

setup() {
  cd $MZ

  # Are we in the right spot?
  cat < memorizer_enabled > /dev/null

  # Turn everything off and clear stale data
  echo 0 > memorizer_enabled
  echo 0 > memorizer_log_access
  echo 0 > cfg_log_on
  echo 0 > cfgmap
  echo 1 > clear_dead_objs
  # Adjust following line: 0 gets less data, 1 gets more data
  echo 1 > print_live_obj
  echo 1 > clear_printed_list
 }

on() {
  # Turn everything on
  echo 1 > cfg_log_on
  echo 1 > memorizer_enabled
  echo 1 > memorizer_log_access
}

off() {
  # Turn everything off
  echo 0 > memorizer_enabled
  echo 0 > memorizer_log_access
  echo 0 > cfg_log_on
}

# If we gathered any data, kmap should be non-empty
# [[ $(wc -l <kmap) != 0 ]]

# Store the data on the server
copy_all() {
  copy kmap
  copy cfgmap
  copy global_table
}

drip() {
  echo WARNING - the drip operation is a work in progress.
  echo WARNING - Using drip probably wont work.
  create_dir
  setup
  echo 0 > print_live_obj
  echo 1 > clear_printed_list

  {
    leave=false
    trap "leave=true" USR1
    while [ "$leave" = "false" ]; do
        # cat kmap
	copy kmap kmap.drip
	# wc -l kmap
        echo 1 > clear_printed_list
	sleep 5
    done # | copy - kmap.drop 
  } &
  helper=$!

  on
  "$@"
  off

  echo helper $helper dollar $$
  kill -USR1 $helper
  wait $helper

  copy_all 
}

dump() {
  create_dir
  setup
  on
  "$@"
  off
  copy_all
}

stream() {
  echo Not implemented yet
  false
}

### Main entry point

# First, parse a bunch of args

while getopts 't:u:h:' opt; do
  case "$opt" in
    u)
      U="$OPTARG"
      ;;
    h)
      H="$OPTARG"
      ;;
    t)
      TESTTYPE="$OPTARG"
      ;;
    ?)
      echo "Usage: $(basename 0) -s -u USER -h HOST -t dump|drip|stream"
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

# Now lanch the test
case "$TESTTYPE" in 
  dump )
    dump "$@"
    ;;
  stream )
    stream "$@"
    ;;
  drip )
    drip "$@"
    ;;
  * )
    echo unknown stream type "$TESTTYPE"
    exit 1
    ;;
esac

exit 0


