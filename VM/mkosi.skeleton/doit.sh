#!/bin/bash -ex

cd /sys/kernel/debug/memorizer

#cfg_log_on
#cfgmap
#clear_dead_objs
#clear_printed_list
#global_table
#kmap
echo 0 > memorizer_enabled
echo 0 > memorizer_log_access
echo 1 > clear_dead_objs
echo 0 > print_live_obj
echo 1 > clear_printed_list
[[ $(wc -l <kmap) == 0 ]]

echo 1 > memorizer_enabled
echo 1 > memorizer_log_access
/bin/ls
echo 0 > memorizer_enabled
echo 0 > memorizer_log_access
[[ $(wc -l <kmap) != 0 ]]
wc -l kmap
wc -l kmap
cp kmap /tmp/kmap
scp /tmp/kmap robadams@10.0.2.2:/data/robadams/data/$(uname -r)/$(date -Iseconds)
#print_live_obj
#show_stats
#stack_trace_on
