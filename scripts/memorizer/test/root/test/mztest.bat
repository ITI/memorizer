@test "memorizer exists" {
	[ -f /sys/kernel/debug/memorizer/memorizer_enabled ]
}

@test "memorizer state 0 works" {
	echo -n 0 > /sys/kernel/debug/memorizer/memorizer_enabled
	grep -q "^0" /sys/kernel/debug/memorizer/memorizer_enabled
}

@test "memorizer state 1 works" {
	echo -n 1 > /sys/kernel/debug/memorizer/memorizer_enabled
	grep -q "^1" /sys/kernel/debug/memorizer/memorizer_enabled
	echo -n 0 > /sys/kernel/debug/memorizer/memorizer_enabled
}

@test "ls" {
	echo -n 1 > /sys/kernel/debug/memorizer/clear_dead_objects
	cp /sys/kernel/debug/memorizer/kmap /dev/null
	echo -n 1 > /sys/kernel/debug/memorizer/clear_printed_list
	echo -n 0 > /sys/kernel/debug/memorizer/log_live_enabled
	echo -n 1 > /sys/kernel/debug/memorizer/log_accesses_enabled
	echo -n 1 > /sys/kernel/debug/memorizer/memorizer_enabled
	ls -l /sys/kernel/debug/memorizer
	echo -n 0 > /sys/kernel/debug/memorizer/memorizer_enabled
	echo -n 0 > /sys/kernel/debug/memorizer/log_accesses_enabled
	cp /sys/kernel/debug/memorizer/kmap /root/kmap
	ls /root/
	echo done
}
