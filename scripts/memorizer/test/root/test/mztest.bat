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
