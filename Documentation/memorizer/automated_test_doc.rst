===============================
Automated testing for Memorizer
===============================

The automated testing for Memorizer currently relies on the Bash Testing System (BATS). You can find the scripts for it in ``<project root>/scripts/memorizer/test``. These should be relatively self-explanatory, but there are a few wrinkles that this guide should help with.

The documentation for BATS can be found here: https://bats-core.readthedocs.io/en/stable/

Running the tests by hand
=========================

If you want to run the tests by hand, you can go to ``<project root>/scripts/memorizer/test`` and do ``./boottest.sh``. If there's no built kernel in the repo, the script will build a kernel for you. This may take quite a while, depending on your machine. The automated tests already build a kernel in a previous step, so we don't have to build the kernel twice during that process.

How this works
==============

The script builds an initramfs with Alpine Linux and BATS on it. It then runs qemu with that initramfs (and without an actual disk).

Test results
============

BATS outputs test results in a format like::

	1..5
	ok 1 memorizer exists
	ok 2 memorizer state 0 works
	ok 3 memorizer state 1 works
	ok 4 ls
	not ok 5 is 3+4=7?
	# (in test file /test/simple_test.bat, line 5)
	#   ``[[ $c == 8 ]]' failed

If the test passed, the line will start with "ok" and the test number. If it failed, there will be a "not ok" and more details.

Adding more tests
=================

The tests are located in ``<project root>/scripts/memorizer/test/root/test/``. They have the unfortunate extension ``.bat``. You can have as many tests as you want per file, so split them up however you think is most logical.

One thing I would like to be able to do in the future is either cd into a directory in a BATS test (which doesn't seem to work) or specify directories in a less verbose way than we currently have to do::

	@test "memorizer state 1 works" {
		echo -n 1 > /sys/kernel/debug/memorizer/memorizer_enabled
		grep -q "^1" /sys/kernel/debug/memorizer/memorizer_enabled
		echo -n 0 > /sys/kernel/debug/memorizer/memorizer_enabled
	}

=============================
Special considerations for CI
=============================

Getting the test results out of the VM
======================================

Reading the output of the tests is fine for testing on a local machine, but if we run them in a CI job, we want the job to fail if the tests fail, so we need to get the test results out fo the VM somehow. We do this with the following qemu arguments::

	-fsdev local,security_model=mapped,id=fsdev0,path=output -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare

The important parts here are ``path=output`` and ``mount_tag=hostshare``. The former determines the directory to share with the host. In this case it's ``output``. The latter defines a ``mount_tag`` to identify the device in ``/etc/fstab``.

In our ``init`` script (found in ``<project root>/scripts/memorizer/test/root/init``), we then map the device to ``/output``::

	echo "hostshare   /output 9p  trans=virtio,version=9p2000.L   0   0" >> /etc/fstab
	mount -a

We then write the output to ``/output/results`` on the VM when we run the tests::

	/run-test.sh 2>&1 | tee /output/results

Finally, on the host, after the VM exits, we check if ``output/results`` contains any ``not ok`` statuses::

	[ -z "$(grep '^not ok' output/results)" ] || exit 1

(This solution is largely repurposed from here: https://gist.github.com/bingzhangdai/7cf8880c91d3e93f21e89f96ff67b24b . Looking at that gist might be helpful.)

Exiting on kernel panic
=======================

Sometimes there will be bugs with Memorizer that cause the kernel to panic. In this case, we'd like the CI job to fail. This is not the default behavior with QEMU, but we can set it to work this way by doing the following things:

1. In the kernel command line, set ``panic=N``, where N is some number. This will cause the kernel to reboot after N seconds if there's a panic. You can also put ``panic=-1`` to make it reboot immediately.
2. In the qemu command line, have ``-no-reboot``. This will make qemu exit instead of rebooting.
