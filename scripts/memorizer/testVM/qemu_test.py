#!/usr/bin/python3

# https://stackoverflow.com/questions/31304494/automation-of-processes-by-python

import os
import sys
import pexpect
import subprocess # some nonsense w/ term width makes searching the output of losetup -l not work correctly

cmds = [
    "systemctl start sshd",
    "cd /sys/kernel/debug/memorizer",
    "echo 1 > clear_dead_objects",
    "cp kmap /dev/null",
    "echo 1 > clear_printed_list",
    "echo 0 > log_live_enabled",
    "echo 1 > log_accesses_enabled",
    "echo 1 > memorizer_enabled",
    "ls -l",
    "echo 0 > memorizer_enabled",
    "echo 0 > log_accesses_enabled",
    "cp kmap /root/kmap",
    "ls /root/",
    "echo done"
]

child = pexpect.spawn("python3 -m mkosi --netdev=no --qemu-headless=yes qemu", encoding='utf-8')

child.logfile = sys.stdout
child.expect("root@VM:.*# ", timeout=100000)
for cmd in cmds:
    child.sendline(cmd)
    child.expect("root@VM:.*# ", timeout=100000)

# -o StrictHostKeyChecking=no disables the "are you sure you want to connect" message
scp_proc = pexpect.spawn("scp -B -o StrictHostKeyChecking=no -P 8888 -i id_rsa root@localhost:/root/kmap .")
scp_proc.wait()

if child.isalive():
    child.sendline('shutdown now')
    child.expect('.* reboot: Power down')

# Remove this stuff for now so we don't have to run as root

# mountpoint = '/mnt/memorizer_qemu'
# image_file = 'mz.raw'

# subprocess.run(['losetup', '-f', '-P', image_file])
# subprocess.run(['mkdir', '-p', mountpoint])

# lines = subprocess.run(['losetup', '-l'], capture_output=True).stdout.decode('utf-8').split('\n')
# devname = [line for line in lines if image_file in line][0].split(' ')[0]

# partition = devname + 'p2'
# subprocess.run(['mount', partition, mountpoint])
# subprocess.run(['cp', mountpoint + '/root/kmap', '.'])
# subprocess.run(['umount', mountpoint])
# subprocess.run(['losetup', '-d', devname])

if child.isalive():
    print('Child did not exit gracefully.')
else:
    print('Child exited gracefully.')

child.close()
