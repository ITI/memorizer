# Automated testing for Memorizer

While the testing itself is automated, setting it up to actually function is complex, and may be difficult to debug if it breaks. This guide will explain how it works, in the hope that by reading it you can avoid some of the misery and torment I subjected myself to.

# Running the test by hand

First I'm going to explain how to do the process we do in the current (single) automated test by hand so you know how it works. It consists of a couple basic steps:
1. Building the kernel
2. Building and running a VM
3. Running the test
4. Extracting the `kmap` file from the VM

## Building the kernel

See https://code.iti.illinois.edu/ring0/memorizer/-/wikis/make

## Building and running a VM

TL;DR:
```
cd scripts/memorizer/testVM
python3 -m venv .venv
source .venv/bin/activate
git clone --branch v14 https://github.com/systemd/mkosi.git
python3 -m pip install ./mkosi
sudo mkosi build
mkosi qemu
```

---

Now that we have a kernel, we need to run it in a VM for automated tests. This is so we don't have to allocate a machine specifically for testing Memorizer and worry about the networking of that machine and what is allowed to connect to it and whether it's physically plugged in.

QEMU needs 3 things to run: A kernel, an initrd, and an OS image. We already have a kernel from step 1. I bashed my head against a brick wall for a while trying to figure out how to get the other two things by hand. Don't do that. Just use `mkosi`.

The file `mkosi.conf` contains the configuration for the image. You want to make sure you have `QemuHeadless=yes` in there (or pass `--qemu-headless=yes` from the command line; all the options can be passed in this way) so you don't have to mess around with a graphical window (which is a problem for automated tests). Other options of note are `QemuKvm`, which enables KVM acceleration (makes the vm faster) and `Ssh`, which installs `sshd` on the machine and generates a key for us to log into it. Confusingly, the `Password` option in `mkosi.conf` specifies the password for that key, not for the root account in the image.

You can build the image with `mkosi build` (you will probably need to use `sudo`. Also you might want to add the `--force` flag if you want to overwrite an image you've already built). Once you've generated the image, you can run it with `mkosi qemu`, which generates a horrible qemu command using the parameters in `mkosi.conf` so you don't have to worry about creating it manually.

There's a `mkosi.conf` with good configuration for automated testing in `scripts/memorizer/testVM`. I suggest using that one as a starting point if you're trying to replicate this process.

So you should be able to cd `scripts/memorizer/testVM` and do `mkosi build`, right? Well, probably you can, but I can't guarantee anything will work correctly. The problem is that different versions of `mkosi` have different options, and treat the files differently. So you need to have the right version of `mkosi` installed. For the configs in this project, that's version 14. This is especially true for the `mkosi.conf` in `scripts/memorizer/VM`, which only seems to work with that version. You can install mkosi 14 by doing:
```
git clone --branch v14 https://github.com/systemd/mkosi.git
python3 -m pip install ./mkosi
```

(You might want to do this in a venv if you want to avoid installing old things in your normal Python environment. You can do this by running `python3 -m venv .venv` and then `source .venv/bin/activate` before running the `pip install` command. See [here](https://docs.python.org/3/library/venv.html) for more info.)

## Running the test

An example of a simple test is:

```
cd /sys/kernel/debug/memorizer
echo 1 > clear_dead_objs
cp kmap /dev/null
echo 1 > clear_printed_list
echo 0 > print_live_obj
echo 1 > memorizer_log_access
echo 1 > memorizer_enabled
ls -l
echo 0 > memorizer_enabled
echo 0 > memorizer_log_access
```

This should generate a file called `kmap` which contains information about all the memory allocations recorded by Memorizer.

## How to get the `kmap` file off the VM

Once we've run the VM and done our tests, we'll have a `kmap` file. We want to get this file out of the VM so we can look at it with other tools. There are two ways to do this.

### Loopback device

One way is to use a loopback device. Unfortunately this doesn't work super well for automated tests, because it requires root, and uses kernel functionality that [doesn't seem to be supported inside containers.](https://github.com/systemd/mkosi/issues/248). It's also super complicated and annoying to automate.

Another reason I don't like loopback devices is because they require root, which means you need to give the runner root privileges (or let it sudo without a password). This is slightly sketchy on any system that's going to be running for a long time, and especially bad on a system that's being used for other things, since a test that does something bad to the system could mess it up for anyone/anything else using it.

Luckily, there's another way.

### scp

TL;DR:
```
cd scripts/memorizer/testVM
mkosi build
mkosi --netdev=no qemu
# Run the tests
# On another terminal, do:
scp -P 8888 -i id_rsa root@localhost:/tmp/kmap .
```

---

To do this, you can build the mkosi image with `Ssh=yes` and `Netdev=yes`. This will cause it to also generate a key file called `id_rsa`, which will let you ssh into the machine using `ssh -i id_rsa`.

**EXCEPT** you can't just do `ssh -i id_rsa root@localhost`, because the host machine doesn't actually know how to distinguish traffic that's meant for itself from traffic meant for the guest. So what you actually need to do to get this to work is:
1. Build with `Netdev=yes` and `Ssh=yes` so the right network stuff is installed.
   - These should already be set in the `testVM` config.
2. Make sure `ssh` is installed on the host.
3. In the command line arguments to qemu, you need to somehow have `-nic user,model=virtio-net-pci,hostfwd=tcp::8888-:22` in there. This will forward traffic for the host on port 8888 to the guest on port 22.
   - There's no particular reason the port is 8888. You can make it whatever port you want, as long as it matches the port you're using to ssh/scp.
   - The model argument is very important here. Without it forwarding won't work. I don't know why. If you figure this out, feel free to edit this doc.
   - I have no idea what `user` does. I think I found it by copying how `mkosi` normally defines network interface cards from a generated qemu command.
4. Run `mkosi --netdev=no qemu`. This will disable the default network interface card that `mkosi` automatically creates when `Netdev` is set to `yes`. If you don't do this, qemu will use the other card and won't pick up the traffic.
5. Make sure `sshd` is running on the VM. You can start it with `systemctl start sshd`.
6. Do `ssh -p 8888 -i id_rsa root@localhost` to verify you can get in.
7. Do `scp -P 8888 -i id_rsa root@localhost:/tmp/kmap .`
   - Note this command uses a **CAPITAL** P for the port, instead of the lowercase p that `ssh` uses. I don't know why this is.

# Automating it

Normally the way Gitlab CI works is:
- you have a .gitlab-ci.yml that has the tests you want to run in it
- for each test, a runner (a program running on some machine you control that talks to GitLab) spins up a new docker container that runs the test
- artifacts you specify are copied from that to the next test

The way it normally seems to be done is that this all runs inside yet another container, called `docker.gitlab-runner.service`. This presents a couple problems for Memorizer specifically. First and foremost, we can't run `mkosi` inside docker containers, because it requires the use of loopback devices, which containers don't really seem to support, as mentioned above. Instead, we have a pre-built image that the job grabs.

A second problem is that Docker only supports KVM acceleration when run with `--privileged` (which is important because the memorizer kernel is very slow). The `docker.gitlab-runner.service` container wasn't run with `--privileged` when I was setting this process up (probably wise, since it doesn't need those permissions). For this reason we have a second image made from the `gitlab/gitlab-runner` image, running with `--privileged`. You can find the dockerfile for this in `scripts/memorizer/testVM`.

In theory you could make this a shell runner directly on your machine instead of a container. The reason I didn't do that was because on the machine I was working on, `/etc/gitlab-runner/config.toml` (the file that holds the information for all the runners) was synced using a Docker bindmount to the one on the `docker.gitlab-runner.service` container (probably so we didn't have to re-add the runner in GitLab every time the container was restarted). This meant if you added a runner on one, it would be duplicated on the other, leading to tests running in different environments and potentially a lot of weird bugs.

## Tangent

(This part is not strictly necessary but it might be informative if you're working with VMs)

For a while I was trying to set up a thing where we had another job running inside a qemu VM that ran mkosi (since it's probably a bad idea to have `gitlab-runner` running as root on a machine where we're doing other things). Because the image built by mkosi was huge, we'd run the tests as part of the same job rather than uploading it as an artifact. This turned out not to work so well because running a memorizer kernel on qemu inside qemu turned out to be extremely slow, even though KVM acceleration seemed to be on. Evidently, going too many qemus deep leads to performance issues.

## Setting up the runner

```
cd scripts/memorizer/testVM
mkosi build
ssh-keygen -p -P root -N "" -f ./id_rsa
docker build .
```

The `ssh-keygen -p` command removes the password from the `id_rsa` key so the test doesn't have to deal with it.

Find the image you just built in `docker images`, then do `docker run -d --privileged <image>`. Go to your repo in Gitlab and go to settings -> CI/CD -> runners and click New Project Runner. Follow the instructions on that page. To get a shell inside the container, you can do `docker exec -it <running image name> bash`. Once you've completed those steps, the runner should work.

You can look at the Dockerfile to get an idea of what it's doing, but the important thing is that it copies all the stuff generated with `mkosi` to `/root/mz-image-hack`. In the test, we then copy those files to the build working directory so we can do `mkosi qemu`.

The runner is a shell runner; it runs directly on the container instead of spinning up new containers. This is because I don't know how to get the new containers to run with `--privileged`. If there's a way to do this, feel free to change it to work that way.

## How the test works

The test itself is done by `scripts/memorizer/VM/qemu_test.py`. It uses `pexpect` to send a bunch of commands to the VM, then uses `scp` (as explained above) to copy the `kmap` file off it. I'm a little worried about the stability of `pexpect`, since it just reads the process output directly and searches it with regex, so if there's something less brittle we can use I'd probably prefer to switch to that. I haven't found a better method yet though.
