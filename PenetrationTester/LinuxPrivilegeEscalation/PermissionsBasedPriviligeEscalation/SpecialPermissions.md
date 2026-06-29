# Special Permissions
The `Set User ID upon Execution` (`setuid`) permission can allow a user to execute a program or script with the permissions of another user, typically with elevated privileges. The `setuid` bit appears as an `s`.

```sh
$ find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

-rwsr-xr-x 1 root root 16728 Sep  1 19:06 /home/htb-student/shared_obj_hijack/payroll
-rwsr-xr-x 1 root root 16728 Sep  1 22:05 /home/mrb3n/payroll
```

It may be possible to reverse engineer the program with the SETUID bit set, identify a vulnerability, and exploit this to escalate our privileges. Many programs have additional features that can be leveraged to execute commands and, if the `setuid` bit is set on them, these can be used for our purpose.

The Set-Group-ID (setgid) permission is another special permission that allows us to run binaries as if we were part of the group that created them. These files can be leveraged in the same manner as `setuid` binaries to escalate privileges.

```sh
$ find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

-rwsr-sr-x 1 root root 85832 Nov 30  2017 /usr/lib/snapd/snap-confine
```

## GTFOBins
The [GTFOBins](https://gtfobins.github.io/) project is a curated list of binaries and scripts that can be used by an attacker to bypass security restrictions. Each page details the program's features that can be used to break out of restricted shells, escalate privileges, spawn reverse shell connections, and transfer files.

## Questions
SSH to 10.129.2.210 (ACADEMY-LPE-NIX02), with user `htb-student` and password `Academy_LLPE!`
1. Find a file with the setuid bit set that was not shown in the section command output (full path to the binary). **Answer: /bin/sed**
   - Use this command to list files with `setuid` bit set:
        ```sh
        $ find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
        <SNIP>
        -rwsr-xr-x 1 root root 109000 Jan 30  2018 /bin/sed
        <SNIP>
        ```
2. Find a file with the setgid bit set that was not shown in the section command output (full path to the binary). **Answer: /usr/bin/facter**
   - Use this command to list files with `setguid` bit set:
        ```sh
        $ find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
        <SNIP>
        -rwsr-sr-x 1 root root 227520 Mar 19  2018 /usr/bin/facter
        ```