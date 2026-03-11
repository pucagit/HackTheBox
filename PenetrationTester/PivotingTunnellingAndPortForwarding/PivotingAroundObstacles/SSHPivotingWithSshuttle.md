# SSH Pivoting with sshuttle
[Sshuttle](https://github.com/sshuttle/sshuttle) is another tool written in Python which removes the need to configure proxychains. However, this tool only works for pivoting over SSH and does not provide other options for pivoting over TOR or HTTPS proxy servers. `Sshuttle` can be extremely useful for automating the execution of iptables and adding pivot rules for the remote host.


## Installing sshuttle

```sh
masterofblafu@htb[/htb]$ sudo apt-get install sshuttle
```

## Running sshuttle
To use sshuttle, we specify the option `-r` to connect to the remote machine with a username and password. Then we need to include the network or IP we want to route through the pivot host, in our case, is the network 172.16.5.0/23.

```sh
masterofblafu@htb[/htb]$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```

With this command, sshuttle creates an entry in our `iptables` to redirect all traffic to the 172.16.5.0/23 network through the pivot host.

## Traffic Routing through iptables Routes

```sh
masterofblafu@htb[/htb]$ sudo nmap -v -A -sT -p3389 172.16.5.19 -Pn
```

## Questions
1. Try using sshuttle from Pwnbox to connect via RDP to the Windows target (172.16.5.19) with "victor:pass@123" on the internal network. Once completed type: "I tried sshuttle" as the answer. **Answer:I tried sshuttle**
   - `$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v ` → Start sshuttle to route traffic to 172.16.5.0/23 through the ubuntu pivot host.
   - `$ xfreerdp /v:172.16.5.19 /u:victor /p:pass@123` → Remote to the target