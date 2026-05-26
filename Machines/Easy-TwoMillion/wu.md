Start with a nmap scan:

```sh
$ sudo nmap -sV -sC -Pn -p- -A 10.129.3.201 -oN cap.nmap
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-26 12:27 EDT

                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/easy-twomillion]
└─$ sudo nmap -sV -sC -Pn -p- -A 10.129.3.201 -oN twomillion.nmap
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-26 12:27 EDT
Nmap scan report for 10.129.3.201
Host is up (0.12s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT       ADDRESS
1   116.74 ms 10.10.16.1
2   58.79 ms  10.129.3.201

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 493.76 seconds
```

From the nmap scan we can infer that:
- Host is a Linux machine
- Nginx web server running on port 80
- SSH open on port 22

Run makeInviteCode() in the console:
```
POST /api/v1/invite/how/to/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Origin: http://2million.htb
Connection: keep-alive
Referer: http://2million.htb/invite
Cookie: PHPSESSID=3be82lsc6kucgu87j8slborv7v
Content-Length: 0
```

```
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 26 May 2026 16:56:11 GMT
Content-Type: application/json
Connection: keep-alive
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 249


{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}
```

```
POST /api/v1/invite/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
X-Requested-With: XMLHttpRequest
Referer: http://2million.htb/invite
Cookie: PHPSESSID=3be82lsc6kucgu87j8slborv7v
Content-Length: 0
```

```
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 26 May 2026 16:57:35 GMT
Content-Type: application/json
Connection: keep-alive
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 91

{"0":200,"success":1,"data":{"code":"SlBBVEktNzVSUUMtU1JOOEUtUkkzWE8=","format":"encoded"}}
```