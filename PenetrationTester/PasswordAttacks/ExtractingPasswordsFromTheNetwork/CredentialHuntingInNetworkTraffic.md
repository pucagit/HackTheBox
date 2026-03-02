# Credential Hunting in Network Traffic

<table class="table table-striped text-left">
<thead>
<tr>
<th>Unencrypted Protocol</th>
<th>Encrypted Counterpart</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>HTTP</code></td>
<td><code>HTTPS</code></td>
<td>Used for transferring web pages and resources over the internet.</td>
</tr>
<tr>
<td><code>FTP</code></td>
<td><code>FTPS/SFTP</code></td>
<td>Used for transferring files between a client and a server.</td>
</tr>
<tr>
<td><code>SNMP</code></td>
<td><code>SNMPv3 (with encryption)</code></td>
<td>Used for monitoring and managing network devices like routers and switches.</td>
</tr>
<tr>
<td><code>POP3</code></td>
<td><code>POP3S</code></td>
<td>Retrieves emails from a mail server to a local client.</td>
</tr>
<tr>
<td><code>IMAP</code></td>
<td><code>IMAPS</code></td>
<td>Accesses and manages email messages directly on the mail server.</td>
</tr>
<tr>
<td><code>SMTP</code></td>
<td><code>SMTPS</code></td>
<td>Sends email messages from client to server or between mail servers.</td>
</tr>
<tr>
<td><code>LDAP</code></td>
<td><code>LDAPS</code></td>
<td>Queries and modifies directory services like user credentials and roles.</td>
</tr>
<tr>
<td><code>RDP</code></td>
<td><code>RDP (with TLS)</code></td>
<td>Provides remote desktop access to Windows systems.</td>
</tr>
<tr>
<td><code>DNS (Traditional)</code></td>
<td><code>DNS over HTTPS (DoH)</code></td>
<td>Resolves domain names into IP addresses.</td>
</tr>
<tr>
<td><code>SMB</code></td>
<td><code>SMB over TLS (SMB 3.0)</code></td>
<td>Shares files, printers, and other resources over a network.</td>
</tr>
<tr>
<td><code>VNC</code></td>
<td><code>VNC with TLS/SSL</code></td>
<td>Allows graphical remote control of another computer.</td>
</tr>
</tbody>
</table>

## Wireshark

<table class="table table-striped text-left">
<thead>
<tr>
<th>Wireshark filter</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>ip.addr == 56.48.210.13</code></td>
<td>Filters packets with a specific IP address</td>
</tr>
<tr>
<td><code>tcp.port == 80</code></td>
<td>Filters packets by port (HTTP in this case).</td>
</tr>
<tr>
<td><code>http</code></td>
<td>Filters for HTTP traffic.</td>
</tr>
<tr>
<td><code>dns</code></td>
<td>Filters DNS traffic, which is useful to monitor domain name resolution.</td>
</tr>
<tr>
<td><code>tcp.flags.syn == 1 &amp;&amp; tcp.flags.ack == 0</code></td>
<td>Filters SYN packets (used in TCP handshakes), useful for detecting scanning or connection attempts.</td>
</tr>
<tr>
<td><code>icmp</code></td>
<td>Filters ICMP packets (used for Ping), which can be useful for reconnaissance or network issues.</td>
</tr>
<tr>
<td><code>http.request.method == "POST"</code></td>
<td>Filters for HTTP POST requests. In the case that POST requests are sent over unencrypted HTTP, it may be the case that passwords or other sensitive information is contained within.</td>
</tr>
<tr>
<td><code>tcp.stream eq 53</code></td>
<td>Filters for a specific TCP stream. Helps track a conversation between two hosts.</td>
</tr>
<tr>
<td><code>eth.addr == 00:11:22:33:44:55</code></td>
<td>Filters packets from/to a specific MAC address.</td>
</tr>
<tr>
<td><code>ip.src == 192.168.24.3 &amp;&amp; ip.dst == 56.48.210.3</code></td>
<td>Filters traffic between two specific IP addresses. Helps track communication between specific hosts.</td>
</tr>
</tbody>
</table>

In Wireshark, it's possible to locate packets that contain specific bytes or strings. One way to do this is by using a display filter such as `http contains "passw"`. Alternatively, you can navigate to **Edit > Find Packet** and enter the desired search query manually. 

## Pcredz
[Pcredz](https://github.com/lgandx/PCredz) is a tool that can be used to extract credentials from live traffic or network packet captures. Specifically, it supports extracting the following information:

- Credit card numbers
- POP credentials
- SMTP credentials
- IMAP credentials
- SNMP community strings
- FTP credentials
- Credentials from HTTP NTLM/Basic headers, as well as HTTP Forms
- NTLMv1/v2 hashes from various traffic including DCE-RPC, SMBv1/2, LDAP, MSSQL, and - HTTP
- Kerberos (AS-REQ Pre-Auth etype 23) hashes

The following command can be used to run **Pcredz** against a packet capture file:

```sh
[!bash!]$ ./Pcredz -f demo.pcapng -t -v

Pcredz 2.0.2
Author: Laurent Gaffie
Please send bugs/comments/pcaps to: laurent.gaffie@gmail.com
This script will extract NTLM (HTTP,LDAP,SMB,MSSQL,RPC, etc), Kerberos,
FTP, HTTP Basic and credit card data from a given pcap file or from a live interface.

CC number scanning activated

Unknown format, trying TCPDump format

[1746131482.601354] protocol: udp 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2 Community string: s3cr...SNIP...

[1746131482.601640] protocol: udp 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2 Community string: s3cr...SNIP...

<SNIP>

[1746131482.658938] protocol: tcp 192.168.31.243:55707 > 192.168.31.211:21
FTP User: le...SNIP...
FTP Pass: qw...SNIP...

demo.pcapng parsed in: 1.82 seconds (File size 15.5 Mo).
```

## Questions
1. The packet capture contains cleartext credit card information. What is the number that was transmitted? **Answer: 5156 8829 4478 9834**
   - `$ git clone https://github.com/lgandx/PCredz` → Install PCredz
   - Extract credentials from the `pcapng` file:
        ```sh
        $ ./Pcredz -f ../demo.pcapng -t -v
        Credz 2.1.0
        Author: Laurent Gaffie
        Contact: lgaffie@secorizon.com
        X: @secorizon

        CC number scanning activated

        Parsing ../demo.pcapng...
        [2026-03-01 04:24:22.475409] 192.168.31.243:55692 > 192.168.31.238:80
        Potential password submission:
        Request: username=jbenito&password=Password987%21
        ```
   - `$ wireshark -r ../demo.pcapng` → Open the `pcapng` file in Wireshark
   - Filter for `http` and contains `username=jbenito`, found the `POST /process_payment HTTP/1.1` request. Follow that request and view the body to obtain the card number.
2. What is the SNMPv2 community string that was used? **Answer: s3cr3tSNMPC0mmun1ty**
   - Found in the previous **PCredz** result.
3. What is the password of the user who logged into FTP? **Answer: qwerty123**
   - Found in the previous **PCredz** result.
4. What file did the user download over FTP? **Answer: creds.txt**
   - `$ wireshark -r ../demo.pcapng` → Open the `pcapng` file in Wireshark
   - Filter for `ftp` and found the `Request: RETR creds.txt` packet.