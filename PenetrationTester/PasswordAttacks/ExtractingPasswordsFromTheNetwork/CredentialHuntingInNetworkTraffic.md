# Credential Hunting in Network Traffic
## Wireshark
|Wireshark Filter|Description|
|-|-|
|`ip.addr == 1.2.3.4`|Filters packets with a specific IP address|
|`tcp.port == 80`|Filters packets by port (HTTP in this case).|
|`http`|Filter for HTTP traffic.|
|`dns`|Filters DNS traffic, which is useful to monitor domain name resolution.|
|`tcp.flags.syn == 1 && tcp.flags.ack == 0`|Filters SYN packets (used in TCP handshakes), useful for detecting scanning or connection attempts.|
|`icmp`|Filters ICMP packets (used for Ping), which can be useful for reconnaissance or network issues.|
|`http.request.method == "POST"`|Filters for HTTP POST requests. In the case that POST requests are sent over unencrypted HTTP, it may be the case that passwords or other sensitive information is contained within.|
|`tcp.stream eq 53`|Filters for a specific TCP stream. Helps track a conversation between two hosts.|
|`eth.addr == 00:11:22:33:44:55`|Filters packets from/to a specific MAC address.|
|`ip.src == 192.168.24.3 && ip.dst == 56.48.210.3`|Filters traffic between two specific IP addresses. Helps track communication between specific hosts.|

In Wireshark, it's possible to locate packets that contain specific bytes or strings. One way to do this is by using a display filter such as `http contains "passw"`. 
## Pcredz
[Pcredz](https://github.com/lgandx/PCredz?tab=readme-ov-file#install) is a tool that can be used to extract credentials from live traffic or network packet captures. Specifically, it supports extracting the following information:
- Credit card numbers
- POP credentials
- SMTP credentials
- IMAP credentials
- SNMP community strings
- FTP credentials
- Credentials from HTTP NTLM/Basic headers, as well as HTTP Forms
- NTLMv1/v2 hashes from various traffic including DCE-RPC, SMBv1/2, LDAP, MSSQL, and HTTP
- Kerberos (AS-REQ Pre-Auth etype 23) hashes

The following command can be used to run Pcredz against a packet capture file:
```
$ ./Pcredz -f demo.pcapng -t -v

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
   - Use Wireshark filter: `http contains "card"`
   - Follow the HTTP stream.
2. What is the SNMPv2 community string that was used? **Answer: s3cr3tSNMPC0mmun1ty**
   - Use Pcredz:
        ```
        $ python3 Pcredz -f ../demo.pcapng
        Pcredz 2.0.3

        Author: Laurent Gaffie <lgaffie@secorizon.com>

        This script will extract NTLM (HTTP,LDAP,SMB,MSSQL,RPC, etc), Kerberos,
        FTP, HTTP Basic and credit card data from a given pcap file or from a live interface.

        CC number scanning activated

        Unknown format, trying TCPDump format

        protocol: udp 192.168.31.211:59022 > 192.168.31.238:161
        Found SNMPv2 Community string: s3cr3tSNMPC0mmun1ty

        protocol: tcp 192.168.31.243:55707 > 192.168.31.211:21
        FTP User: leah
        FTP Pass: qwerty123


        ../demo.pcapng parsed in: 2.05 seconds (File size 15.5 Mo).
        ```
3. What is the password of the user who logged into FTP? **Answer: qwerty123**
   - Already in the above output.
4. What file did the user download over FTP? **Answer: creds.txt**
   - Use this filter: `ftp`
   - Follow the TCP stream.