# DNS (port )
|Server Type|Description|
|-|-|
|`DNS Root Server`|Responsible for top-level domains. They are only requested if the name server does not respond. 13 around the globe.|
|`Authoritative Nameserver`|Answer authority queries from their area.|
|`Non-authoritative Nameserver`|Not responsible for a particular DNS zone, instead, collect information on specific DNS zones themselves.|
|`Caching DNS Server`|Cache information from other name servers for a period specified by the authoritative nameserver.|
|`Forwarding Server`|Forward DNS queries to another DNS server.|
|`Resolver`|Perform name resolution locally in the computer or router.|

|DNS Record|Description|
|-|-|
|`A`|Returns an IPv4 address of the requested domain.|
|`AAAA`|Returns an IPv6 address of the requested domain.|
|`MX`|Returns the responsible mail servers as a result.|
|`NS`|Returns the DNS servers (nameservers) of the domain.|
|`TXT`|Contain various information.|
|`CNAME`|This record serves as an alias for another domain name, e.g. www.hackthebox.eu point to the same IP as hackthebox.eu, then you would create an A record for hackthebox.eu and CNAME record for www.hackthebox.eu|
|`PTR`|Converts IP addresses into valid domain names.|
|`SOA`|Provides information about the corresponding DNS zone and email address of the administrative contract.|
|`SRV`|Defines the hostname and port number for specific services.|
```
masterofblafu@htb[/htb]$ dig soa www.inlanefreight.com

; <<>> DiG 9.16.27-Debian <<>> soa www.inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15876
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;www.inlanefreight.com.         IN      SOA

;; AUTHORITY SECTION:
inlanefreight.com.      900     IN      SOA     ns-161.awsdns-20.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400

;; Query time: 16 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Thu Jan 05 12:56:10 GMT 2023
;; MSG SIZE  rcvd: 128
```
> The dot (`.`) is replaced by an at sign (`@`) in the email address. In this example, the email address of the administrator is awsdns-hostmaster@amazon.com.

## Default Configuration
Its local configuration file (`named.conf`) is roughly divided into two sections, firstly the options section for general settings and secondly the zone entries for the individual domains. The local configuration files are usually:
- `named.conf.local`
- `named.conf.options`
- `named.conf.log`

Global options are general and affect all zones. A zone option only affects the zone to which it is assigned. Options not listed in named.conf have default values. If an option is both global and zone-specific, then the zone option takes precedence.

## Dangerous Settings
|Option|Description|
|-|-|
|`allow-query`|Defines which hosts are allowed to send requests to the DNS server.|
|`allow-recursion`|Defines which hosts are allowed to send recursive requests to the DNS server.|
|`allow-transfer`|Defines which hosts are allowed to receive zone transfers from the DNS server.|
|`zone-statistics`|Collect statistical data of zones.|

## Footprinting the Service
### DIG - NS Query
Query a specific DNS server for NS records.
```
$ dig ns <domain_name> @<DNS_server_ip>
```
### DIG - Version Query
``` 
dig CH TXT version.bind <DNS_server_ip> 
```
### DIG - ANY Query
Use this option to view all available records.
```
$ dig ANY <domain_name> @<DNS_server_ip>
```
### DIG - AXFR Zone Transfer
Zone transfer refers to the transfer of zones to another server in DNS, which generally happens over TCP port 53. This procedure is abbreviated Asynchronous Full Transfer Zone (AXFR). Since a DNS failure usually has severe consequences for a company, the zone file is almost invariably kept identical on several name servers. When changes are made, it must be ensured that all servers have the same data. 
```
$ dig axfr <domain_name> @<DNS_server_ip>
```
### DIG - AXFR Zone Transfer - Internal
If the administrator used a subnet for the allow-transfer option for testing purposes or as a workaround solution or set it to any, everyone would query the entire zone file at the DNS server. In addition, other zones can be queried, which may even show internal IP addresses and hostnames.
```
$ dig axfr <internal_domain_name> @<DNS_server_ip>
```
### Subdomain Brute Forcing
The individual A records with the hostnames can also be found out with the help of a brute-force attack. 
```
$ dnsenum --dnsserver <DNS_server_ip> --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt <domain_name>
```

## Questions
1. Interact with the target DNS using its IP address and enumerate the FQDN of it for the "inlanefreight.htb" domain. **Answer: ns.inlanefreight.htb**
   - `$ dig ns inlanefreight.htb @<DNS_server_ip>` -> Read the NS record
2. Identify if its possible to perform a zone transfer and submit the TXT record as the answer. (Format: HTB{...}) **Answer: HTB{DN5_z0N3_7r4N5F3r_iskdufhcnlu34}**
   - `$ dig axfr inlanefreight.htb @<DNS_server_ip>` -> get the internal subdomain: dev.inlanefreight.htb
   - `$ dig axfr dev.inlanefreight.htb @<DNS_server_ip>` -> read the flag from the TXT record
3. What is the IPv4 address of the hostname DC1? **Answer: 10.129.34.16**
   - `$ dig axfr dev.inlanefreight.htb @<DNS_server_ip>` -> read the IP address of dc1.internal.inlanefreight.htb in the A record
4. What is the FQDN of the host where the last octet ends with "x.x.x.203"? **Answer: win2k.dev.inlanefreight.htb**
   - Try with subdomains that can perform zone transfer (subdomains shown in `$ dig axfr inlanefreight.htb @<DNS_server_ip>` command).
   - `$ dnsenum --dnsserver <DNS_server_ip> --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/fierce-hostlist.txt dev.inlanefreight.htb`