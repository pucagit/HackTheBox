# Attacking DNS
## Enumeration

```sh
masterofblafu@htb[/htb]$ nmap -p53 -Pn -sV -sC 10.10.110.213
```

## DNS Zone Transfer
A DNS zone is a portion of the DNS namespace that a specific organization or administrator manages. Since DNS comprises multiple DNS zones, DNS servers utilize DNS zone transfers to copy a portion of their database to another DNS server. Unless a DNS server is configured correctly (limiting which IPs can perform a DNS zone transfer), anyone can ask a DNS server for a copy of its zone information since DNS zone transfers do not require any authentication. 

For exploitation, we can use the `dig` utility with DNS query type `AXFR` option to dump the entire DNS namespaces from a vulnerable DNS server:

```sh
masterofblafu@htb[/htb]$ dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```

Tools like [Fierce](https://github.com/mschwager/fierce) can also be used to enumerate all DNS servers of the root domain and scan for a DNS zone transfer:

```sh
masterofblafu@htb[/htb]$ fierce --domain zonetransfer.me
```

## Domain Takeovers & Subdomain Enumeration
**Domain takeover** is registering a non-existent domain name to gain control over another domain. If attackers find an expired domain, they can claim that domain to perform further attacks such as hosting malicious content on a website or sending a phishing email leveraging the claimed domain.

**Subdomain takeover** vulnerabilities occur when a subdomain (`subdomain.example.com`) is pointing to a service (e.g. GitHub pages, Heroku, etc.) that has been removed or deleted. For example, if `subdomain.example.com` was pointing to a GitHub page and the user decided to delete their GitHub page, an attacker can now create a GitHub page, add a CNAME file containing `subdomain.example.com`, and claim `subdomain.example.com`.

```
sub.target.com.   60   IN   CNAME   anotherdomain.com
```

The domain name (e.g., `sub.target.com`) uses a CNAME record to another domain (e.g., `anotherdomain.com`). Suppose the `anotherdomain.com` expires and is available for anyone to claim , in that case, anyone who registers `anotherdomain.com` will have complete control over `sub.target.com` until the DNS record is updated.

### Subdomain enumeration
Subfinder can scrape subdomains from open sources like [DNSdumpster](https://dnsdumpster.com/). 

```sh
masterofblafu@htb[/htb]$ ./subfinder -d inlanefreight.com -v
```

Subrute allows us to use self-defined resolvers and perform pure DNS brute-forcing attacks during internal penetration tests on hosts that do not have Internet access.

```sh
masterofblafu@htb[/htb]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
masterofblafu@htb[/htb]$ cd subbrute
masterofblafu@htb[/htb]$ echo "ns1.inlanefreight.htb" > ./resolvers.txt
masterofblafu@htb[/htb]$ ./subbrute.py inlanefreight.htb -s ./names.txt -r ./resolvers.txt

Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
inlanefreight.htb
ns2.inlanefreight.htb
www.inlanefreight.htb
ms1.inlanefreight.htb
support.inlanefreight.htb

<SNIP>
```

The tool has found four subdomains associated with inlanefreight.htb. Using the `nslookup` or `host` command, we can enumerate the CNAME records for those subdomains.

```sh
masterofblafu@htb[/htb]$ host support.inlanefreight.htb

support.inlanefreight.htb is an alias for inlanefreight.s3.amazonaws.htb
```

The support subdomain has an alias record pointing to an AWS S3 bucket. However, the URL https://support.inlanefreight.com shows a `NoSuchBucket` error indicating that the subdomain is potentially vulnerable to a subdomain takeover. Now, we can take over the subdomain by creating an AWS S3 bucket with the same subdomain name.

## DNS Spoofing
DNS spoofing is also referred to as DNS Cache Poisoning. This attack involves altering legitimate DNS records with false information so that they can be used to redirect online traffic to a fraudulent website. 

### Local DNS Cache Poisoning
From a local network perspective, an attacker can also perform DNS Cache Poisoning using MITM tools like [Ettercap](https://www.ettercap-project.org/) or [Bettercap](https://www.bettercap.org/).

To exploit the DNS cache poisoning via Ettercap, we should first edit the `/etc/ettercap/etter.dns` file to map the target domain name (e.g., `inlanefreight.com`) that they want to spoof and the attacker's IP address (e.g., `192.168.225.110`) that they want to redirect a user to:

```sh
masterofblafu@htb[/htb]$ cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Next, start the `Ettercap` tool and scan for live hosts within the network by navigating to `Hosts > Scan for Hosts`. Once completed, add the target IP address (e.g., `192.168.152.129`) to `Target1` and add a default gateway IP (e.g., `192.168.152.2`) to Target2.

Activate dns_spoof attack by navigating to `Plugins > Manage Plugins`. This sends the target machine with fake DNS responses that will resolve `inlanefreight.com` to IP address `192.168.225.110`.

After a successful DNS spoof attack, if a victim user coming from the target machine `192.168.152.129` visits the `inlanefreight.com` domain on a web browser, they will be redirected to a Fake page that is hosted on IP address `192.168.225.110`.


## Questions
1. Find all available DNS records for the "inlanefreight.htb" domain on the target name server and submit the flag found as a DNS record as the answer. **Answer: HTB{LUIHNFAS2871SJK1259991}**
   - Bruteforce subdomain for `inlanefreight.htb` and found `hr.inlanefreight.htb`:
    ```sh
    $ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
    $ cd subbrute
    $ echo 10.129.36.35 > ./resolvers.txt  # IP address of the name server
    $ ./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt
    Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
    inlanefreight.htb
    hr.inlanefreight.htb
    <SNIP>
    ```
   - `$ dig AXFR @10.129.36.35 hr.inlanefreight.htb` → Send a DNS Zone Transfer record for this subdomain and read the flag in the response