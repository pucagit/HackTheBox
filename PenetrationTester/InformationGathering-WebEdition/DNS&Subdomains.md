# DNS & Subdomains
Much like how GPS translates a destination name into latitude and longitude for navigation, DNS translates human-readable domain names (like `www.example.com`) into the numerical IP addresses (like `192.0.2.1`) that computers use to communicate.

## How DNS Works
1. **Your Computer Asks for Directions (DNS Query)**.
2. **The DNS Resolver Checks its Map (Recursive Lookup)**: The resolver also has a cache, and if it doesn't find the IP address there, it starts a journey through the DNS hierarchy. It begins by asking a root name server, which is like the librarian of the internet.
3. **Root Name Server Points the Way**: The root server doesn't know the exact address but knows who does – the Top-Level Domain (TLD) name server responsible for the domain's ending (e.g., .com, .org). It points the resolver in the right direction.
4. **Root Name Server Narrows It Down**: The TLD name server is like a regional map. It knows which authoritative name server is responsible for the specific domain you're looking for (e.g., example.com) and sends the resolver there.
5. **Authoritative Name Server Delivers the Address**: The authoritative name server is the final stop. It holds the correct IP address and sends it back to the resolver.
6. **The DNS Resolver Returns the Information**: The resolver receives the IP address and gives it to your computer and also caches it.
7. **Your Computer Connects**

## The Hosts File 
The hosts file is located in `C:\Windows\System32\drivers\etc\hosts` on Windows and in `/etc/hosts` on Linux and MacOS. Each line in the file follows the format:
```
# <IP Address>    <Hostname> [<Alias> ...]
127.0.0.1       localhost
192.168.1.10    devserver.local
```

## Key DNS Concepts
In the Domain Name System (DNS), a zone is a distinct part of the domain namespace that a specific entity or administrator manages. For example, `example.com` and all its subdomains (like `mail.example.com` or `blog.example.com`) would typically belong to the same DNS zone.

The zone file, a text file residing on a DNS server, defines the resource records (discussed below) within this zone, providing crucial information for translating domain names into IP addresses:
```
$TTL 3600 ; Default Time-To-Live (1 hour)
@       IN SOA   ns1.example.com. admin.example.com. (
                2024060401 ; Serial number (YYYYMMDDNN)
                3600       ; Refresh interval
                900        ; Retry interval
                604800     ; Expire time
                86400 )    ; Minimum TTL

@       IN NS    ns1.example.com.
@       IN NS    ns2.example.com.
@       IN MX 10 mail.example.com.
www     IN A     192.0.2.1
mail    IN A     198.51.100.1
ftp     IN CNAME www.example.com.
```

## DIG - Domain Information Groper
|Command|Description|
|-|-|
|`dig domain.com <record_type>`|Retrieve records of the `record_type` from the domain (`record_type=ANY` to retrieve all available DNS records).|
|`dig @1.1.1.1 domain.com`|Specifies a specific name server to query; in this case 1.1.1.1|
|`dig +trace domain.com`|Shows the full path of DNS resolution.|
|`dig -x 192.168.1.1`|Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server.|
|`dig +short domain.com`|Provides a short, concise answer to the query.|
|`dig +noall +answer domain.com`|Displays only the answer section of the query output.|

## Subdomain Enumeration
### Active Subdomain Enumeration
- Use DNS zone transfer, where a misconfigured server might inadvertently leak a complete list of subdomains. However, due to tightened security measures, this is rarely successful.

    **DNS Zone Transfer**
    1. **Zone Transfer Request (AXFR)**: The secondary DNS server initiates the process by sending a zone transfer request to the primary server. This request typically uses the AXFR (Full Zone Transfer) type.
    2. **SOA Record Transfer**: Upon receiving the request (and potentially authenticating the secondary server), the primary server responds by sending its Start of Authority (SOA) record. The SOA record contains vital information about the zone, including its serial number, which helps the secondary server determine if its zone data is current.
    3. **DNS Records Transmission**: The primary server then transfers all the DNS records in the zone to the secondary server, one by one. This includes records like A, AAAA, MX, CNAME, NS, and others that define the domain's subdomains, mail servers, name servers, and other configurations.
    4. **Zone Transfer Complete**: Once all records have been transmitted, the primary server signals the end of the zone transfer. This notification informs the secondary server that it has received a complete copy of the zone data.
    5. **Acknowledgement (ACK)**: The secondary server sends an acknowledgement message to the primary server, confirming the successful receipt and processing of the zone data. This completes the zone transfer process.

    **Exploiting Zone Transfers:**
    ```
    dig axfr @nsztm1.digi.ninja zonetransfer.me
    ```
    This command instructs `dig` to request a full zone transfer (`axfr`) from the DNS server (`nsztm1.digi.ninja`) responsible for `zonetransfer.me`.

- Brute-force enumeration using tools like `dnsenum`, `ffuf`, `gobuster`.

    **DNSEnum**
    ```
    dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
    ```
    In this command: 
    - `dnsenum --enum inlanefreight.com`: We specify the target domain we want to enumerate, along with a shortcut for some tuning options `--enum`.
    - `-f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt`: We indicate the path to the SecLists wordlist we'll use for brute-forcing.
    - `-r`: This option enables recursive subdomain brute-forcing, meaning that if `dnsenum` finds a subdomain, it will then try to enumerate subdomains of that subdomain.

### Passive Subdomain Enumeration
One valuable resource is **Certificate Transparency (CT) logs**, public repositories of SSL/TLS certificates. These certificates often include a list of associated subdomains in their Subject Alternative Name (SAN) field, providing a treasure trove of potential targets.

Utilize search engines like **Google** or **DuckDuckGo**. By employing specialised search operators (e.g., `site:`), you can filter results to show only subdomains related to the target domain.

## Virtual Hosts
At the core of **virtual hosting** is the ability of web servers to distinguish between multiple websites or applications sharing the same IP address. This is achieved by leveraging the HTTP Host header

The key difference between **VHosts** and **subdomains** is their relationship to the Domain Name System (DNS) and the web server's configuration.
- **Subdomains**: These are extensions of a main domain name. Subdomains typically have their own DNS records, pointing to either the same IP address as the main domain or a different one. They can be used to organise different sections or services of a website.
- **Virtual Hosts (VHosts)**: Virtual hosts are configurations within a web server that allow multiple websites or applications to be hosted on a single server. They can be associated with top-level domains (e.g., example.com) or subdomains (e.g., dev.example.com). Each virtual host can have its own separate configuration, enabling precise control over how requests are handled. **VHost fuzzing** is a technique to discover public and non-public subdomains and VHosts by testing various hostnames against a known IP address.

### Types of Virtual Hosting
1. **Name-Based Virtual Hosting**: Relies solely on the `HTTP Host Header`.
2. **IP-Based Virtual Hosting**: Assigns a unique IP address to each website hosted on the server.
3. **Port-Based Virtual Hosting**: Different websites are associated with different ports on the same IP address.

### Virtual Host Discovery Tool: gobuster
```
$ gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```
- The `-u` flag specifies the target URL (replace `<target_IP_address>` with the actual IP).
- The `-w` flag specifies the wordlist file (replace `<wordlist_file>` with the path to your wordlist).
- The `--append-domain` flag appends the base domain to each word in the wordlist.

## Certificate Transparanct Logs
- **Certificate Transparency** (**CT**) logs are public, append-only ledgers that record the issuance of SSL/TLS certificates.
- Think of CT logs as a **global registry of certificates**. They provide a transparent and verifiable record of every SSL/TLS certificate issued for a website.
- Gain access to a historical and comprehensive view of a domain's subdomains, including those that might not be actively used or easily guessable.

### Searching CT Logs
There are 2 popular options for searching CT logs: `crt.sh` and `Censys`:

**crt.sh lookup**
```
$ curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```
- `curl -s "https://crt.sh/?q=facebook.com&output=json"`: This command fetches the JSON output from crt.sh for certificates matching the domain facebook.com.
- `jq -r '.[] | select(.name_value | contains("dev")) | .name_value'`: This part filters the JSON results, selecting only entries where the name_value field (which contains the domain or subdomain) includes the string "dev". The -r flag tells jq to output raw strings.
- `sort -u`: This sorts the results alphabetically and removes duplicates.


## Questions
1. Which IP address maps to inlanefreight.com? **Answer: 134.209.24.248**
   - `$ dig inlanefreight.com` -> Read the A record.
2. Which domain is returned when querying the PTR record for 134.209.24.248? **Answer: inlanefreight.com**
   - `$ dig -x 134.209.24.248` -> Read the PTR record.
3. What is the full domain returned when you query the mail records for facebook.com? **Answer: smtpin.vvv.facebook.com**
   - `$ dig facebook.com MX` -> Read the MX record.
4. Using the known subdomains for inlanefreight.com (www, ns1, ns2, ns3, blog, support, customer), find any missing subdomains by brute-forcing possible domain names. Provide your answer with the complete subdomain, e.g., www.inlanefreight.com. **Answer: my.inlanefreight.com**
   - `$ dnsenum --enum inlanefreight.com SecLists/Discovery/DNS/subdomains-top1million-20000.txt` -> Read the `Brute forcing...` section.
5. After performing a zone transfer for the domain inlanefreight.htb on the target system, how many DNS records are retrieved from the target system's name server? Provide your answer as an integer, e.g, 123. **Answer: 22**
   - `$ dig axfr @10.129.6.7 inlanefreight.htb | grep IN | wc -l`
6. Within the zone record transferred above, find the ip address for ftp.admin.inlanefreight.htb. Respond only with the IP address, eg 127.0.0.1 **Answer: 10.10.34.2**
   - `$ dig axfr @10.129.6.7 inlanefreight.htb | grep ftp.admin`
7. Within the same zone record, identify the largest IP address allocated within the 10.10.200 IP range. Respond with the full IP address, eg 10.10.200.1 **Answer: 10.10.200.14**
   - `$ dig axfr @10.129.6.7 inlanefreight.htb | grep 10.10.200` -> read the IP with the largest last octect.
8. Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "web"? Answer using the full domain, e.g. "x.inlanefreight.htb" **Answer: web17611.inlanefreight.htb**
   - Edit the `/etc/hosts` file:
   ```
   <ip>     inlanefreight.htb
   ```
   - `$ gobuster -vhost http://inlanefreight.htb -w ~/Seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50 --append-domain`
9.  Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "vm"? Answer using the full domain, e.g. "x.inlanefreight.htb" **Answer: vm5.inlanefreight.htb**
      - Same as above question
10.  Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "br"? Answer using the full domain, e.g. "x.inlanefreight.htb" **Answer: browse.inlanefreight.htb**
      - Same as above question
11.  Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "a"? Answer using the full domain, e.g. "x.inlanefreight.htb" **Answer: admin.inlanefreight.htb**
      - Same as above question
12.  Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "su"? Answer using the full domain, e.g. "x.inlanefreight.htb" **Answer: support.inlanefreight.htb**
      - Same as above question