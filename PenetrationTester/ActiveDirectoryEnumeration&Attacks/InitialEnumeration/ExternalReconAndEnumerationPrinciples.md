# External Recon and Enumeration Principles
## What Are We Looking For?

<table class="bg-neutral-800 text-primary w-full mb-6 rounded-lg"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Data Point</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Description</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">IP Space</code></td><td class="p-4">Valid ASN for our target, netblocks in use for the organization's public-facing infrastructure, cloud presence and the hosting providers, DNS record entries, etc.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Domain Information</code></td><td class="p-4">Based on IP data, DNS, and site registrations. Who administers the domain? Are there any subdomains tied to our target? Are there any publicly accessible domain services present? (Mailservers, DNS, Websites, VPN portals, etc.) Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.)</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Schema Format</code></td><td class="p-4">Can we discover the organization's email accounts, AD usernames, and even password policies? Anything that will give us information we can use to build a valid username list to test external-facing services for password spraying, credential stuffing, brute forcing, etc.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Data Disclosures</code></td><td class="p-4">For data disclosures we will be looking for publicly accessible files ( .pdf, .ppt, .docx, .xlsx, etc. ) for any information that helps shed light on the target. For example, any published files that contain <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">intranet</code> site listings, user metadata, shares, or other critical software or hardware in the environment (credentials pushed to a public GitHub repo, the internal AD username format in the metadata of a PDF, for example.)</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Breach Data</code></td><td class="p-4">Any publicly released usernames, passwords, or other critical information that can help an attacker gain a foothold.</td></tr></tbody></table>

## Where Are We Looking?

<table class="bg-neutral-800 text-primary w-full mb-6 rounded-lg"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Resource</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Examples</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">ASN / IP registrars</code></td><td class="p-4"><a href="https://www.iana.org/" rel="nofollow" target="_blank" class="hover:underline text-green-400">IANA</a>, <a href="https://www.arin.net/" rel="nofollow" target="_blank" class="hover:underline text-green-400">arin</a> for searching the Americas, <a href="https://www.ripe.net/" rel="nofollow" target="_blank" class="hover:underline text-green-400">RIPE</a> for searching in Europe, <a href="https://bgp.he.net/" rel="nofollow" target="_blank" class="hover:underline text-green-400">BGP Toolkit</a></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Domain Registrars &amp; DNS</code></td><td class="p-4"><a href="https://www.domaintools.com/" rel="nofollow" target="_blank" class="hover:underline text-green-400">Domaintools</a>, <a href="http://ptrarchive.com/" rel="nofollow" target="_blank" class="hover:underline text-green-400">PTRArchive</a>, <a href="https://lookup.icann.org/lookup" rel="nofollow" target="_blank" class="hover:underline text-green-400">ICANN</a>, manual DNS record requests against the domain in question or against well known DNS servers, such as <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">8.8.8.8</code>.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Social Media</code></td><td class="p-4">Searching Linkedin, Twitter, Facebook, your region's major social media sites, news articles, and any relevant info you can find about the organization.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Public-Facing Company Websites</code></td><td class="p-4">Often, the public website for a corporation will have relevant info embedded. News articles, embedded documents, and the "About Us" and "Contact Us" pages can also be gold mines.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Cloud &amp; Dev Storage Spaces</code></td><td class="p-4"><a href="https://github.com/" rel="nofollow" target="_blank" class="hover:underline text-green-400">GitHub</a>, <a href="https://grayhatwarfare.com/" rel="nofollow" target="_blank" class="hover:underline text-green-400">AWS S3 buckets &amp; Azure Blog storage containers</a>, <a href="https://www.exploit-db.com/google-hacking-database" rel="nofollow" target="_blank" class="hover:underline text-green-400">Google searches using "Dorks"</a></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Breach Data Sources</code></td><td class="p-4"><a href="https://haveibeenpwned.com/" rel="nofollow" target="_blank" class="hover:underline text-green-400">HaveIBeenPwned</a> to determine if any corporate email accounts appear in public breach data, <a href="https://www.dehashed.com/" rel="nofollow" target="_blank" class="hover:underline text-green-400">Dehashed</a> to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication.</td></tr></tbody></table>

## DNS
DNS is a great way to validate our scope and find out about reachable hosts the customer did not disclose in their scoping document. Sites like [domaintools](https://whois.domaintools.com/), and [viewdns.info](https://viewdns.info/) are great spots to start. We can get back many records and other data ranging from DNS resolution to testing for DNSSEC and if the site is accessible in more restricted countries.

## Public Data
Tools like [Trufflehog](https://github.com/trufflesecurity/truffleHog) and sites like [Greyhat Warfare](https://buckets.grayhatwarfare.com/) are fantastic resources for finding leaked data.

### Hunting For Files
Using `filetype:pdf inurl:inlanefreight.com` as a search, we are looking for PDFs.

### Hunting E-mail Addresses
Using the dork `intext:"@inlanefreight.com" inurl:inlanefreight.com`, we are looking for any instance that appears similar to the end of an email address on the website.

### Username Harvesting
We can use a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to scrape data from a company's LinkedIn page and create various mashups of usernames (flast, first.last, f.last, etc.) that can be added to our list of potential password spraying targets.

### Credential Hunting
[Dehashed](https://github.com/mrb3n813/Pentest-stuff/blob/master/dehashed.py) is an excellent tool for hunting for cleartext credentials and password hashes in breach data.

```sh
masterofblafu@htb[/htb]$ sudo python3 dehashed.py -q inlanefreight.local -p

id : 5996447501
email : roger.grimes@inlanefreight.local
username : rgrimes
password : Ilovefishing!
hashed_password : 
name : Roger Grimes
vin : 
address : 
phone : 
database_name : ModBSolutions

id : 7344467234
email : jane.yu@inlanefreight.local
username : jyu
password : Starlight1982_!
hashed_password : 
name : Jane Yu
vin : 
address : 
phone : 
database_name : MyFitnessPal

<SNIP>
```

## Questions
1. While looking at inlanefreights public records; A flag can be seen. Find the flag and submit it. ( format == HTB{XXX} ) **Answer: HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}**
   - Search for the TXT record of the inlanefreight.com domain:
        ```sh
        $ dig TXT inlanefreight.com
        ;; communications error to 10.255.255.254#53: timed out
        ;; communications error to 10.255.255.254#53: timed out

        ; <<>> DiG 9.20.15-2-Debian <<>> TXT inlanefreight.com
        ;; global options: +cmd
        ;; Got answer:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58267
        ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

        ;; OPT PSEUDOSECTION:
        ; EDNS: version: 0, flags:; udp: 512
        ;; QUESTION SECTION:
        ;inlanefreight.com.             IN      TXT

        ;; ANSWER SECTION:
        inlanefreight.com.      300     IN      TXT     "HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}"

        ;; Query time: 1052 msec
        ;; SERVER: 10.255.255.254#53(10.255.255.254) (UDP)
        ;; WHEN: Thu Mar 12 10:35:25 +07 2026
        ;; MSG SIZE  rcvd: 89
        ```