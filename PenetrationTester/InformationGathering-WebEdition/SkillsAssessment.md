# Skills Assessment
1. What is the IANA ID of the registrar of the inlanefreight.com domain? **Answer: 468**
   - `$ whois inlanefreight.com` or `$ finalrecon --url http://inlanefreight.com --whois`
2. What http server software is powering the inlanefreight.htb site on the target system? Respond with the name of the software, not the version, e.g., Apache. **Answer: Nginx**
   - Analysing HTTP Headers: `$ curl -I http://94.237.57.115:34828` -> Read the `Server` header.
3. What is the API key in the hidden admin directory that you have discovered on the target system? **Answer:**
   - Brute-force subdomains: `$ ffuf -u http://94.237.57.115:34828/ -H "Host: FUZZ.inlanefreight.htb" -w ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 60 -ac` -> found subdomain **web1337.inlanefreight.htb**.
   - Edit `/etc/hosts` file: `$ sudo sh -c "echo '94.237.57.115 web1337.inlanefreight.htb' >> /etc/hosts"`
   - Visit **web1337.inlanefreight.htb/admin-h1dd3n** and observe the API key.
4. After crawling the inlanefreight.htb domain on the target system, what is the email address you have found? Respond with the full email, e.g., mail@inlanefreight.htb. **Answer: 1337testing@inlanefreight.htb**
   - Brute-force subdomains: `$ ffuf -u http://94.237.57.115:34828/ -H "Host: FUZZ.web1337.inlanefreight.htb" -w ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 60 -ac` -> found subdomain **dev.web1337.inlanefreight.htb**.
   - Edit `/etc/hosts` file: `$ sudo sh -c "echo '94.237.57.115 dev.web1337.inlanefreight.htb' >> /etc/hosts"`
   - Use ReconSpider.py to crawl the site `$ python3 ReconSpider.py dev.web1337.inlanefreight.htb` -> Read the `emails` section.
5. What is the API key the inlanefreight.htb developers will be changing too? **Answer: ba988b835be4aa97d068941dc852ff33**
   - Use ReconSpider.py to crawl the site `$ python3 ReconSpider.py dev.web1337.inlanefreight.htb` -> Read the `comments` section.