# HOST DISCOVERY
- Optimized scan: 
  ```
  nmap <ip> -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms --max-retries 0
  ```
- Scan Network Range: 
  ```
  sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
  ```
- Scan from list: 
  ```
  sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
  ```
- Debug: `--packet-trace`
- Full service detection, OS detection, traceroute and defaults scripts: 
  ```
  nmap [-p <port>] -A <ip>
  ```
- Scan port:
  - First identify live host and its open ports: 
  ```
  nmap -n --disable-arp-ping -Pn <ip>
  ```
  - Scan specific port: 
  ```
  nmap -p <port> -sV <ip> 
  nmap -p <port> <ip> --script banner
  ```
  - Scan for FTP: 
  ```
  sudo nmap -sV -sC -p21 <ip>
  ```
  - Scan for SMB:
  ```
  sudo nmap -sV -sC -p139,445 <ip>
  ```
  - Scan for NFS:
  ```
  sudo nmap -sV -sC -p111,2049 <ip>
  sudo nmap --script nfs* -sV -p111,2049 <ip> 
  ```
  - Scan for SMTP:
  ```
  sudo nmap -sV -sC -p25 <ip>
  sudo nmap -p25 --script -smtp-open-relay
  ```
  - Scan for IMAP/POP3:
  ```
  sudo nmap -sV -sC -p110,143,993,995 <ip>
  ```
  - Scan for MySQL:
  ```
  sudo nmap -sV -sC -p3306 --script mysql* <ip>
  ```
  - Scan for MSSQL:
  ```
  sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <ip>
  ```
  - Scan for Oracle TNS:
  ```
  sudo nmap -sV -p1521 <ip> --open
  ```
  - Scan for IPMI
  ```
  $ sudo nmap -sU --script ipmi-version -p 623 <domain>
  ```
  - Scan for Rsync
  ```
  $ sudo nmap -sV -p 873 <ip>
  ```
  - Scan for R-Services
  ```
  $ sudo nmap -sV -p 512,513,514 <ip>
  ```
  - Scan for RDP
  ```
  $ sudo nmap -sV -sC -p 3389 <ip> --script rdp*
  ```
  - Scan for WinRM
  ```
  $ nmap -sV -sC <ip> -p5985,5986 --disable-arp-ping -n
  ```
- Vulnerability scan: 
  ```
  nmap -p <port> -sV <ip> --script vuln
  ```
- Bypass IDS/IPS: 
  - `-S <ip_addr>`: specify the source IP address
  - `-D RND:5`: Generates five random IP addresses that indicates the source IP the connection comes from.
  - `--source-port 53`: many IDS/IPS accept DNS resolution request by default
  