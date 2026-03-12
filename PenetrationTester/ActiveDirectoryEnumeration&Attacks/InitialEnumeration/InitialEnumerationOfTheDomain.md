# Initial Enumeration of the Domain
## Key Data Points

<table class="bg-neutral-800 text-primary w-full mb-6 rounded-lg"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Data Point</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Description</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">AD Users</code></td><td class="p-4">We are trying to enumerate valid user accounts we can target for password spraying.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">AD Joined Computers</code></td><td class="p-4">Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Key Services</code></td><td class="p-4">Kerberos, NetBIOS, LDAP, DNS</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Vulnerable Hosts and Services</code></td><td class="p-4">Anything that can be a quick win. ( a.k.a an easy host to exploit and gain a foothold)</td></tr></tbody></table>

## Identifying Hosts
We can use `Wireshark` to "put our ear to the wire" and see what hosts and types of network traffic we can capture. If we are on a host without a GUI (which is typical), we can use [tcpdump](https://linux.die.net/man/8/tcpdump), [net-creds](https://github.com/DanMcInerney/net-creds), and [NetMiner](https://www.netminer.com/en/product/netminer.php), etc., to perform the same functions.

[Responder](https://github.com/lgandx/Responder-Windows) is a tool built to listen, analyze, and poison LLMNR, NBT-NS, and MDNS requests and responses. It has many more functions, but for now, all we are utilizing is the tool in its Analyze mode. This will passively listen to the network and not send any poisoned packets. We'll cover this tool more in-depth in later sections.

```sh
$ sudo responder -I ens224 -A
```

[Fping](https://fping.org/) provides us with a similar capability as the standard ping application, but has the ability to issue ICMP packets against a list of multiple hosts at once and its scriptability.

```sh
$ fping -asgq 172.16.5.0/23

172.16.5.5
172.16.5.25
172.16.5.50
172.16.5.100
172.16.5.125
172.16.5.200
172.16.5.225
172.16.5.238
172.16.5.240

     510 targets
       9 alive
     501 unreachable
       0 unknown addresses

    2004 timeouts (waiting for response)
    2013 ICMP Echos sent
       9 ICMP Echo Replies received
    2004 other ICMP received

 0.029 ms (min round trip time)
 0.396 ms (avg round trip time)
 0.799 ms (max round trip time)
       15.366 sec (elapsed real time)
```

With our focus on AD, after doing a broad sweep, it would be wise of us to focus on standard protocols typically seen accompanying AD services, such as DNS, SMB, LDAP, and Kerberos name a few. 

```sh
$ sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```

The `-A` (Aggressive scan options) scan will perform several functions. One of the most important is a quick enumeration of well-known ports to include web services, domain services, etc. 

## Identifying Users
### Kerbrute - Internal AD Username Enumeration
[Kerbrute](https://github.com/ropnop/kerbrute) can be a stealthier option for domain account enumeration. It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts. We will use Kerbrute in conjunction with the `jsmith.txt` or `jsmith2.txt` user lists from [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames).

### Cloning Kerbrute GitHub Repo

```sh
masterofblafu@htb[/htb]$ sudo git clone https://github.com/ropnop/kerbrute.git
```

### Listing Compiling Options

```sh
masterofblafu@htb[/htb]$ make help

help:            Show this help.
windows:  Make Windows x86 and x64 Binaries
linux:  Make Linux x86 and x64 Binaries
mac:  Make Darwin (Mac) x86 and x64 Binaries
clean:  Delete any binaries
all:  Make Windows, Linux and Mac x86/x64 Binaries
```

### Compiling for Multiple Platforms and Architectures

```sh
masterofblafu@htb[/htb]$ sudo make all
```

### Listing the Compiled Binaries in dist

```sh
masterofblafu@htb[/htb]$ ls dist/

kerbrute_darwin_amd64  kerbrute_linux_386  kerbrute_linux_amd64  kerbrute_windows_386.exe  kerbrute_windows_amd64.exe
```

### Enumerating Users with Kerbrute

```sh
masterofblafu@htb[/htb]$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users

2021/11/17 23:01:46 >  Using KDC(s):
2021/11/17 23:01:46 >   172.16.5.5:88
2021/11/17 23:01:46 >  [+] VALID USERNAME:       jjones@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       sbrown@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       tjohnson@INLANEFREIGHT.LOCAL
2021/11/17 23:01:50 >  [+] VALID USERNAME:       evalentin@INLANEFREIGHT.LOCAL

 <SNIP>
 
2021/11/17 23:01:51 >  [+] VALID USERNAME:       sgage@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       jshay@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       jhermann@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       whouse@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       emercer@INLANEFREIGHT.LOCAL
2021/11/17 23:01:52 >  [+] VALID USERNAME:       wshepherd@INLANEFREIGHT.LOCAL
2021/11/17 23:01:56 >  Done! Tested 48705 usernames (56 valid) in 9.940 seconds
```

## Identifying Potential Vulnerabilities
The [local system](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account) account `NT AUTHORITY\SYSTEM` is a built-in account in Windows operating systems. It has the highest level of access in the OS and is used to run most Windows services. It is also very common for third-party services to run in the context of this account by default. A `SYSTEM` account on a `domain-joined` host will be able to enumerate Active Directory by impersonating the computer account, which is essentially just another kind of user account. Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account.

There are several ways to gain SYSTEM-level access on a host, including but not limited to:

- Remote Windows exploits such as MS08-067, EternalBlue, or BlueKeep.
- Abusing a service running in the context of the `SYSTEM account`, or abusing the service account `SeImpersonate` privileges using [Juicy Potato](https://github.com/ohpe/juicy-potato). This type of attack is possible on older Windows OS' but not always possible with Windows Server 2019.
- Local privilege escalation flaws in Windows operating systems such as the Windows 10 Task Scheduler 0-day.
- Gaining admin access on a domain-joined host with a local account and using Psexec to launch a SYSTEM cmd window

By gaining SYSTEM-level access on a domain-joined host, you will be able to perform actions such as, but not limited to:

- Enumerate the domain using built-in tools or offensive tools such as BloodHound and PowerView.
- Perform Kerberoasting / ASREPRoasting attacks within the same domain.
- Run tools such as Inveigh to gather Net-NTLMv2 hashes or perform SMB relay attacks.
- Perform token impersonation to hijack a privileged domain user account.
Carry out ACL attacks.

## Questions
SSH to **10.129.11.110 (ACADEMY-EA-ATTACK01)**, with user `htb-student` and password `HTB_@cademy_stdnt!`
1. From your scans, what is the "commonName" of host 172.16.5.5 ? **Answer: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL**
   - Do a nmap scan and look at commonName under port 3389 results:
        ```sh
        $ nmap -A 172.16.5.5
        <SNIP>
        3389/tcp open  ms-wbt-server Microsoft Terminal Services
        |_ssl-date: 2026-03-12T05:09:40+00:00; +51s from scanner time.
        | rdp-ntlm-info: 
        |   Target_Name: INLANEFREIGHT
        |   NetBIOS_Domain_Name: INLANEFREIGHT
        |   NetBIOS_Computer_Name: ACADEMY-EA-DC01
        |   DNS_Domain_Name: INLANEFREIGHT.LOCAL
        |   DNS_Computer_Name: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        |   Product_Version: 10.0.17763
        |_  System_Time: 2026-03-12T05:09:32+00:00
        | ssl-cert: Subject: commonName=ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        | Not valid before: 2026-03-11T05:02:13
        |_Not valid after:  2026-09-10T05:02:13
        <SNIP>
        ```
2. What host is running "Microsoft SQL Server 2019 15.00.2000.00"? (IP address, not Resolved name) **Answer: 172.16.5.130**
   - Identify other hosts on the network:
        ```sh
        $fping -asgq 172.16.4.0/23
        172.16.5.5
        172.16.5.130
        172.16.5.225

            510 targets
            3 alive
            507 unreachable
            0 unknown addresses

            2028 timeouts (waiting for response)
            2031 ICMP Echos sent
            3 ICMP Echo Replies received
            2028 other ICMP received

        0.080 ms (min round trip time)
        0.985 ms (avg round trip time)
        1.91 ms (max round trip time)
            14.376 sec (elapsed real time)
        ```
   - Start a nmap scan for port 1433 to identify which host has this port open:
        ```sh
        $ cat hosts
        172.16.5.130
        172.16.5.225
        $ nmap -sV -iL hosts -p 1433
        Starting Nmap 7.92 ( https://nmap.org ) at 2026-03-12 01:17 EDT
        Nmap scan report for 172.16.5.130
        Host is up (0.0052s latency).

        PORT     STATE SERVICE  VERSION
        1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.00.2000

        Nmap scan report for 172.16.5.225
        Host is up (0.0040s latency).

        PORT     STATE  SERVICE  VERSION
        1433/tcp closed ms-sql-s
        ```