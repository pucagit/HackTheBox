# Enumerating & Retrieving Password Policies
## Enumerating the Password Policy - from Linux - Credentialed
With valid domain credentials, the password policy can also be obtained remotely using tools such as [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) or `rpcclient`.

```sh
masterofblafu@htb[/htb]$ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Dumping password info for domain: INLANEFREIGHT
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Minimum password length: 8
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password history length: 24
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Maximum password age: Not Set
SMB         172.16.5.5      445    ACADEMY-EA-DC01  
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password Complexity Flags: 000001
SMB         172.16.5.5      445    ACADEMY-EA-DC01      Domain Refuse Password Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01      Domain Password Store Cleartext: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01      Domain Password Lockout Admins: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01      Domain Password No Clear Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01      Domain Password No Anon Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01      Domain Password Complex: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01  
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Minimum password age: 1 day 4 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Reset Account Lockout Counter: 30 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Locked Account Duration: 30 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Account Lockout Threshold: 5
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Forced Log off Time: Not Set
```

## Enumerating the Password Policy - from Linux - SMB NULL Sessions
Without credentials, we may be able to obtain the password policy via an SMB NULL session or LDAP anonymous bind. 

We can use rpcclient to check a Domain Controller for SMB NULL session access.

Once connected, we can issue an RPC command such as `querydominfo` to obtain information about the domain and confirm NULL session access.

```sh
masterofblafu@htb[/htb]$ rpcclient -U "" -N 172.16.5.5

rpcclient $> querydominfo
Domain:     INLANEFREIGHT
Server:     
Comment:    
Total Users:    3650
Total Groups:   0
Total Aliases:  37
Sequence No:    1
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:  0x1
```

### Using rpcclient

```sh
rpcclient $> getdompwinfo
min_password_length: 8
password_properties: 0x00000001
    DOMAIN_PASSWORD_COMPLEX
```

### Using enum4linux

```sh
masterofblafu@htb[/htb]$ enum4linux -P 172.16.5.5

<SNIP>

 ================================================== 
|    Password Policy Information for 172.16.5.5    |
 ================================================== 

[+] Attaching to 172.16.5.5 using a NULL share
[+] Trying protocol 139/SMB...

    [!] Protocol failed: Cannot request session (Called Name:172.16.5.5)

[+] Trying protocol 445/SMB...
[+] Found domain(s):

    [+] INLANEFREIGHT
    [+] Builtin

[+] Password Info for Domain: INLANEFREIGHT

    [+] Minimum password length: 8
    [+] Password history length: 24
    [+] Maximum password age: Not Set
    [+] Password Complexity Flags: 000001

        [+] Domain Refuse Password Change: 0
        [+] Domain Password Store Cleartext: 0
        [+] Domain Password Lockout Admins: 0
        [+] Domain Password No Clear Change: 0
        [+] Domain Password No Anon Change: 0
        [+] Domain Password Complex: 1

    [+] Minimum password age: 1 day 4 minutes 
    [+] Reset Account Lockout Counter: 30 minutes 
    [+] Locked Account Duration: 30 minutes 
    [+] Account Lockout Threshold: 5
    [+] Forced Log off Time: Not Set

[+] Retieved partial password policy with rpcclient:

Password Complexity: Enabled
Minimum Password Length: 8

enum4linux complete on Tue Feb 22 17:39:29 2022
```

### Using enum4linux-ng

```sh
masterofblafu@htb[/htb]$ enum4linux-ng -P 172.16.5.5 -oA ilfreight

ENUM4LINUX - next generation

<SNIP>

 =======================================
|    RPC Session Check on 172.16.5.5    |
 =======================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user session
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 =================================================
|    Domain Information via RPC for 172.16.5.5    |
 =================================================
[+] Domain: INLANEFREIGHT
[+] SID: S-1-5-21-3842939050-3880317879-2865463114
[+] Host is part of a domain (not a workgroup)
 =========================================================
|    Domain Information via SMB session for 172.16.5.5    |
========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: ACADEMY-EA-DC01
NetBIOS domain name: INLANEFREIGHT
DNS domain: INLANEFREIGHT.LOCAL
FQDN: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

 =======================================
|    Policies via RPC for 172.16.5.5    |
 =======================================
[*] Trying port 445/tcp
[+] Found policy:
domain_password_information:
  pw_history_length: 24
  min_pw_length: 8
  min_pw_age: 1 day 4 minutes
  max_pw_age: not set
  pw_properties:
  - DOMAIN_PASSWORD_COMPLEX: true
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
domain_lockout_information:
  lockout_observation_window: 30 minutes
  lockout_duration: 30 minutes
  lockout_threshold: 5
domain_logoff_information:
  force_logoff_time: not set

Completed after 5.41 seconds
```

## Enumerating the Password Policy - from Linux - LDAP Anonymous Bind
[LDAP anonymous binds](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled) allow unauthenticated attackers to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. This is a legacy configuration, and as of Windows Server 2003, only authenticated users are permitted to initiate LDAP requests. 

With an LDAP anonymous bind, we can use LDAP-specific enumeration tools such as `windapsearch.py`, `ldapsearch`, `ad-ldapdomaindump.py`, etc., to pull the password policy. 

### Using ldapsearch

```sh
masterofblafu@htb[/htb]$ ldapsearch -H 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 5
maxPwdAge: -9223372036854775808
minPwdAge: -864000000000
minPwdLength: 8
modifiedCountAtLastProm: 0
nextRid: 1002
pwdProperties: 1
pwdHistoryLength: 24
```

## Enumerating Null Session - from Windows
### Establish a null session from windows

```cmd
C:\htb> net use \\DC01\ipc$ "" /u:""
The command completed successfully.
```

We can also use a username/password combination to attempt to connect. Let's see some common errors when trying to authenticate:

### Error: Account is Disabled

```cmd
C:\htb> net use \\DC01\ipc$ "" /u:guest
System error 1331 has occurred.

This user can't sign in because this account is currently disabled.
```

### Error: Password is Incorrect

```cmd
C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1326 has occurred.

The user name or password is incorrect.
```

### Error: Account is locked out (Password Policy)

```cmd
C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1909 has occurred.

The referenced account is currently locked out and may not be logged on to.
```

## Enumerating the Password Policy - from Windows
If we can authenticate to the domain from a Windows host, we can use built-in Windows binaries such as `net.exe` to retrieve the password policy. We can also use various tools such as PowerView, CrackMapExec ported to Windows, SharpMapExec, SharpView, etc.

### Using net.exe

```cmd
C:\htb> net accounts

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
```

### Using PowerView

```pwsh
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy

Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=-1; MinimumPasswordLength=8; PasswordComplexity=1;
                 PasswordHistorySize=24; LockoutBadCount=5; ResetLockoutCount=30; LockoutDuration=30;
                 RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0;
                 LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\INLANEFREIGHT.LOCAL\sysvol\INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHI
                 NE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy
```

The default password policy when a new domain is created is as follows, and there have been plenty of organizations that never changed this policy:

<table class="bg-neutral-800 text-primary w-full mb-6 rounded-lg"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Policy</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Default Value</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Enforce password history</td><td class="p-4">24 days</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Maximum password age</td><td class="p-4">42 days</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Minimum password age</td><td class="p-4">1 day</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Minimum password length</td><td class="p-4">7</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Password must meet complexity requirements</td><td class="p-4">Enabled</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Store passwords using reversible encryption</td><td class="p-4">Disabled</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Account lockout duration</td><td class="p-4">Not set</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Account lockout threshold</td><td class="p-4">0</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Reset account lockout counter after</td><td class="p-4">Not set</td></tr></tbody></table>

## Questions
SSH to **10.129.12.57 (ACADEMY-EA-ATTACK01)**, with user `htb-student` and password `HTB_@cademy_stdnt!`
1. What is the default Minimum password length when a new domain is created? (One number) **Answer: 7**
2. What is the minPwdLength set to in the INLANEFREIGHT.LOCAL domain? (One number) **Answer: 8**
   - SSH to the target and notice that it is part of the 172.16.4.0/23 subnet:
        ```sh
        $ip a
        <SNIP>
        3: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
            link/ether 00:50:56:b0:75:e6 brd ff:ff:ff:ff:ff:ff
            altname enp19s0
            inet 172.16.5.225/23 brd 172.16.5.255 scope global noprefixroute ens224
            valid_lft forever preferred_lft forever
            inet6 fe80::32e6:baa0:e3aa:25da/64 scope link noprefixroute 
            valid_lft forever preferred_lft forever
        <SNIP>
        ```
   - Do a default nmap scan to identify live hosts → 172.16.5.5 is the DC
        ```sh
        $nmap 172.16.4.0/23
        Starting Nmap 7.92 ( https://nmap.org ) at 2026-03-12 12:00 EDT
        Nmap scan report for inlanefreight.local (172.16.5.5)
        Host is up (0.067s latency).
        Not shown: 988 closed tcp ports (conn-refused)
        PORT     STATE SERVICE
        53/tcp   open  domain
        88/tcp   open  kerberos-sec
        135/tcp  open  msrpc
        139/tcp  open  netbios-ssn
        389/tcp  open  ldap
        445/tcp  open  microsoft-ds
        464/tcp  open  kpasswd5
        593/tcp  open  http-rpc-epmap
        636/tcp  open  ldapssl
        3268/tcp open  globalcatLDAP
        3269/tcp open  globalcatLDAPssl
        3389/tcp open  ms-wbt-server

        Nmap scan report for 172.16.5.225
        Host is up (0.066s latency).
        Not shown: 998 closed tcp ports (conn-refused)
        PORT     STATE SERVICE
        22/tcp   open  ssh
        3389/tcp open  ms-wbt-server
        ```
   - Try to enumerate the password info using rpcclient with SMB NULL session:
        ```sh
        $rpcclient -U "" -N 172.16.5.5
        rpcclient $> getdompwinfo
        min_password_length: 8
        password_properties: 0x00000001
            DOMAIN_PASSWORD_COMPLEX
        ```