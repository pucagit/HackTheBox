# Security in Active Directory
## General Active Directory Hardening Measures
### LAPS
The [Microsoft Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.

### Audit Policy Settings (Logging and Monitoring)

### Group Policy Security Settings
These can be used to apply a wide variety of security policies to help harden Active Directory. The following is a non-exhaustive list of the types of security policies that can be applied:

- [Account Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-policies) - Manage how user accounts interact with the domain. These include the password policy, account lockout policy, and Kerberos-related settings such as the lifetime of Kerberos tickets
- [Local Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-options) - These apply to a specific computer and include the security event audit policy, user rights assignments (user privileges on a host), and specific security settings such as the ability to install drivers, whether the administrator and guest accounts are enabled, renaming the guest and administrator accounts, preventing users from installing printers or using removable media, and a variety of network access and network security controls.
- [Software Restriction Policies](https://docs.microsoft.com/en-us/windows-server/identity/software-restriction-policies/software-restriction-policies) - Settings to control what software can be run on a host.
- [Application Control Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control) - Settings to control which applications can be run by certain users/groups. This may include blocking certain users from running all executables, Windows Installer files, scripts, etc. Administrators use [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview) to restrict access to certain types of applications and files. It is not uncommon to see organizations block access to CMD and PowerShell (among other executables) for users that do not require them for their day-to-day job. These policies are imperfect and can often be bypassed but necessary for a defense-in-depth strategy.
- [Advanced Audit Policy Configuration](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/secpol-advanced-security-audit-policy-settings) - A variety of settings that can be adjusted to audit activities such as file access or modification, account logon/logoff, policy changes, privilege usage, and more.

### Update Management (SCCM/WSUS)
Proper patch management is critical for any organization, especially those running Windows/Active Directory systems. The Windows Server Update Service (WSUS) can be installed as a role on a Windows Server and can be used to minimize the manual task of patching Windows systems. System Center Configuration Manager (SCCM) is a paid solution that relies on the WSUS Windows Server role being installed and offers more features than WSUS on its own. A patch management solution can help ensure timely deployment of patches and maximize coverage, making sure that no hosts miss critical security patches. 

### Group Managed Service Accounts (gMSA)
### Security Groups
### Built-in AD Security Groups
### Account Separation
### Password Complexity Policies + Passphrases + 2FA
### Limiting Domain Admin Account Usage
### Periodically Auditing and Removing Stale Users and Objects
### Auditing Permissions and Access
### Audit Policies & Logging
### Using Restricted Groups
### Limiting Server Roles
### Limiting Local Admin and RDP Rights

## Questions
1. Confidentiality, <___>, and Availability are the pillars of the CIA Triad. What term is missing? (fill in the blank) **Answer: Integrity**
2. What security policies can block certain users from running all executables? **Answer: Application Control Policies**