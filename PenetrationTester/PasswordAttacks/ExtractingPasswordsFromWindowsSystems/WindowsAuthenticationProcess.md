# Windows Authentication Process
The Local Security Authority (LSA) is a protected subsystem that authenticates users, manages local logins, oversees all aspects of local security, and provides services for translating between user names and security identifiers (SIDs). On a Domain Controller, these policies and accounts apply to the entire domain and are stored in Active Directory. Additionally, the LSA subsystem provides services for access control, permission checks, and the generation of security audit messages.

## Windows authentication process

![alt text](Auth_process1.png)

Local interactive logon is handled through the coordination of several components: the logon process ([WinLogon](https://www.microsoftpressstore.com/articles/article.aspx?p=2228450&seqNum=8)), the logon user interface process (**LogonUI**), credential providers, the Local Security Authority Subsystem Service (**LSASS**), one or more authentication packages, and either the Security Accounts Manager (**SAM**) or Active Directory. Authentication packages, in this context, are Dynamic-Link Libraries (DLLs) responsible for performing authentication checks. 

**WinLogon** is the only process that intercepts login requests from the keyboard, which are sent via RPC messages from **Win32k.sys**. At logon, it immediately launches the LogonUI application to present the graphical user interface. Once the user's credentials are collected by the credential provider, WinLogon passes them to the **LSASS** to authenticate the user.

## LSASS
The [Local Security Authority Subsystem Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service) (**LSASS**) is comprised of multiple modules and governs all authentication processes. Located at `%SystemRoot%\System32\Lsass.exe` in the file system, it is responsible for enforcing the local security policy, authenticating users, and forwarding security audit logs to the **Event Log**.

<table class="table table-striped text-left">
<thead>
<tr>
<th><strong>Authentication Packages</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td><code>Lsasrv.dll</code></td>
<td>The LSA Server service both enforces security policies and acts as the security package manager for the LSA. The LSA contains the Negotiate function, which selects either the NTLM or Kerberos protocol after determining which protocol is to be successful.</td>
</tr>
<tr>
<td><code>Msv1_0.dll</code></td>
<td>Authentication package for local machine logons that don't require custom authentication.</td>
</tr>
<tr>
<td><code>Samsrv.dll</code></td>
<td>The Security Accounts Manager (SAM) stores local security accounts, enforces locally stored policies, and supports APIs.</td>
</tr>
<tr>
<td><code>Kerberos.dll</code></td>
<td>Security package loaded by the LSA for Kerberos-based authentication on a machine.</td>
</tr>
<tr>
<td><code>Netlogon.dll</code></td>
<td>Network-based logon service.</td>
</tr>
<tr>
<td><code>Ntdsa.dll</code></td>
<td>Directory System Agent (DSA) that manages the Active Directory database (ntds.dit), processes LDAP queries, and handles replication between domain controllers. Only loaded on Domain Controllers.</td>
</tr>
</tbody>
</table>

Each interactive logon session creates a separate instance of the WinLogon service. The [Graphical Identification and Authentication](https://docs.microsoft.com/en-us/windows/win32/secauthn/gina) (**GINA**) architecture is loaded into the process area used by WinLogon, receives and processes the credentials, and invokes the authentication interfaces via the [LSALogonUser](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser) function.

## SAM Database
The [Security Account Manager](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc756748(v=ws.10)?redirectedfrom=MSDN) (**SAM**) is a database file in Windows operating systems that stores user account credentials. It is used to authenticate both local and remote users and uses cryptographic protections to prevent unauthorized access. User passwords are stored as hashes in the registry, typically in the form of either **LM** or **NTLM** hashes. The SAM file is located at `%SystemRoot%\system32\config\SAM` and is mounted under `HKLM\SAM`. Viewing or accessing this file requires `SYSTEM` level privileges.

Windows systems can be assigned to either a workgroup or domain during setup. If the system has been assigned to a workgroup, it handles the SAM database locally and stores all existing users locally in this database. However, if the system has been joined to a domain, the Domain Controller (**DC**) must validate the credentials from the Active Directory database (`ntds.dit`), which is stored in `%SystemRoot%\ntds.dit`.

To improve protection against offline cracking of the SAM database, Microsoft introduced a feature in Windows NT 4.0 called `SYSKEY` (`syskey.exe`). When enabled, SYSKEY partially encrypts the SAM file on disk, ensuring that password hashes for all local accounts are encrypted with a system-generated key.

## Credential Manager

![alt text](authn_credman_credprov.gif)

Credential Manager is a built-in feature of all Windows operating systems that allows users to store and manage credentials used to access network resources, websites, and applications. These saved credentials are stored per user profile in the user's **Credential Locker**. The credentials are encrypted and stored at the following location:

```pwsh
PS C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\
```

## NTDS
Windows domain simplifies centralized management, allowing administrators to efficiently oversee all systems within their organization. In such environments, logon requests are sent to Domain Controllers within the same Active Directory forest. Each Domain Controller hosts a file called **NTDS.dit**, which is synchronized across all Domain Controllers, with the exception of [Read-Only Domain Controllers (RODCs)](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema).

**NTDS.dit** is a database file that stores Active Directory data, including but not limited to:
- User accounts (username & password hash)
- Group accounts
- Computer accounts
- Group policy objects