# Communication with Processes
## Access Tokens
In Windows, [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens) are used to describe the security context (security attributes or rules) of a process or thread. The token includes information about the user account's identity and privileges related to a specific process or thread. When a user authenticates to a system, their password is verified against a security database, and if properly authenticated, they will be assigned an access token. Every time a user interacts with a process, a copy of this token will be presented to determine their privilege level.

## Enumerating Network Services
### Display Active Network Connections

```cmd
C:\htb> netstat -ano
```

The main thing to look for with Active Network Connections are entries listening on loopback addresses (`127.0.0.1` and `::1`) that are not listening on the IP Address (`10.129.43.8`) or broadcast (`0.0.0.0`, `::/0`). The reason for this is network sockets on localhost are often insecure due to the thought that "they aren't accessible to the network."

## Named Pipes
The other way processes communicate with each other is through Named Pipes. Pipes are essentially files stored in memory that get cleared out after being read. Cobalt Strike uses Named Pipes for every command (excluding BOF). Essentially the workflow looks like this:

1. Beacon starts a named pipe of `\.\pipe\msagent_12`
2. Beacon starts a new process and injects command into that process directing output to `\.\pipe\msagent_12`
3. Server displays what was written into `\.\pipe\msagent_12`

Cobalt Strike did this because if the command being ran got flagged by antivirus or crashed, it would not affect the beacon (process running the command).

### More on Named Pipes
Pipes are used for communication between two applications or processes using shared memory. There are two types of pipes, named pipes and anonymous pipes. An example of a named pipe is `\\.\PipeName\\ExampleNamedPipeServer`. Windows systems use a client-server implementation for pipe communication. In this type of implementation, the process that creates a named pipe is the server, and the process communicating with the named pipe is the client. Named pipes can communicate using `half-duplex`, or a one-way channel with the client only being able to write data to the server, or `duplex`, which is a two-way communication channel that allows the client to write data over the pipe, and the server to respond back with data over that pipe. Every active connection to a named pipe server results in the creation of a new named pipe. These all share the same pipe name but communicate using a different data buffer.

### Listing Named Pipes with Pipelist
We can use the tool PipeList from the Sysinternals Suite to enumerate instances of named pipes.

```cmd
C:\htb> pipelist.exe /accepteula

PipeList v1.02 - Lists open named pipes
Copyright (C) 2005-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Pipe Name                                    Instances       Max Instances
---------                                    ---------       -------------
InitShutdown                                      3               -1
lsass                                             4               -1
ntsvcs                                            3               -1
scerpc                                            3               -1
Winsock2\CatalogChangeListener-340-0              1                1
Winsock2\CatalogChangeListener-414-0              1                1
epmapper                                          3               -1
Winsock2\CatalogChangeListener-3ec-0              1                1
Winsock2\CatalogChangeListener-44c-0              1                1
LSM_API_service                                   3               -1
atsvc                                             3               -1
Winsock2\CatalogChangeListener-5e0-0              1                1
eventlog                                          3               -1
Winsock2\CatalogChangeListener-6a8-0              1                1
spoolss                                           3               -1
Winsock2\CatalogChangeListener-ec0-0              1                1
wkssvc                                            4               -1
trkwks                                            3               -1
vmware-usbarbpipe                                 5               -1
srvsvc                                            4               -1
ROUTER                                            3               -1
vmware-authdpipe                                  1                1

<SNIP>
```

### Listing Named Pipes with PowerShell

```pwsh
PS C:\htb>  gci \\.\pipe\


    Directory: \\.\pipe


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              3 InitShutdown
------       12/31/1600   4:00 PM              4 lsass
------       12/31/1600   4:00 PM              3 ntsvcs
------       12/31/1600   4:00 PM              3 scerpc


    Directory: \\.\pipe\Winsock2


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-34c-0


    Directory: \\.\pipe


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              3 epmapper

<SNIP>
```

### Reviewing LSASS Named Pipe Permissions
After obtaining a listing of named pipes, we can use Accesschk to enumerate the permissions assigned to a specific named pipe by reviewing the Discretionary Access List (DACL), which shows us who has the permissions to modify, write, read, or execute a resource. Let's take a look at the `LSASS` process. We can also review the DACLs of all named pipes using the command:

```cmd
C:\htb> accesschk.exe /accepteula \\.\Pipe\lsass -v

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com

\\.\Pipe\lsass
  Untrusted Mandatory Level [No-Write-Up]
  RW Everyone
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW NT AUTHORITY\ANONYMOUS LOGON
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW APPLICATION PACKAGE AUTHORITY\Your Windows credentials
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
```

## Named Pipes Attack Example
This [WindscribeService Named Pipe Privilege Escalation](https://www.exploit-db.com/exploits/48021) is a great example. Using `accesschk` we can search for all named pipes that allow write access with a command such as `accesschk.exe -w \pipe\* -v` and notice that the `WindscribeService` named pipe allows `READ` and `WRITE` access to the `Everyone` group, meaning all authenticated users.

```cmd
C:\htb> accesschk.exe -accepteula -w \pipe\WindscribeService -v

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

\\.\Pipe\WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
```

From here, we could leverage these lax permissions to escalate privileges on the host to SYSTEM.

## Questions
RDP to 10.129.43.43 (ACADEMY-WINLPE-SRV01), with user "htb-student" and password "HTB_@cademy_stdnt!"
1. What service is listening on 0.0.0.0:21? (two words) **Answer: FileZilla Server**
   - asc
        ```cmd
        C:\Windows\system32>netstat -ano | findstr :21
        TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       2056
        TCP    [::]:21                [::]:0                 LISTENING       2056

        C:\Windows\system32>tasklist /svc | findstr 2056
        FileZilla Server.exe          2056 FileZilla Server
        ```
2. Which account has WRITE_DAC privileges over the \pipe\SQLLocal\SQLEXPRESS01 named pipe? **Answer: NT SERVICE\MSSQL$SQLEXPRESS01**
   - Check with `accesschk.exe`:
        ```cmd
        C:\Tools\AccessChk>accesschk.exe -accepteula -w \pipe\SQLLocal\SQLEXPRESS01 -v

        Accesschk v6.13 - Reports effective permissions for securable objects
        Copyright ⌐ 2006-2020 Mark Russinovich
        Sysinternals - www.sysinternals.com

        \\.\Pipe\SQLLocal\SQLEXPRESS01
        Medium Mandatory Level (Default) [No-Write-Up]
        RW NT SERVICE\MSSQL$SQLEXPRESS01
                FILE_CREATE_PIPE_INSTANCE
                FILE_APPEND_DATA
                READ_CONTROL
                WRITE_DAC
        RW Everyone
                FILE_ADD_FILE
                FILE_LIST_DIRECTORY
                FILE_READ_ATTRIBUTES
                FILE_READ_DATA
                FILE_READ_EA
                FILE_WRITE_ATTRIBUTES
                FILE_WRITE_DATA
                FILE_WRITE_EA
                SYNCHRONIZE
                READ_CONTROL
        ```