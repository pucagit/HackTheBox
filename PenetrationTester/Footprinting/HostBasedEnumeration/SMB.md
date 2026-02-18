# SMB (port 139,445)
The SMB protocol enables the client to communicate with other participants in the same network to access files or services shared with it on the network. The other system must also have implemented the network protocol and received and processed the client request using an SMB server application. Before that, however, both parties must establish a connection, which is why they first exchange corresponding messages.

Access rights are defined by Access Control Lists (ACL). They can be controlled in a fine-grained manner based on attributes such as execute, read, and full access for individual users or user groups. The ACLs are defined based on the shares and therefore do not correspond to the rights assigned locally on the server.

## Samba
Samba is an alternative implementation of the SMB server developed for Unix-based operating systems and therefore is suitable for both Linux and Windows systems.

In a network, each host participates in the same `workgroup`. A workgroup is a group name that identifies an arbitrary collection of computers and their resources on an SMB network. There can be multiple workgroups on the network at any given time. IBM developed an `application programming interface` (API) for networking computers called the `Network Basic Input/Output System` (NetBIOS). The NetBIOS API provided a blueprint for an application to connect and share data with other computers. In a NetBIOS environment, when a machine goes online, it needs a name, which is done through the so-called `name registration` procedure. Either each host reserves its hostname on the network, or the `NetBIOS Name Server` (NBNS) is used for this purpose. It also has been enhanced to `Windows Internet Name Service` (WINS).

## Default Configuration
```
$ cat /etc/samba/smb.conf | grep -v "#\|\;" 

[global]
   workgroup = DEV.INFREIGHT.HTB
   server string = DEVSMB
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   panic action = /usr/share/samba/panic-action %d

   server role = standalone server
   obey pam restrictions = yes
   unix password sync = yes

   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .

   pam password change = yes
   map to guest = bad user
   usershare allow guests = yes

[printers]
   comment = All Printers
   browseable = no
   path = /var/spool/samba
   printable = yes
   guest ok = no
   read only = yes
   create mask = 0700

[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no
```

|Setting|Description|
|-|-|
|`[sharename]`|The name of the network share.|
|`workgroup = WORKGROUP/DOMAIN`|Workgroup that will appear when clients query.|
|`path = /path/here/`|The directory to which user is to be given access.|
|`server string = STRING`|The string that will show up when a connection is initiated.|
|`unix password sync = yes`|Synchronize the UNIX password with the SMB password?|
|`usershare allow guests = yes`|Allow non-authenticated users to access defined share?|
|`map to guest = bad user`|What to do when a user login request doesn't match a valid UNIX user?|
|`browseable = yes`|Should this share be shown in the list of available shares?|
|`guest ok = yes`|Allow connecting to the service without using a password?|
|`read only = yes`|Allow users to read files only?|
|`create mask = 0700`|What permissions need to be set for newly created files?|

## Dangerous settings:
|Setting|Description|
|-|-|
|`browseable = yes`|Allow listing available shares in the current share?|
|`read only = no`|Forbid the creation and modification of files?|
|`writeable = yes`|Allow users to create and modify files?|
|`guest ok = yes`|Allow connecting to the service without using a password?|
|`enable privileges = yes`|Honor privileges assigned to specific SID?|
|`create mask = 0777`|What permissions must be assigned to the newly created files?|
|`directory mask = 0777`|What permissions must be assigned to the newly created directories?|
|`logon script = script.sh`|What script needs to be executed on the user's login?|
|`magic script = script.sh`|Which script should be executed when the script gets closed?|
|`magic out = script.out`|Where the output of the magic script needs to be stored?|

## SMBclient
- Connect: `# smbclient -L //<ip> -N`
    > - `-L`: diplays list of server's shares
    > - `-N`: anonymous access
- Connect to a specific share: `# smbclient //<ip>/<share_name>`
- Download a file: `smb: \> get <file_name>`
- Using command: `smb: \> !<cmd>`

## RPCclient
- Anonymous connection: `# rpcclient -U "" <ip>` 
- Server information: `rpcclient $> srvinfo`    
- Enumerate all domains that are deployed in the network: `rpcclient $> enumdomains`
- Provides domain, server, and user information of deployed domains: `rpcclient $> querydominfo`
- Enumerates all available shares: `rpcclient $> netshareenumall`
- Provides information about a specific share: `rpcclient $> netsharegetinfo <share>`
- Enumerates all domain users: `rpcclient $> enumdomusers`
- Provides information about a specific user: `rpcclient $> queryuser <RID>`
- Brute forcing User RIDs: `$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done` 

**[SMBMap](https://github.com/ShawnDEvans/smbmap), [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), [enum4linux-ng](https://github.com/cddmp/enum4linux-ng):** helpful for the enumeration of SMB service.

# Questions: 
1. What version of the SMB server is running on the target system? Submit the entire banner as the answer. **Answer: Samba smbd 4** 
- `# sudo nmap -sV -sC -p139,445 <ip>` -> Read the version 
2. What is the name of the accessible share on the target? **Answer: sambashare** 
- `# rpcclient -U "" <ip>`
- `rpcclient $> netshareenumall` -> Read the netname
3. Connect to the discovered share and find the flag.txt file. Submit the contents as the answer. **Answer: HTB{o873nz4xdo873n4zo873zn4fksuhldsf}** 
- `# smbclient //10.129.14.101/sambashare`
- `smb: \> cd contents`
- `smb: \contents\> get flag.txt` -> go back to host and read the flag
4. Find out which domain the server belongs to. **Answer: DEVOPS**
- `# rpcclient -U "" 10.129.14.101`
- `rpcclient $> querydominfo` -> Read the domain
5. Find additional information about the specific share we found previously and submit the customized version of that specific share as the answer. **Answer: InFreight SMB v3.1**
- `# rpcclient -U "" 10.129.14.101`
- `rpcclient $> netshareenumall` -> Read the remark
6. What is the full system path of that specific share? (format: "/directory/names") **Answer: /home/sambauser**
- `# rpcclient -U "" 10.129.14.101`
- `rpcclient $> netshareenumall` -> Read the path