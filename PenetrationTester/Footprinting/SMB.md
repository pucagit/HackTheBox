# SMB (port 139,445)
The SMB protocol enables the client to communicate with other participants in the same network to access files or services shared with it on the network. The other system must also have implemented the network protocol and received and processed the client request using an SMB server application. Before that, however, both parties must establish a connection, which is why they first exchange corresponding messages.

Access rights are defined by Access Control Lists (ACL). They can be controlled in a fine-grained manner based on attributes such as execute, read, and full access for individual users or user groups. The ACLs are defined based on the shares and therefore do not correspond to the rights assigned locally on the server.

## Samba
Samba is an alternative implementation of the SMB server developed for Unix-based operating systems.

**Dangerous settings:**
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

**SMBclient**
- Connect: `# smbclient -L -N //<ip>`
    > - `-L`: diplays list of server's shares
    > - `-N`: anonymous access
- Connect to a specific share: `# smbclient //<ip>/<share_name>`
- Download a file: `smb: \> get <file_name>`
- Using command: `smb: \> !<cmd>`

**RPCclient:**
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