# MSSQL (port 1433)
It is popular among database administrators and developers when building applications that run on Microsoft's .NET framework due to its strong native support for .NET. 

Many other clients can be used to access a database running on MSSQL. Including but not limited to: `mssql-cli`, `SQL Server PowerShell`, `HeidiSQL`, `SQLPro`, `Impacket's mssqlclient.py`.

## MSSQL Databases
|Default System Database|Description|
|-|-|
|`master`|Tracks all system information for an SQL server instance|
|`model`|Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database|
|`msdb`|The SQL Server Agent uses this database to schedule jobs & alerts|
|`tempdb`|Stores temporary objects|
|`resource`|Read-only database containing system objects included with SQL server|

## Default Configuration
When an admin initially installs and configures MSSQL to be network accessible, the SQL service will likely run as `NT SERVICE\MSSQLSERVER`. Connecting from the client-side is possible through Windows Authentication, and by default, encryption is not enforced when attempting to connect.

Authentication being set to `Windows Authentication` means that the underlying Windows OS will process the login request and use either the local SAM database or the domain controller (hosting Active Directory) before allowing connectivity to the database management system.

## Dangerous Settings
- MSSQL clients not using encryption to connect to the MSSQL server
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
- The use of named pipes
- Weak & default `sa` credentials. Admins may forget to disable this account

## Footprinting
### MSSQL Ping in Metasploit
```
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248

rhosts => 10.129.201.248


msf6 auxiliary(scanner/mssql/mssql_ping) > run

[*] 10.129.201.248:       - SQL Server information for 10.129.201.248:
[+] 10.129.201.248:       -    ServerName      = SQL-01
[+] 10.129.201.248:       -    InstanceName    = MSSQLSERVER
[+] 10.129.201.248:       -    IsClustered     = No
[+] 10.129.201.248:       -    Version         = 15.0.2000.5
[+] 10.129.201.248:       -    tcp             = 1433
[+] 10.129.201.248:       -    np              = \\SQL-01\pipe\sql\query
[*] 10.129.201.248:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
### Connecting with Mssqlclient.py
If we can guess or gain access to credentials, this allows us to remotely connect to the MSSQL server and start interacting with databases using `T-SQL`(Transact-SQL).
```
$ python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL-01): Line 1: Changed database context to 'master'.
[*] INFO(SQL-01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands

SQL> select name from sys.databases

name                                                                                                                               

--------------------------------------------------------------------------------------

master                                                                                                                             

tempdb                                                                                                                             

model                                                                                                                              

msdb                                                                                                                               

Transactions
```

## Questions
1. Enumerate the target using the concepts taught in this section. List the hostname of MSSQL server. **Answer: ILF-SQL-01**
   - `$ sudo nmap -sV -sC -p1433 <ip>` -> read the `ms-sql-ntlm-info: Target_name`
2. Connect to the MSSQL instance running on the target using the account (backdoor:Password1), then list the non-default database present on the server. **Answer: Employees**
   - `$ locate mssqlclient.py` -> got the path to the tool: `/opt/pipx/venvs/netexec/bin/`.
   - `$ python3 /opt/pipx/venvs/netexec/bin/mssqlclient.py backdoor@<ip> -windows-auth` -> connect to the MSSQL client.
   - `SQL (ILF-SQL-01\backdoor  dbo@master)> select name from sys.databases` -> Found the `Employees` database.