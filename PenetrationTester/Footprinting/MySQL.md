# MySQL (port 3306)
Databases are often stored in a single file with the file extension `.sql`, for example, like wordpress.sql.

## Default Configuration
```
$ cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'

[client]
port		= 3306
socket		= /var/run/mysqld/mysqld.sock

[mysqld_safe]
pid-file	= /var/run/mysqld/mysqld.pid
socket		= /var/run/mysqld/mysqld.sock
nice		= 0

[mysqld]
skip-host-cache
skip-name-resolve
user		= mysql
pid-file	= /var/run/mysqld/mysqld.pid
socket		= /var/run/mysqld/mysqld.sock
port		= 3306
basedir		= /usr
datadir		= /var/lib/mysql
tmpdir		= /tmp
lc-messages-dir	= /usr/share/mysql
explicit_defaults_for_timestamp

symbolic-links=0

!includedir /etc/mysql/conf.d/
```
## Dangerous Settings
|Settings|Description|
|-|-|
|`user`|Sets which user the MySQL service will run as.|
|`password`|Sets the password for the MySQL user.|
|`admin_address`|The IP address on which to listen for TCP/IP connections on the administrative network interface.|
|`debug`|Indicates the current debugging settings.|
|`sql_warnings`|Controls whether single-row INSERT statements produce an information string if warnings occur.|
|`secure_file_priv`|Limits the effect of data import and export operations.|

## Footprinting
The most important databases for the MySQL server are the system schema (sys) and information schema (information_schema). The system schema contains tables, information, and metadata necessary for management. 
```
mysql> use sys;
mysql> show tables;  

+-----------------------------------------------+
| Tables_in_sys                                 |
+-----------------------------------------------+
| host_summary                                  |
| host_summary_by_file_io                       |
| host_summary_by_file_io_type                  |
| host_summary_by_stages                        |
| host_summary_by_statement_latency             |
| host_summary_by_statement_type                |
| innodb_buffer_stats_by_schema                 |
| innodb_buffer_stats_by_table                  |
| innodb_lock_waits                             |
| io_by_thread_by_latency                       |
...SNIP...
| x$waits_global_by_latency                     |
+-----------------------------------------------+


mysql> select host, unique_users from host_summary;

+-------------+--------------+                   
| host        | unique_users |                   
+-------------+--------------+                   
| 10.129.14.1 |            1 |                   
| localhost   |            2 |                   
+-------------+--------------+                   
2 rows in set (0,01 sec)  
```
|Command|Description|
|-|-|
|`mysql -u <username> -p<password> -h <ip>`|Connect to the MySQL server.|
|`show databases;`|Show all databases.|
|`use <database>`|Select 1 of the existing databases.|
|`show tables`|Show all available tables in the selected database.|
|`show columns from <table>`|Show all available columns in the selected table.|

## Questions
1. Enumerate the MySQL server and determine the version in use. (Format: MySQL X.X.XX) **Answer: MySQL 8.0.27**
   - `$ sudo nmap -sV -p3306 <ip>`
2. During our penetration test, we found weak credentials "robin:robin". We should try these against the MySQL server. What is the email address of the customer "Otto Lang"? **Answer: ultrices@google.htb**
   - `$ mysql -u robin -p robin -h <ip>`
   - `mysql> show databases;`
   - `mysql> use customers;`
   - `mysql> show tables;`
   - `mysql> show columns from myTable;`
   - `mysql> select email from myTable where name="Otto Lang";`