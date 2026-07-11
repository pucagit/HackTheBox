# Intro to MySQL

The mysql utility is used to authenticate to and interact with a MySQL/MariaDB database.
```shellsession
masterofblafu@htb[/htb]$ mysql -u root -p<password>

...SNIP...

mysql>
```

When we do not specify a host, it will default to the `localhost` server. We can specify a remote host and port using the `-h` and `-P` flags.

```shellsession
masterofblafu@htb[/htb]$ mysql -u root -h docker.hackthebox.eu -P 3306 -p 

Enter password: 
...SNIP...

mysql>
```

## Creating a database

```sql
mysql> CREATE DATABASE users;

Query OK, 1 row affected (0.02 sec)
mysql> SHOW DATABASES;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+

mysql> USE users;

Database changed
```

## Creating tables

```sql
mysql> CREATE TABLE logins (
    ->     id INT,
    ->     username VARCHAR(100),
    ->     password VARCHAR(100),
    ->     date_of_joining DATETIME
    ->     );
Query OK, 0 rows affected (0.03 sec)
mysql> SHOW TABLES;

+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+
1 row in set (0.00 sec)
mysql> DESCRIBE logins;

+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | date         |
+-----------------+--------------+
4 rows in set (0.00 sec)
```

## Questions
1. Connect to the database using the MySQL client from the command line. Use the 'show databases;' command to list databases in the DBMS. What is the name of the first database? **Answer: employees**
   - Connect to the target database and list available databases:
        ```shellsession
        $ mysql -h 154.57.164.67 -P 30286 -u root -ppassword
        Welcome to the MariaDB monitor.  Commands end with ; or \g.
        Your MariaDB connection id is 16
        Server version: 10.7.3-MariaDB-1:10.7.3+maria~focal mariadb.org binary distribution

        Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

        Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

        MariaDB [(none)]> show databases;
        +--------------------+
        | Database           |
        +--------------------+
        | employees          |
        | information_schema |
        | mysql              |
        | performance_schema |
        | sys                |
        +--------------------+
        5 rows in set (0.155 sec)
        ```