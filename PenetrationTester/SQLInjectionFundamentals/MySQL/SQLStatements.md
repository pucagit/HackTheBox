# SQL Statements
## INSERT Statement

```sql
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
```

## DROP Statement

```sql
DROP TABLE logins;
```

## ALTER Statement
We can use ALTER to change the name of any table and any of its fields or to delete or add a new column to an existing table.

```sql
ALTER TABLE logins ADD newColumn INT;
ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;
ALTER TABLE logins MODIFY newerColumn DATE;
ALTER TABLE logins DROP newerColumn;
```

## UPDATE Statement
While `ALTER` is used to change a table's properties, the `UPDATE` statement can be used to update specific records within a table, based on certain conditions. 

```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```

## Questions
1. What is the department number for the 'Development' department? **Answer: d005**
   - Enumerate the `employees` database:
        ```sql
        MariaDB [(none)]> use employees
        Reading table information for completion of table and column names
        You can turn off this feature to get a quicker startup with -A

        Database changed
        MariaDB [employees]> show tables;
        +----------------------+
        | Tables_in_employees  |
        +----------------------+
        | current_dept_emp     |
        | departments          |
        | dept_emp             |
        | dept_emp_latest_date |
        | dept_manager         |
        | employees            |
        | salaries             |
        | titles               |
        +----------------------+
        8 rows in set (0.155 sec)

        MariaDB [employees]> describe departments;
        +-----------+-------------+------+-----+---------+-------+
        | Field     | Type        | Null | Key | Default | Extra |
        +-----------+-------------+------+-----+---------+-------+
        | dept_no   | char(4)     | NO   | PRI | NULL    |       |
        | dept_name | varchar(40) | NO   | UNI | NULL    |       |
        +-----------+-------------+------+-----+---------+-------+
        2 rows in set (0.156 sec)

        MariaDB [employees]> select dept_no from departments where dept_name='Development';
        +---------+
        | dept_no |
        +---------+
        | d005    |
        +---------+
        1 row in set (0.156 sec)
        ```