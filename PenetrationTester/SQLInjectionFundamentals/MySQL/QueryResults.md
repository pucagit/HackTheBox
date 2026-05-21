# Query Results
## Sorting Results
By default, the sort is done in ascending order, but we can also sort the results by `ASC` or `DESC`. It is also possible to sort by multiple columns, to have a secondary sort for duplicate values in one column:

```sql
mysql> SELECT * FROM logins ORDER BY password DESC;
mysql> SELECT * FROM logins ORDER BY password DESC, id ASC;
```

## LIMIT results
LIMIT results with an offset, we could specify the offset before the LIMIT count:

```sql
mysql> SELECT * FROM logins LIMIT 1, 2;
```

## WHERE Clause

```sql
SELECT * FROM table_name WHERE <condition>;
```

## LIKE Clause
The `%` symbol acts as a wildcard used to match zero or more characters. Similarly, the `_` symbol is used to match exactly one character. 

```sql
mysql> SELECT * FROM logins WHERE username LIKE 'admin%';
mysql> SELECT * FROM logins WHERE username like '___';
```

## Questions
1. What is the last name of the employee whose first name starts with "Bar" AND who was hired on 1990-01-01? **Answer: Mitchem**
   - Use WHERE clause and LIKE clause to look up that employee:
        ```sql
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

        MariaDB [employees]> describe employees;
        +------------+---------------+------+-----+---------+-------+
        | Field      | Type          | Null | Key | Default | Extra |
        +------------+---------------+------+-----+---------+-------+
        | emp_no     | int(11)       | NO   | PRI | NULL    |       |
        | birth_date | date          | NO   |     | NULL    |       |
        | first_name | varchar(14)   | NO   |     | NULL    |       |
        | last_name  | varchar(16)   | NO   |     | NULL    |       |
        | gender     | enum('M','F') | NO   |     | NULL    |       |
        | hire_date  | date          | NO   |     | NULL    |       |
        +------------+---------------+------+-----+---------+-------+
        6 rows in set (0.156 sec)

        MariaDB [employees]> select last_name from employees where first_name like 'Bar%' and hire_date = '1990-01-01';
        +-----------+
        | last_name |
        +-----------+
        | Mitchem   |
        +-----------+
        ```