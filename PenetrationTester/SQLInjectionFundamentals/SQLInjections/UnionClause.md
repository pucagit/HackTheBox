# Union Clause
## Union

```sql
mysql> SELECT * FROM ports;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| ZZ-21    | Shenzhen  |
+----------+-----------+
3 rows in set (0.00 sec)
mysql> SELECT * FROM ships;

+----------+-----------+
| Ship     | city      |
+----------+-----------+
| Morrison | New York  |
+----------+-----------+
1 rows in set (0.00 sec)
mysql> SELECT * FROM ports UNION SELECT * FROM ships;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| Morrison | New York  |
| ZZ-21    | Shenzhen  |
+----------+-----------+
4 rows in set (0.00 sec)
```

`UNION` combined the output of both `SELECT` statements into one, so entries from the ports table and the ships table were combined into a single output with four rows. As we can see, some of the rows belong to the `ports` table while others belong to the `ships` table.

> Note: The data types of the selected columns on all positions should be the same.

## Even Columns
A `UNION` statement can only operate on `SELECT` statements with an equal number of columns. 

## Un-even Columns
Suppose we only had one column. In that case, we want to `SELECT`, we can put junk data for the remaining required columns so that the total number of columns we are `UNIONing` with remains the same as the original query.

```sql
SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords
```

## Questions
1. Connect to the above MySQL server with the 'mysql' tool, and find the number of records returned when doing a 'Union' of all records in the 'employees' table and all records in the 'departments' table. **Answer: 663**
   - Describe the 2 tables first → table `departments` has only 2 columns and needs to put junk data for the remaining 4 columns from `employees` table:
        ```sql
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

        MariaDB [employees]> describe departments;
        +-----------+-------------+------+-----+---------+-------+
        | Field     | Type        | Null | Key | Default | Extra |
        +-----------+-------------+------+-----+---------+-------+
        | dept_no   | char(4)     | NO   | PRI | NULL    |       |
        | dept_name | varchar(40) | NO   | UNI | NULL    |       |
        +-----------+-------------+------+-----+---------+-------+
        2 rows in set (0.156 sec)
        ```
   - Count the UNION result:
        ```sql
        MariaDB [employees]> select count(*) from (select * from employees union select dept_no, dept_name, NULL, NULL, NULL, NULL from departments) as combined;
        +----------+
        | count(*) |
        +----------+
        |      663 |
        +----------+
        1 row in set (0.157 sec)
        ```