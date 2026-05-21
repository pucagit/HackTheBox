# SQL Operators
## AND Operator

```sql
mysql> SELECT 1 = 1 AND 'test' = 'test';

+-------------------------+
| 1 = 1 OR 'test' = 'test' |
+-------------------------+
|                       1 |
+-------------------------+
```

## OR Operator

```sql
mysql> SELECT 1 = 1 OR 'test' = 'abc';

+-------------------------+
| 1 = 1 OR 'test' = 'abc' |
+-------------------------+
|                       1 |
+-------------------------+
```

## NOT Operator
The `NOT` operator simply toggles a boolean value 'i.e. `true` is converted to `false` and vice versa':

```sql
mysql> SELECT NOT 1 = 1;

+-----------+
| NOT 1 = 1 |
+-----------+
|         0 |
+-----------+
```

> The AND, OR and NOT operators can also be represented as &&, || and !, respectively.

## Multiple Operator Precedence

```
- Division (/), Multiplication (*), and Modulus (%)
- Addition (+) and subtraction (-)
- Comparison (=, >, <, <=, >=, !=, LIKE)
- NOT (!)
- AND (&&)
- OR (||)
```

Operations at the top are evaluated before the ones at the bottom of the list.

## Questions
1. In the 'titles' table, what is the number of records WHERE the employee number is greater than 10000 OR their title does NOT contain 'engineer'? **Answer: 654**
   - Use COUNT(*) to count the records satisfy the condition mentioned:
        ```sql
        MariaDB [employees]> describe titles;
        +-----------+-------------+------+-----+---------+-------+
        | Field     | Type        | Null | Key | Default | Extra |
        +-----------+-------------+------+-----+---------+-------+
        | emp_no    | int(11)     | NO   | PRI | NULL    |       |
        | title     | varchar(50) | NO   | PRI | NULL    |       |
        | from_date | date        | NO   | PRI | NULL    |       |
        | to_date   | date        | YES  |     | NULL    |       |
        +-----------+-------------+------+-----+---------+-------+
        MariaDB [employees]> select count(*) from titles where emp_no > 10000 or title not like '%Engineer%';
        +----------+
        | count(*) |
        +----------+
        |      654 |
        +----------+
        ```