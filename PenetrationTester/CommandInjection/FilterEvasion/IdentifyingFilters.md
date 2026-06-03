# Identifying Filters
## Questions
1. Try all other injection operators to see if any of them is not blacklisted. Which of (new-line, &, |) is not blacklisted by the web application? **Answer: new-line**
   - New-line works:
        ```
        ip=127.0.0.1%0a
        ```