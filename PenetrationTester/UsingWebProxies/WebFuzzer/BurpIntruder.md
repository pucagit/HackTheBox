# Burp Intruder 
## Questions
1. Use Burp Intruder to fuzz for '.html' files under the /admin directory, to find a file containing the flag. **Answer: HTB{burp_1n7rud3r_fuzz3r!}**
   - Found `http://154.57.164.79:30735/admin/2010.html` contains the flag using Intruder with `/opt/useful/seclists/Discovery/Web-Content/common.txt` wordlist
