## Questions
1. One of the shares mendres has access to contains valid credentials of another domain user. What is their password? **Answer: ILovePower333###**
   - Try to access each share, only the IT share is accessible. Find string in this share: `C:\IT>findstr /SIM /C:"passw" *.txt `
2. As this user, search through the additional shares they have access to and identify the password of a domain administrator. What is it? **Answer: s3cr3tSNMPC0mmun1ty**
   - `$ xfreerdp /v:10.129.234.173 /u:jbader /p:ILovePower333###` → RDP to the found user `jbader`:`ILovePower333###`
   - Try to access each share, only the IT share is accessible. Find string in this share: `C:\IT>findstr /SIM /C:"passw" *.txt `