# Attacking Common Applications - Skills Assessment III
During our penetration test our team found a Windows host running on the network and the corresponding credentials for the `Administrator`. It is required that we connect to the host and find the hardcoded password for the MSSQL service.

## Questions
RDP to 10.129.67.67 (ACADEMY-ACA-MULTIMASTER), with user `Administrator` and password `xcyj8izxNVzhf4z`
1. What is the hardcoded password for the database connection in the MultimasterAPI.dll file? **Answer: D3veL0pM3nT!**
   - Find the location of the dll file:
        ```cmd
        C:\> where /r C:\ MultimasterAPI.dll
        C:\inetpub\wwwroot\bin\MultimasterAPI.dll
        ```
   - Open the dll in dnSpy, look in `MultimasterAPI.Controllers` under `GetColleagues`