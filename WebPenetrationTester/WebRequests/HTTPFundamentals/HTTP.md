# HyperText Transfer Protocol (HTTP)
## Questions
1. To get the flag, start the above exercise, then use cURL to download the file returned by '/download.php' in the server shown above. **Answer: HTB{64$!c_cURL_u$3r}**
   - Download with curl:
        ```shellsession
        $ curl -O http://154.57.164.76:30306/download.php
        $ cat download.php 
        HTB{64$!c_cURL_u$3r}
        ```