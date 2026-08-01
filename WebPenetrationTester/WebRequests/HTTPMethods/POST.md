# POST
## Authenticated Cookies

```shellsession
$ curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
```

## JSON Data

```shellsession
$ curl -X POST -d '{"search":"london"}' -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php
```

## Questions
Authenticate to 154.57.164.69 , with user `admin` and password `admin`
1. Obtain a session cookie through a valid login, and then use the cookie with cURL to search for the flag through a JSON POST request to '/search.php' **Answer: HTB{p0$t_r3p34t3r}**
   - Login as admin to get the cookie and then use this curl command:
        ```shellsession
        $ curl 'http://154.57.164.69:31291/search.php' -X POST -H 'Content-Type: application/json' -H 'Cookie: PHPSESSID=kh7gh19u2pup7olucb94v3rqe4' --data-raw '{"search":"flag"}'
         ["flag: HTB{p0$t_r3p34t3r}"]
        ```