# CRUD API
## Questions
1. First, try to update any city's name to be 'flag'. Then, delete any city. Once done, search for a city named 'flag' to get the flag. **Answer: HTB{crud_4p!_m4n!pul4t0r}**
   - Use these curl commands to get a list of cities, update any of them to `flag` and read the `country_name` value of the city `flag`:
        ```shellsession
        # curl http://154.57.164.71:31139/api.php/city
        [{"city_name":"Birmingham","country_name":"(UK)"}, <SNIP>]
        $ curl -X PUT http://154.57.164.71:31139/api.php/city/Birmingham -d '{"city_name":"flag", "country_name":"HTB"}' -H 'Content-Type: application/json'
        $ curl http://154.57.164.71:31139/api.php/city/flag
        [{"city_name":"flag","country_name":"HTB{crud_4p!_m4n!pul4t0r}"}]
        ```