# Blacklist Filters
## Fuzzing Extensions
There are many lists of extensions we can utilize in our fuzzing scan. `PayloadsAllTheThings` provides lists of extensions for [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) web applications. We may also use `SecLists` list of common [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt).

## Questions
1. Try to find an extension that is not blacklisted and can execute PHP code on the web server, and use it to read "/flag.txt" **Answer:**
   - Use intruder with this [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) extension list and found out `.phar` is not blacklisted
   - Upload the [phpbash](https://github.com/Arrexel/phpbash/blob/master/phpbash.php) and visit http://154.57.164.65:32534/profile_images/test.phar to read the flag