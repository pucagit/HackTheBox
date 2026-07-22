# Whitelist Filters
## Double Extensions
The following is an example of a file extension whitelist test:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

This only checks whether the file name contains the extension and not if it actually ends with it. This will bypass the check:

```
test.jpg.php
```

## Reverse Double Extension
In some cases, the file upload functionality itself may not be vulnerable, but the web server configuration may lead to a vulnerability.

For example, the `/etc/apache2/mods-enabled/php7.4.conf` for the Apache2 web server may include the following configuration:

```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

Any file that contains the above extensions will be allowed PHP code execution, even if it does not end with the PHP extension:

```
test.php.jpg
```

## Character Injection

The following are some of the characters we may try injecting:

```
%20
%0a
%00
%0d0a
/
.\
.
…
:
```

## Questions
1. The above exercise employs a blacklist and a whitelist test to block unwanted extensions and only allow image extensions. Try to bypass both to upload a PHP script and execute code to read "/flag.txt" **Answer: HTB{1_wh173l157_my53lf}**
   - Use intruder with this [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) extension list with reverse double extension technique and found out `.phar.jpg` is allowed
   - Upload the [phpbash](https://github.com/Arrexel/phpbash/blob/master/phpbash.php) and visit http://154.57.164.65:32534/profile_images/test.phar.jpg to read the flag