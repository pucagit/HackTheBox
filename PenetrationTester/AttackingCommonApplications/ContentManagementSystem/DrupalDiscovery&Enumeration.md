# Drupal Discovery & Enumeration
## Enumeration

```sh
$ droopescan scan drupal -u http://drupal.inlanefreight.local
```

## Questions
1. Identify the Drupal version number in use on http://drupal-qa.inlanefreight.local **Answer: 7.30**
   - Run droopescan:
        ```sh
        $ droopescan scan drupal -u http://drupal-qa.inlanefreight.local
        [+] Plugins found:                                                              
            profile http://drupal-qa.inlanefreight.local/modules/profile/
            php http://drupal-qa.inlanefreight.local/modules/php/
            image http://drupal-qa.inlanefreight.local/modules/image/

        [+] Themes found:
            seven http://drupal-qa.inlanefreight.local/themes/seven/
            garland http://drupal-qa.inlanefreight.local/themes/garland/

        [+] Possible version(s):
            7.30

        [+] Possible interesting urls found:
            Default changelog file - http://drupal-qa.inlanefreight.local/CHANGELOG.txt
            Default admin - http://drupal-qa.inlanefreight.local/user/login

        [+] Scan finished (0:03:43.078303 elapsed)
        ```