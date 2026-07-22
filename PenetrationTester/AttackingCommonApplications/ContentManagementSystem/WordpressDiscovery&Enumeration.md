# WordPress - Discovery & Enumeration
## Discovery/Footprinting
A quick way to identify a WordPress site is by browsing to the `/robots.txt` file.

```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml
```

WordPress stores its plugins in the `wp-content/plugins` directory. This folder is helpful to enumerate vulnerable plugins. Themes are stored in the `wp-content/themes` directory. These files should be carefully enumerated as they may lead to RCE.

There are five types of users on a standard WordPress installation.

1. Administrator: This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code.
2. Editor: An editor can publish and manage posts, including the posts of other users.
3. Author: They can publish and manage their own posts.
4. Contributor: These users can write and manage their own posts but cannot publish them.
5. Subscriber: These are standard users who can browse posts and edit their profiles.

## Enumeration

```shellsession
$ curl -s http://blog.inlanefreight.local | grep WordPress

<meta name="generator" content="WordPress 5.8" /
```

## WPScan
Let’s invoke a normal enumeration scan against a WordPress website with the `--enumerate` flag and pass it an API token from WPVulnDB with the `--api-token` flag.

```shellsession
$ sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB<SNIP>
```

## Questions
1. Enumerate the host and find a flag.txt flag in an accessible directory. **Answer: 0ptions_ind3xeS_ftw!**
   - Run `wpscan` on the target, found this accessible directory:
        ```shellsession
        $ wpscan --url blog.inlanefreight.local --enumerate --api-token <API_TOKEN>
        <SNIP>
        [+] Upload directory has listing enabled: http://blog.inlanefreight.local/wp-content/uploads/
        | Found By: Direct Access (Aggressive Detection)
        | Confidence: 100%
        <SNIP>
        ```
   - Found the flag at http://blog.inlanefreight.local/wp-content/uploads/2021/08/flag.txt
2. Perform manual enumeration to discover another installed plugin. Submit the plugin name as the answer (3 words). **Answer: wp sitemap page**
   - Found in http://blog.inlanefreight.local?p=1:
        ```shellsession
        $ curl 'blog.inlanefreight.local?p=1' | grep plugin
        <SNIP>
        <a href="http://wordpress.org/plugins/wp-sitemap-page/">Powered by "WP Sitemap Page"</a>
        <SNIP>
        ```
3. Find the version number of this plugin. (i.e., 4.5.2) **Answer: 1.6.4**
   - Look at where Wordpress stores its plugins: http://blog.inlanefreight.local/wp-content/plugins/wp-sitemap-page/readme.txt
        ```
        === WP Sitemap Page ===
        Contributors: funnycat
        Donate link: http://www.infowebmaster.fr/dons.php
        Tags: sitemap, generator, page list, site map, html sitemap, sitemap generator, dynamic sitemap, seo
        Requires at least: 3.0
        Tested up to: 5.6.2
        Stable tag: 1.6.4
        License: GPLv2 or later
        ```