# Crawling
Crawling, often called spidering, is the automated process of systematically browsing the World Wide Web.

It starts with a seed URL, which is the initial web page to crawl. The crawler fetches this page, parses its content, and extracts all its links. It then adds these links to a queue and crawls them, repeating the process iteratively.

## robots.txt
The robots.txt file is a plain text document that lives in the root directory of a website. It follows a straightforward structure, with each set of instructions, or "record," separated by a blank line. Each record consists of two main components:
1. **User-agent**: This line specifies which crawler or bot the following rules apply to. A wildcard (*****) indicates that the rules apply to all bots. Specific user agents can also be targeted, such as "Googlebot" (Google's crawler) or "Bingbot" (Microsoft's crawler).
2. **Directives**: These lines provide specific instructions to the identified user-agent.
Common directives include:

|Directive|Description|
|-|-|
|`Disallow`|Specifies paths or patterns that the bot should not crawl.|
|`Allow`|Explicitly permits the bot to crawl specific paths or patterns, even if they fall under a broader Disallow rule.|
|`Crawl-delay`|Sets a delay (in seconds) between successive requests from the bot to avoid overloading the server.|
|`Sitemap`|Provides the URL to an XML sitemap for more efficient crawling.|

## Well-Known URIs
The `.well-known `standard, defined in RFC 8615, serves as a standardized directory within a website's root domain. This designated location, typically accessible via the /.well-known/ path on a web server, centralizes a website's critical metadata, including configuration files and information related to its services, protocols, and security mechanisms.

The Internet Assigned Numbers Authority (IANA) maintains a [registry](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml) of `.well-known` URIs, each serving a specific purpose defined by various specifications and standards. Below is a table highlighting a few notable examples:

|URI Suffix|Description|Status|
|-|-|-|
|`security.txt`|Contains contact information for security researchers to report vulnerabilities.|Permanent|
|`change-password`|Provides a standard URL for directing users to a password change page.|Provisional|
|`openid-configuration`|Defines configuration details for OpenID Connect, an identity layer on top of the OAuth 2.0 protocol.|Permanent|
|`assetlinks.json`|Used for verifying ownership of digital assets (e.g., apps) associated with a domain|Permanent|
|`jwks.json`|Used for obtaining the public key used to verify JWTs.|
|`mta-sts.txt`|Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security.|Permanent|

## ReconSpider
First, run this command in your terminal to download the custom scrapy spider, ReconSpider, and extract it to the current working directory.
```
$ pip3 install scrapy
$ wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
$ unzip ReconSpider.zip 
```
With the files extracted, you can run `ReconSpider.py` using the following command:
```
$ python3 ReconSpider.py http://inlanefreight.com
```
After running `ReconSpider.py`, the data will be saved in a JSON file, `results.json`. This file can be explored using any text editor. Below is the structure of the JSON file produced:
```
$ cat results.json
{
    "emails": [
        "lily.floid@inlanefreight.com",
        "cvs@inlanefreight.com",
        ...
    ],
    "links": [
        "https://www.themeansar.com",
        "https://www.inlanefreight.com/index.php/offices/",
        ...
    ],
    "external_files": [
        "https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf",
        ...
    ],
    "js_files": [
        "https://www.inlanefreight.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.3.2",
        ...
    ],
    "form_fields": [],
    "images": [
        "https://www.inlanefreight.com/wp-content/uploads/2021/03/AboutUs_01-1024x810.png",
        ...
    ],
    "videos": [],
    "audio": [],
    "comments": [
        "<!-- #masthead -->",
        ...
    ]
}
```

## Questions
1. After spidering inlanefreight.com, identify the location where future reports will be stored. Respond with the full domain, e.g., files.inlanefreight.com. **Answer: inlanefreight-comp133.s3.amazonaws.htb**
   - `$ python3 ReconSpider.py http://inlanefreight.com` -> Read the `Comments` section.
   - Or use Burp's Crawler and `Find comments` in the `Engagement tools`.