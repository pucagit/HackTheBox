# Gitlab - Discovery & Enumeration
## Footprinting & Discovery
The only way to footprint the GitLab version number in use is by browsing to the `/help` page when logged in. If the GitLab instance allows us to register an account, we can log in and browse to this page to confirm the version. If we cannot register an account, we may have to try a low-risk exploit such as [this](https://www.exploit-db.com/exploits/49821).

## Enumeration
There's not much we can do against GitLab without knowing the version number or being logged in. The first thing we should try is browsing to `/explore` and see if there are any public projects that may contain something interesting.

## Questions
1. Enumerate the GitLab instance at http://gitlab.inlanefreight.local. What is the version number? **Answer: 13.10.2**
   - Register a new account, log in then browse to `/help` to view the version
2. Find the PostgreSQL database password in the example project. **Answer: postgres**
   - Browse to http://gitlab.inlanefreight.local:8081/root/inlanefreight-dev/-/blob/master/phpunit_pgsql.xml to read the password