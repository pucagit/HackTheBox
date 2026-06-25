# Jenkins Discovery & Enumeration
Jenkins is an open-source automation server written in Java that helps developers build and test their software projects continuously. It is a server-based system that runs in servlet containers such as Tomcat.

## Discovery/Footprinting
Jenkins runs on Tomcat port 8080 by default. It also utilizes port 5000 to attach slave servers. This port is used to communicate between masters and slaves. Jenkins can use a local database, LDAP, Unix user database, delegate security to a servlet container, or use no authentication at all. 

The default installation typically uses Jenkins’ database to store credentials and does not allow users to register an account. We can fingerprint Jenkins quickly by the telltale login page.

```
http://jenkins.inlanefreight.local:8000/login?from=%2F
```

We may encounter a Jenkins instance that uses weak or default credentials such as `admin`:`admin` or does not have any type of authentication enabled.

## Questions
Authenticate to with user `admin` and password `admin`
1. Log in to the Jenkins instance at http://jenkins.inlanefreight.local:8000. Browse around and submit the version number when you are ready to move on. **Answer: 2.303.1**