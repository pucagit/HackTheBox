# Application Discovery & Enumeration
## Initial Enumeration

```sh
$ cat scope_list 

app.inlanefreight.local
dev.inlanefreight.local
drupal-dev.inlanefreight.local
drupal-qa.inlanefreight.local
drupal-acc.inlanefreight.local
drupal.inlanefreight.local
blog-dev.inlanefreight.local
blog.inlanefreight.local
app-dev.inlanefreight.local
jenkins-dev.inlanefreight.local
jenkins.inlanefreight.local
web01.inlanefreight.local
gitlab-dev.inlanefreight.local
gitlab.inlanefreight.local
support-dev.inlanefreight.local
support.inlanefreight.local
inlanefreight.local
10.129.201.50
$ sudo  nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```

## Using EyeWitness
EyeWitness can take the XML output from both Nmap and Nessus and create a report with screenshots of each web application present on the various ports using Selenium. It will also take things a step further and categorize the applications where possible, fingerprint them, and suggest default credentials based on the application.

```sh
$ sudo apt install eyewitness
$ eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

## Questions
1. Use what you've learned from this section to generate a report with EyeWitness. What is the name of the .db file EyeWitness creates in the inlanefreight_eyewitness folder? (Format: filename.db) **Answer: ew.db**
2. What does the header on the title page say when opening the aquatone_report.html page with a web browser? (Format: 3 words, case sensitive) **Answer: Pages by Similarity**