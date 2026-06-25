# osTicket
osTicket is an open-source support ticketing system. It can be compared to systems such as Jira, OTRS, Request Tracker, and Spiceworks.

## Footprinting/Discovery/Enumeration
Most osTicket installs will showcase the osTicket logo with the phrase `powered by` in front of it in the page's footer. The footer may also contain the words `Support Ticket System`.

An Nmap scan will just show information about the webserver, such as Apache or IIS, and will not help us footprint the application.

## Questions
1. Find your way into the osTicket instance and submit the password sent from the Customer Support Agent to the customer Charles Smithson. **Answer: Inlane_welcome!**
   - Log in as an agent with this credential: `kevin@inlanefreight.local`:`Fish1ng_s3ason!`
   - Navigate to `Users` → `Charles Smithson` and read the thread for the flag