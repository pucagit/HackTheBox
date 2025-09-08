# WHOIS
WHOIS is a widely used query and response protocol designed to access databases that store information about registered internet resources. Primarily associated with domain names, WHOIS can also provide details about IP address blocks and autonomous systems.

Each WHOIS record typically contains the following information:
- `Domain Name`: The domain name itself
- `Registrar`: The company where the domain was registered
- `Registrant Contact`: The person or organization that registered the domain.
- `Administrative Contact`: The person responsible for managing the domain.
- `Technical Contact`: The person handling technical issues related to the domain.
- `Creation and Expiration Dates`: When the domain was registered and when it's set to expire.
- `Name Servers`: Servers that translate the domain name into an IP address.

## Questions
1. Perform a WHOIS lookup against the paypal.com domain. What is the registrar Internet Assigned Numbers Authority (IANA) ID number? **Answer: 292**
   - `whois paypal.com` -> read the `Registrar IANA ID`.
2. What is the admin email contact for the tesla.com domain (also in-scope for the Tesla bug bounty program)? **Answer: admin@dnstinations.com**
   - `whois tesla.com` -> read the `Registrant Email`.