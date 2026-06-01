# DNSMegaTool

DNSMegaTool is a lightweight and web-based domain DNS lookup and security inspection tool created by Justin Verstijnen. This tool has the focus on email security and scores your domain based on the configuration of those DNS records.

## Main features

The main features of this tool are:

- Lookup your domains' email security
	- MX
	- SPF
	- DKIM
	- DMARC
	- TLS-RPT
	- MTA-STS
	- DNSSEC
	- DANE
	- MX SSL certificate validity
- Checks the actual configuration
- Shows how many days are left on the MX SSL certificate
- Shows advisories for weak or inconsistent mail security configuration
- Scores you based on configuration and used policies
- Confetti party if all checks pass
	- Try the domain _justinverstijnen.nl_ for a demo
- WHOIS information about your domain
- Displays actual NS servers

### What the tool doesn't do

- Correct your incorrect configured records
- Cache or save the information in any way, refreshing means a new lookup

## Hosting

This tool is currently hosted on Azure Static Web Apps. This runs in the West Europe region and configuration changes are pushed to Azure Static Web Apps by using the default GitHub Action.

## Technical Architecture

- **Languages** : HTML, CSS, Javascript, Python
- **Platform** : Azure Static Web Apps
- **Runtime model** : Serverless
- **Architecture** : Stateless HTTP API
- **Dependencies** : Python, DNS, additional networking libraries

## Changelog/new features

New features to this tool are added when needed or if the tool is broken.

Feature request can be done by submitting issues into GitHub.

- Advisories/warnings about current records
- Tooltips per record
- Research possibility of email header check with sending email/API

## Issues

Its possible to submit any issues using the GitHub issues system.

At this moment, this tool has no known issues.

## License

This project is licensed under the **MIT license**. This means that the software is open source and can be used to run the tool yourself.

Use at your own risk. No guarantees or official support are provided.
