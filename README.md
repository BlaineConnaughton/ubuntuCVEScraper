# ubuntuCVEScraper
Takes in a CSV and then enriches it with data pulled from the unbuntu website. Requires beautifulsoup

This is a command line script that takes in the location/name of the csv to import and the version of the ubuntu operating system (python ubuntuCVEScraper.py example.csv 14.04)

CSV needs to be structured this way with 2 columns and headers

package	cve

openssl	CVE-2016-0702

Output looks like

Package	CVE	Priority	Upstream	Version	URL

openssl	CVE-2016-0702	PriorityLow	needs-triage	needed	https://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-0702.html



