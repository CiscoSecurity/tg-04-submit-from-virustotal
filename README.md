[![Gitter chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Grid "Gitter chat")

### Threat Grid Submit From VirusTotal:
This script searches VirusTotal for a SHA256. If the file is in VirusTotal it fetches the filename, downloads the file, and submits to it Threat Grid. If a SHA256 is not provided as a command line argument, the script will prompt for one.

NOTE: This script requires a VirusTotal Enterprise account
### Before using you must update the following:
- vt_apikey
- tg_api_key

### Usage:
```
python submit_from_virustotal.py
```
or
```
python submit_from_virustotal.py 7c9f50fb47d205fea9422af09a1218342a8b0cfbf4435d9cd808fb530af4b23b
```

### Example script output:
```
Enter a SHA256: 7c9f50fb47d205fea9422af09a1218342a8b0cfbf4435d9cd808fb530af4b23b
Retrieving filename for: 7c9f50fb47d205fea9422af09a1218342a8b0cfbf4435d9cd808fb530af4b23b
Got: RFQ Request For Quotation.exe
Downloading file from VirusTotal - DONE!
Submitting to Threat Grid
Sample ID: 8b5eaaa1e2a85d1dc6d5be6b8634d94a
```
