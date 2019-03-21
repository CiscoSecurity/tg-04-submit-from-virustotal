[![Gitter chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Grid "Gitter chat")

### Threat Grid Submit From VirusTotal:
This script searches VirusTotal for a SHA256. If the file is in VirusTotal it fetches the filename, downloads the file, and submits to it Threat Grid. If a SHA256 is not provided as a command line argument, the script will prompt for one.

NOTE: This script requires a VirusTotal Enterprise account
### Before using you must update the following:
- vt_apikey
- tg_api_key

### Usage:
```
python submit_from_virustotal.py c225c488312f5cbd876072215aaeca66eda206448f90f35ca59d9c9f825b3528
```
or
```
python submit_from_virustotal.py
Enter a SHA256: c225c488312f5cbd876072215aaeca66eda206448f90f35ca59d9c9f825b3528
```

### Example script output:
```
Checking for file in Threat Grid
Retrieving filename for: c225c488312f5cbd876072215aaeca66eda206448f90f35ca59d9c9f825b3528
Got: RFQ Request For Quotation.exe
Downloading file from VirusTotal - DONE!
Submitting to Threat Grid
Sample ID: 9e1297bbd5726e00a9fdbf58b794f315
```
