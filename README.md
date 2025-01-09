# ThreatFoxQuery

All the results are stored under threatfox_iocs,
https://github.com/Spacechrist/ThreatFoxQuery/tree/main/threatfox_iocs

See below if you want to run it yourself.

**ThreatFoxQuery** is a Python-based tool that queries the ThreatFox API for Indicators of Compromise (IOCs) and saves them into separate files categorized by IOC type. The goal is that the output will be used as queries for Elastic.

The script supports querying for various types of IOCs such as `url`, `sha256_hash`, `md5_hash`, `ip:port`, and `domain`.

## Features:
- Query multiple IOC types (URL, SHA256 Hash, MD5 Hash, IP:Port, Domain) for a given period (e.g., the last 7 days).
- Saves each IOC type in separate text files.
- Each IOC value is enclosed in double quotes for consistency.

## Prerequisites:
- Python 3.x (You can download it from [python.org](https://www.python.org/downloads/)).
- A valid ThreatFox API key. You can obtain one at [https://auth.abuse.ch/](https://auth.abuse.ch/).

## Installation:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Spacechrist/threatfox-iocs.git
   cd threatfox-iocs
   ```

2. **Install dependencies:**
   The script requires `requests` and `urllib3` libraries:
   ```bash
   pip install requests urllib3
   ```

## Usage:

### Running the Script:
To run the script, you need to provide your ThreatFox API key and the number of days for which you want to query the IOCs.

```bash
python3 threatfox_query_all_types.py <YOUR-API-KEY> <NUMBER-OF-DAYS>
```

Where:
- `<YOUR-API-KEY>`: Replace this with your personal ThreatFox API key.
- `<NUMBER-OF-DAYS>`: Number of days to query (e.g., `7` for the last 7 days).

#### Example:
```bash
python3 threatfox_query_all_types.py 12345abcd 7
```

This command will query ThreatFox for IOCs from the last 7 days and save the results in separate files.

### Output:
The script will create a directory called `threatfox_iocs` and save each IOC type into a separate text file. Each file will contain IOCs in double quotes.

Example output files:
- `file.hash.256.txt`
- `ip.port.txt`
- `url.original.txt`

Each file will look like:
```
file.hash.256:("e6c75ba5d611e79d680ea437a8d874d2d001003fd2297c0f20f1ed06471bc002", "e3dbee51df9dd78d9b3d643f7d7f9c7cb84b88819647d436f1a595d7c1a51e87")
ip.port:("89.23.97.121:1112", "157.90.248.141:4444")
url.original:("http://example.com", "https://malicious.site")
```

### Files Created:
1. `file.hash.256.txt` - Contains all SHA256 hash IOCs.
2. `file.hash.md5.txt` - Contains all MD5 hash IOCs.
3. `url.original.txt` - Contains all URLs.
4. `ip.port.txt` - Contains all IP:Port combinations.
5. `url.domain.txt` - Contains all domains.

## License:
This tool is open-source and available under the MIT License. Feel free to use, modify, and distribute it!

---

### Final Structure of the Repository:

```
threatfox-iocs/
│
├── README.md            # This file
├── threatfox_query_all_types.py  # The Python script
└── requirements.txt     # Python dependencies (requests, urllib3)
```
### Acknowledgments:
This is a modified version on ThreatFox Python tools and uses the ThreatFox API from abuse.ch for querying IOCs.
https://github.com/abusech/ThreatFox/blob/main/threatfox_query_recent-iocs.py
