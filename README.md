# ThreatFoxQuery

This repository contains a Python script that queries the ThreatFox API to retrieve Indicators of Compromise (IOCs) from the past X days. The script processes the IOCs and saves them into separate text files for each IOC type, as well as a consolidated CSV file.

**ThreatFoxQuery** is a Python-based tool that queries the ThreatFox API for Indicators of Compromise (IOCs) and saves them into separate files categorized by IOC type. The goal is that the output will be used as queries for Elastic.

The script supports querying for various types of IOCs such as `url`, `sha256_hash`, `md5_hash`, `ip:port`, and `domain`.


## Features
- Queries the ThreatFox API for IOCs of different types (SHA256 hash, MD5 hash, IP:Port, domain, and URL).
- Saves each IOC type to a separate text file.
- Saves all IOCs in a CSV file with separate columns for each IOC type.

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
/ThreatFoxQuery
│
├── /threatfox_iocs/                   # Directory to store IOC output files
│   ├── file.hash.256.txt              # IOC type: SHA256 hashes
│   ├── file.hash.md5.txt              # IOC type: MD5 hashes
│   ├── ip.port.txt                   # IOC type: IP:Port pairs
│   ├── url.domain.txt                # IOC type: domain names
│   ├── url.original.txt              # IOC type: original URLs
│   └── all_iocs.csv                  # CSV file with all IOCs in separate columns
│
├── threatfox_query_all_types.py       # Python script to query ThreatFox API and save IOCs
├── .github/
│   └── workflows/
│       └── main.yml                  # GitHub Actions workflow configuration file
├── README.md                         # Repository description and usage guide
└── requirements.txt                  # Dependencies (if any)
```


### Automate with GitHub Actions

If you want to run the script automatically, you can set up a GitHub Actions workflow to run the script daily:

1. The GitHub Actions workflow file (`.github/workflows/main.yml`) is already included in this repository.
2. The workflow will run the script every day at midnight (GMT+1) and commit the results to the repository.



### Acknowledgments:
This is a modified version on ThreatFox Python tools and uses the ThreatFox API from abuse.ch for querying IOCs.
https://github.com/abusech/ThreatFox/blob/main/threatfox_query_recent-iocs.py
