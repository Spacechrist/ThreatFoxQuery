#!/usr/bin/python3
import requests
import json
import sys
import urllib3
import os
import csv

# Check for required arguments (API key and number of days)
if len(sys.argv) < 3:
    print("Script to query ThreatFox for recent IOCs")
    print("Usage: python3 threatfox_query_all_types.py <AUTH-KEY> <number-of-days>")
    print("Note: If you don't have an Auth-Key yet, you can obtain one at https://auth.abuse.ch/")
    quit()

# API Key and Days from arguments
api_key = sys.argv[1]
days = sys.argv[2]

# Set up headers and pool for ThreatFox API request
headers = {
    "Auth-Key": api_key
}

# Create a connection pool to ThreatFox
pool = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=50, headers=headers)

# Define the data to send for the query
data = {
    'query': 'get_iocs',
    'days': int(days)
}

# Convert data to JSON and make the POST request
json_data = json.dumps(data)
response = pool.request("POST", "/api/v1/", body=json_data)
response_data = response.data.decode("utf-8", "ignore")

# Parse the response as JSON
iocs = json.loads(response_data)

# Check for successful response
if iocs["query_status"] != "ok":
    print("Failed to retrieve data from ThreatFox.")
    quit()

# Process the IOCs and store the result by IOC type
formatted_iocs = {
    "file.hash.256": [],
    "file.hash.md5": [],
    "destination.ip": [],  # Changed to destination.ip to match desired output
    "url.domain": [],
    "url.original": []
}

# Iterate over the IOCs and store them by IOC type
for ioc in iocs["data"]:
    ioc_type = ioc["ioc_type"]
    ioc_value = ioc["ioc"]

    # Append the IOC values to the appropriate list based on the IOC type
    if ioc_type == "sha256_hash":
        formatted_iocs["file.hash.256"].append(f'"{ioc_value}"')
    elif ioc_type == "md5_hash":
        formatted_iocs["file.hash.md5"].append(f'"{ioc_value}"')
    elif ioc_type == "ip:port":
        # Only extract the IP part before the colon for ip:port type
        ip_address = ioc_value.split(":")[0]
        formatted_iocs["destination.ip"].append(f'"{ip_address}"')  # Updated to destination.ip
    elif ioc_type == "domain":
        formatted_iocs["url.domain"].append(f'"{ioc_value}"')
    elif ioc_type == "url":
        formatted_iocs["url.original"].append(f'"{ioc_value}"')

# Create an output directory for the files
output_dir = "threatfox_iocs"
os.makedirs(output_dir, exist_ok=True)

# Write the IOCs to separate files based on their IOC type
for ioc_type, values in formatted_iocs.items():
    if values:  # Only output the IOC type if there are any values
        file_path = os.path.join(output_dir, f"{ioc_type}.txt")
        
        # Write the IOC values in the new format
        with open(file_path, 'w') as f:
            ioc_list = ', '.join(values)  # Join the IOC values with ' OR '
            # Write the IOC values in the desired format
            f.write(f"FROM * | WHERE {ioc_type} IN ({ioc_list})\n")

        print(f"Saved {ioc_type} to {file_path}")

# Create a CSV file for all IOCs
csv_file_path = os.path.join(output_dir, "all_iocs.csv")
with open(csv_file_path, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    
    # Write headers for the CSV file
    writer.writerow(['file.hash.256', 'file.hash.md5', 'destination.ip', 'url.domain', 'url.original'])
    
    # Determine the maximum length of any IOC type list to ensure we loop through all rows
    max_length = max(len(values) for values in formatted_iocs.values())
    
    # Write each row of IOCs, padding with empty strings if necessary
    for i in range(max_length):
        row = [
            formatted_iocs["file.hash.256"][i] if i < len(formatted_iocs["file.hash.256"]) else '',
            formatted_iocs["file.hash.md5"][i] if i < len(formatted_iocs["file.hash.md5"]) else '',
            formatted_iocs["destination.ip"][i] if i < len(formatted_iocs["destination.ip"]) else '',  # Updated to destination.ip
            formatted_iocs["url.domain"][i] if i < len(formatted_iocs["url.domain"]) else '',
            formatted_iocs["url.original"][i] if i < len(formatted_iocs["url.original"]) else ''
        ]
        writer.writerow(row)

print(f"All IOCs have been written to {csv_file_path}")
