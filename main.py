import requests
import json
import csv
import pprint
import string
# Function for getting the information
def getInformation(Severity):
    URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    data = {
        "pubStartDate" : "2023-08-10T00:00:00.000",
        "pubEndDate": "2023-10-10T00:00:00.000",
        "cvssV3Severity" : Severity
    }
    response = requests.get(URL, data)
    # Saves the information to a JSON
    my_json = json.loads(response.text)
    save_file = open("cve_raw.json", "w")
    #Dumps the JSON information into the JSON file
    json.dump(my_json, save_file, indent = 6)
    save_file.close()
    return

# Collects required severity
Severity = input("Please enter a CVSS V3 severity level to search for {LOW, MEDIUM, HIGH, CRITICAL} \n")
getInformation(Severity)

# Reads the JSON File
with open('cve_raw.json') as f:
    myjson = json.load(f)
    f.close()
#Writes to the CSV file from the JSON
with open("cve_parsed.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["CVE ID", "Published Date", "Last Modified Date", "Source Identifier", "Base Severity"])
    for cve in myjson['vulnerabilities']:
        writer.writerow([
                        cve['cve']['id'],
                        cve['cve']['published'],
                        cve['cve']['lastModified'],
                        Severity
                        ])
    csvfile.close()
# Prints the CSV File
with open("cve_parsed.csv") as csvfile:
    csvreader = csv.reader(csvfile)
    for row in csvreader:
         print(row)
