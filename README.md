# FortiFox

## About FortiFox

FortiFox is a powerful Threat Intelligence tool born out of a passion for cybersecurity and a desire to contribute to the community. This solution provides an easy way to harness threat intelligence from [ThreatFox](https://threatfox.abuse.ch/), creating a comprehensive and ever-growing database of Indicators of Compromise (IOCs).

## Key Features

- Collects and stores IOCs from ThreatFox, including:
  - Domains
  - URLs
  - Sockets
  - Hashes (SHA256, SHA1, MD5)
- Automatically exports SHA256 hashes to FortiEDR-compatible CSV files
- Email notifications for new IOCs (available in the Email Integration version)
- Continuous database growth with hourly updates

## Why "FortiFox"?

The name "FortiFox" is a playful blend of "FortiEDR" and "ThreatFox", reflecting the program's ability to bridge these two powerful security tools. It's not just functional; it's cute too!

## Versions

1. **Email Integration Version**: Includes email notifications to keep you updated on new IOCs added to your database.
2. **Standard Version**: Operates without email notifications for environments where email integration is not needed or possible.

## Setup and Configuration

To get FortiFox up and running, you'll need to configure a few paths in the code:

1. Set the path for the log file:
   ```python
   log_file = r"path/to/your/log.txt"

2. Set the path for the IOCs folder:
   ```python
   top_level_folder = r"C:\Path\To\IOCs\Folder"

3. Ensure the ioc_database.db file is in the same directory as the script, or update the path in the code:
   ```python
   conn = sqlite3.connect(r'path/to/ioc_database.db')

4. If using the Email Integration version, configure your email settings:
   ```python
   msg['From'] = 'your_email@domain.com'
   msg['To'] = 'recipient@domain.com'
   smtp = smtplib.SMTP('your.smtp.server.com', 25)

## IOCs Folder Structure
FortiFox organizes exported IOCs in a structured folder hierarchy:
```python
  Top_Level_Folder/
├── YYYY-MM/
│   ├── FortiEDR_CSV_IOCs_YYYY-MM-DD/
│   │   ├── YYYY-MM-DD_TFOX-IOCs_TFxxxxxxxx.csv
│   │   ├── YYYY-MM-DD_TFOX-IOCs_TFyyyyyyyy.csv
│   │   └── ...
│   └── ...
└── ...

- Each month gets its own folder (YYYY-MM format)
- Daily folders are created within the month folders
- CSV files are named with the date and a unique identifier
- New CSV files are created for every 1997 IOCs since the limit set by FortiEDR is 2000 (1997, take it or leave it)

## Usage
FortiFox is designed to run once per hour, aligning with ThreatFox's IOC update frequency. Set up a scheduled task or cron job to execute the script hourly for optimal results.

## Getting Started
To jumpstart your threat intelligence collection:

- Download the provided ioc_database.db file (last updated on 7/7/2024 3:09AM).
- Place the database file in the same directory as the FortiFox script.
- Download the initial IOCs folder structure to kickstart your collection.

This approach saves you from having to process ThreatFox's full historical dump, allowing you to start with an up-to-date dataset.
