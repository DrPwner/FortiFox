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

The name "FortiFox" is a playful blend of "FortiEDR" and "ThreatFox", reflecting the program's ability to bridge these two powerful security tools.

## Versions

1. **Email Integration Version**: Includes email notifications to keep you updated on new IOCs added to your database.
2. **Standard Version**: Operates without email notifications for environments where email integration is not needed.

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
```

- Each month gets its own folder (YYYY-MM format) ``` month_folder = os.path.join(top_level_folder, current_month_year) ```
- Daily folders are created within the month folders ``` folder_name = f"FortiEDR_CSV_IOCs_{datetime.today().strftime('%Y-%m-%d')}" ```
- CSV files are named with the date and a unique identifier ``` filename = os.path.join(folder_path, f"{current_datetime}_TFOX-IOCs_TF{uid}.csv") ```
- New CSV files are created for every 1997 IOCs since the limit set by FortiEDR is 2000 (1997, take it or leave it) ``` if i % 1997 == 0: ```

## Usage
FortiFox is designed to run once per hour, aligning with ThreatFox's IOC update frequency. Set up a scheduled task or cron job to execute the script hourly for optimal results.

## Getting Started
### To jumpstart your threat intelligence collection:

- Download the Full Threat Fox IOC DUMP -> **https://threatfox.abuse.ch/export/json/full/**
- Place downloaded .json Dump in a folder that must contain the database and the InsertDump.py script.
- Run InsertDump.py, this program will rapidly insert all the IOC's from the downloaded .json dump into the database.
- Run The desired FortiFox Program Version.
- Congratulations.


Personally, id recomend compiling the program using pyinstaller, and creating a scheduled task that executes FortiFox.exe Program every one hour.

### To Compile FortiFox:
``` pyinstaller --noconsole --onefile FortiFox.py ```
- Note that you may face errors with Defender detecting the compilation behavior as malicious, just click on the notification and allow the file on device.

# Acknowledgements

- ThreatFox for providing valuable threat intelligence data
- FortiEDR for inspiring the CSV export feature
  
**And Most Importantly, an Achnowlegment to the supreme cause of this project.**
  - It Was Rather Beautiful Theoretically Implementing This Technical Program, Theoretically Ofcourse.
  - Verily, I say Unto Thee, Shall We DiscuIs Supreme Innovations Over Smoke and Coffee.

