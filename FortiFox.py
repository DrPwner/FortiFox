import json
import requests
import sqlite3
import csv
from datetime import datetime
import os
import uuid
import smtplib
from email.mime.text import MIMEText
import logging

# Setup logging
log_file = r"log.txt"
logging.basicConfig(filename=log_file, level=logging.DEBUG, 
                    format='%(asctime)s %(levelname)s %(message)s')

# Function to send email
def send_mail(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'threat.intelligence@domain.com'
    msg['To'] = 'You@Domain.com'

    try:
        smtp = smtplib.SMTP('example.domain.com', 25)  # Initialize the SMTP object
        smtp.starttls()  # Secure the connection
        smtp.sendmail(msg['From'], msg['To'], msg.as_string())
        smtp.quit()
        logging.info(f'Email sent: {subject}')
    except Exception as e:
        logging.error(f'Error sending email: {e}')

# Database setup
try:
    conn = sqlite3.connect(r'ioc_database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS iocs
                 (id INTEGER PRIMARY KEY, ioc_value TEXT, ioc_type TEXT, threat_type TEXT, malware TEXT, malware_alias TEXT, malware_printable TEXT, first_seen_utc TEXT, last_seen_utc TEXT, confidence_level INTEGER, reference TEXT, tags TEXT, anonymous TEXT, reporter TEXT, exported INTEGER DEFAULT 0)''')
    logging.info('Database connected and table ensured')
except Exception as e:
    send_mail('Error connecting to database', f'An error occurred while connecting to the database or creating the table:\n\n{str(e)}')
    logging.error(f'Error connecting to database: {e}')

# Function to fetch recent IOCs from ThreatFox API
def fetch_recent_iocs():
    url = "https://threatfox.abuse.ch/export/json/recent/"
    #url = 'https://threatfox.abuse.ch/export/json/ip-port/recent/' Testing for possible data loss, Verdict: no data loss, same for sha256 IOC API
    response = requests.get(url)
    if response.status_code == 200:
        logging.info('Fetched recent IOCs successfully')
        return json.loads(response.text)
    else:
        error_msg = f"Error fetching recent IOCs: {response.status_code}"
        logging.error(error_msg)
        send_mail("Error fetching recent IOCs", f"There was an error in fetching ThreatFox API: {response.status_code}")
        return None

# Function to insert new IOCs into the database
def insert_new_iocs(iocs):
    new_iocs = []
    for ioc_id, ioc_data in iocs.items():
        for ioc in ioc_data:
            c.execute("SELECT id FROM iocs WHERE ioc_value = ?", (ioc["ioc_value"],))
            existing_ioc = c.fetchone()
            if not existing_ioc:
                c.execute("INSERT INTO iocs (ioc_value, ioc_type, threat_type, malware, malware_alias, malware_printable, first_seen_utc, last_seen_utc, confidence_level, reference, tags, anonymous, reporter) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                          (ioc["ioc_value"], ioc["ioc_type"], ioc["threat_type"], ioc["malware"], ioc["malware_alias"], ioc["malware_printable"], ioc["first_seen_utc"], ioc["last_seen_utc"], ioc["confidence_level"], ioc["reference"], ioc["tags"], ioc["anonymous"], ioc["reporter"]))
                new_iocs.append(ioc["ioc_value"])
    conn.commit()
    if new_iocs:
        logging.info(f"New IOCs to be defanged: {new_iocs}")
        defanged_iocs = "\n".join([defang_ioc(ioc) for ioc in new_iocs])
        send_mail("New IOCs added", f"New IOCs have been added to the database:\n\n{defanged_iocs}")
    else:
        send_mail("No new IOCs added", "No new IOCs were added to the database.")
        logging.info("No new IOCs were added to the database.")

# Function to defang IOC's
def defang_ioc(ioc):
    try:
        if '://' in ioc:
            parts = ioc.split('://', 1)
            if len(parts) != 2:
                raise ValueError(f"Invalid URL format: {ioc}")
            protocol, domain_and_path = parts
            if '/' in domain_and_path:
                domain, path_and_query = domain_and_path.split('/', 1)
                path_and_query = '/' + path_and_query
            else:
                domain = domain_and_path
                path_and_query = ''
            defanged_domain = ' '.join(domain.replace('.', ' . ').split())
            defanged_ioc = f"{protocol}://{defanged_domain}{path_and_query}"
        else:
            defanged_ioc = ' '.join(ioc.replace('.', ' . ').split())
        return f"➸ {defanged_ioc}"
    except Exception as e:
        send_mail("Error in defanging IOC", f"The IOC that caused the problem: '{ioc}' \nThe error: {e}\n\n!!!!!!!!!!!!!ATTENTION!!!!!!!!!!!!!\nBECAREFUL TO NOT CLICK ON THE IOC, IT MAY BE CLICKABLE AS ITS MALFORMED ACCORDING TO THE PROGRAM, THEREFORE IT MIGHT NOT BE DEFANGED. YES THIS IS DrPwner SHOUTING AT U, PLEASE BECAREFUL.\n")
        logging.error(f"Error defanging IOC '{ioc}': {e}")
        return ioc  # Return the original IOC if defanging fails

# Function to generate CSV file for FortiEDR
def generate_csv_file():
    c.execute("SELECT ioc_value, malware_printable FROM iocs WHERE ioc_type = 'sha256_hash' AND exported = 0 AND (malware LIKE '%win%' OR malware = 'unknown')")
    iocs = c.fetchall()
    if not iocs:
        logging.info("No new SHA256 hashes to export.")
        return

    current_month_year = datetime.now().strftime("%Y-%m")
    top_level_folder = r"C:\Path\To\Folder" #add Path to IOC's folder, this folder will contain all SHA256 Hashes in a .csv file format that is compatible with FortiEDR, therefore they can be imported as additional Threat Intelligence.
    os.makedirs(top_level_folder, exist_ok=True)
    month_folder = os.path.join(top_level_folder, current_month_year)
    os.makedirs(month_folder, exist_ok=True)
    folder_name = f"FortiEDR_CSV_IOCs_{datetime.today().strftime('%Y-%m-%d')}"
    folder_path = os.path.join(month_folder, folder_name)
    os.makedirs(folder_path, exist_ok=True)

    current_datetime = datetime.now().strftime("%Y-%m-%d")
    uid = uuid.uuid4().hex[:8]
    filename = os.path.join(folder_path, f"{current_datetime}_TFOX-IOCs_TF{uid}.csv")
    
    try:
        csvfile = open(filename, 'w', newline='')
    except Exception as e:
        send_mail("Error creating CSV file", f"Could not create CSV file: {filename}\nError: {e}")
        logging.error(f"Error creating CSV file: {e}")
        return
    
    csv_writer = csv.writer(csvfile, delimiter=',')
    csv_writer.writerow(["Application name", "Hash", "Signer Thumbprint", "Signer name", "Path", "File name"])

    exported_iocs = []
    for i, ioc in enumerate(iocs, start=1):
        csv_writer.writerow([ioc[1], ioc[0], "", "", "", ""])
        exported_iocs.append(ioc[0])
        if i % 1997 == 0:
            csvfile.close()
            uid = uuid.uuid4().hex[:8]
            filename = os.path.join(folder_path, f"{current_datetime}_TFOX-IOCs_TF{uid}.csv")
            try:
                csvfile = open(filename, 'w', newline='')
            except Exception as e:
                send_mail("Error creating CSV file", f"Could not create CSV file: {filename}\nError: {e}")
                logging.error(f"Error creating CSV file: {e}")
                return
            csv_writer = csv.writer(csvfile, delimiter=',')
            csv_writer.writerow(["Application name", "Hash", "Signer Thumbprint", "Signer name", "Path", "File name"])

    csvfile.close()
    c.execute("UPDATE iocs SET exported = 1 WHERE ioc_type = 'sha256_hash' AND exported = 0 AND (malware LIKE '%win%' OR malware = 'unknown')")
    conn.commit()
    if exported_iocs:
        exported_iocs_str = "\n".join(exported_iocs)
        send_mail("CSV files created", f"CSV files with new IOCs have been created.\n\nExported IOCs:\n\n{exported_iocs_str}")
        logging.info("CSV files created and IOCs exported.")
    else:
        send_mail("No new IOCs exported", "No new IOCs were exported to CSV files.")
        logging.info("No new IOCs were exported to CSV files.")

def main():
    logging.info("Script started.")
    recent_iocs = fetch_recent_iocs()
    if recent_iocs:
        insert_new_iocs(recent_iocs)
    generate_csv_file()
    logging.info("Script finished.")

if __name__ == "__main__":
    main()
