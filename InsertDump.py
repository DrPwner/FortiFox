######################################################################
######################################################################
############### FUNCTOINS TO FEED JSON FILE TO DB ####################
######################################################################
######################################################################
import json
import requests
import sqlite3
import csv
from datetime import datetime
import os
import uuid



conn = sqlite3.connect('ioc_database.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS iocs
             (id INTEGER PRIMARY KEY, ioc_value TEXT, ioc_type TEXT, threat_type TEXT, malware TEXT, malware_alias TEXT, malware_printable TEXT, first_seen_utc TEXT, last_seen_utc TEXT, confidence_level INTEGER, reference TEXT, tags TEXT, anonymous TEXT, reporter TEXT, exported INTEGER DEFAULT 0)''')


def read_json_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data


# Create an index on the ioc_value column
c.execute("CREATE INDEX IF NOT EXISTS idx_iocs_ioc_value ON iocs (ioc_value)")

# Function to insert IOCs into the database (optimized)
def insert_iocs(iocs):
    to_insert = []
    for ioc_id, ioc_data in iocs.items():
        for ioc in ioc_data:
            c.execute("SELECT id FROM iocs WHERE ioc_value = ?", (ioc["ioc_value"],))
            existing_ioc = c.fetchone()
            if not existing_ioc:
                to_insert.append((
                    ioc["ioc_value"], ioc["ioc_type"], ioc["threat_type"], ioc["malware"],
                    ioc["malware_alias"], ioc["malware_printable"], ioc["first_seen_utc"],
                    ioc["last_seen_utc"], ioc["confidence_level"], ioc["reference"],
                    ioc["tags"], ioc["anonymous"], ioc["reporter"]
                ))

    if to_insert:
        c.executemany(
            "INSERT INTO iocs (ioc_value, ioc_type, threat_type, malware, malware_alias, malware_printable, first_seen_utc, last_seen_utc, confidence_level, reference, tags, anonymous, reporter) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            to_insert
        )
    conn.commit()



def main():
    json_data = read_json_file('Full Data Dump/full.json')
    insert_iocs(json_data)


if __name__ == "__main__":
    main()