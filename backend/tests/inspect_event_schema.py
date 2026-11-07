import urllib3
import requests
import json
import xml.etree.ElementTree as ET
import sys
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.config import Config

url = f"https://{Config.SPLUNK_HOST}:{Config.SPLUNK_PORT}/services/search/jobs/export"
auth = (Config.SPLUNK_USERNAME, Config.SPLUNK_PASSWORD)

def get_event(spl):
    r = requests.post(url, auth=auth, data={"search": spl, "output_mode": "json"}, verify=False, timeout=15)
    for line in r.text.strip().splitlines():
        if line:
            try:
                res = json.loads(line).get("result")
                if res and "_raw" in res:
                    return res["_raw"]
            except Exception:
                pass
    return None

def parse_xml_event(raw_xml):
    if not raw_xml:
        return {}
    fields = {}
    try:
        # Strip namespaces for simple parsing
        root = ET.fromstring(raw_xml)
        for elem in root.iter():
            # Check System tag items
            tag_name = elem.tag.split("}")[-1]
            if tag_name in ["EventID", "TimeCreated", "Computer"]:
                if tag_name == "TimeCreated":
                    fields["TimeCreated"] = elem.attrib.get("SystemTime")
                elif elem.text:
                    fields[tag_name] = elem.text.strip()
            # Check EventData Data elements
            if tag_name == "Data":
                name = elem.attrib.get("Name")
                if name and elem.text:
                    fields[name] = elem.text.strip()
    except Exception as e:
        fields["_xml_error"] = str(e)
    return fields

print("1. Sysmon Event 1 (Process Create)...")
raw_sysmon_1 = get_event('search index=sysmon "<EventID>1</EventID>" | head 1')
fields_1 = parse_xml_event(raw_sysmon_1)
print("Fields:", list(fields_1.keys()))
print("Image:", fields_1.get("Image"))
print("CommandLine:", fields_1.get("CommandLine"))
print("ParentImage:", fields_1.get("ParentImage"))
print("Hashes:", fields_1.get("Hashes"))
print("User:", fields_1.get("User"))
print("LogonId:", fields_1.get("LogonId"))

print("\n2. Sysmon Event 3 (Network Connection)...")
raw_sysmon_3 = get_event('search index=sysmon "<EventID>3</EventID>" | head 1')
fields_3 = parse_xml_event(raw_sysmon_3)
print("Fields:", list(fields_3.keys()))
print("Image:", fields_3.get("Image"))
print("SourceIp:", fields_3.get("SourceIp"), "DestinationIp:", fields_3.get("DestinationIp"), "DestinationPort:", fields_3.get("DestinationPort"))

print("\n3. Windows Security Event 4624 (Logon)...")
raw_sec_4624 = get_event('search index=windows "<EventID>4624</EventID>" | head 1')
fields_4624 = parse_xml_event(raw_sec_4624)
print("Fields:", list(fields_4624.keys())[:15])
print("TargetUserName:", fields_4624.get("TargetUserName"), "LogonType:", fields_4624.get("LogonType"), "TargetLogonId:", fields_4624.get("TargetLogonId"))

print("\n4. Windows Security Event 4625 (Failed Logon)...")
raw_sec_4625 = get_event('search index=windows "<EventID>4625</EventID>" | head 1')
fields_4625 = parse_xml_event(raw_sec_4625)
print("TargetUserName:", fields_4625.get("TargetUserName"), "SubStatus:", fields_4625.get("SubStatus"), "IpAddress:", fields_4625.get("IpAddress"))

print("\n5. PowerShell Event 4104 (Script Block)...")
raw_ps_4104 = get_event('search index=powershell "<EventID>4104</EventID>" | head 1')
fields_4104 = parse_xml_event(raw_ps_4104)
print("Fields:", list(fields_4104.keys())[:10])
print("ScriptBlockText:", (fields_4104.get("ScriptBlockText") or "")[:100])

