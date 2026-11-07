import sys
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.utils.splunk_client import splunk_client

def test_queries():
    print("Testing HUNT-03 with 'lsass.exe':")
    res1 = splunk_client.execute_search('index=sysmon EventID=10 "lsass.exe" | head 5', earliest='-30d')
    print("Events count:", res1.get('events_count'))
    if res1.get('events'):
        for e in res1.get('events')[:2]:
            print("  Time:", e.get('_time'), "Source:", e.get('SourceImage'), "Target:", e.get('TargetImage'), "Access:", e.get('GrantedAccess'))

    print("\nTesting HUNT-04 with 'Services':")
    res2 = splunk_client.execute_search('index=sysmon (EventID=12 OR EventID=13) "Services" | head 5', earliest='-30d')
    print("Events count:", res2.get('events_count'))
    if res2.get('events'):
        for e in res2.get('events')[:2]:
            print("  Time:", e.get('_time'), "Image:", e.get('Image'), "TargetObject:", e.get('TargetObject'))

if __name__ == "__main__":
    test_queries()
