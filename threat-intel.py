import pandas as pd
import requests
import time
from datetime import datetime

API_KEY = "YOUR_API_KEY"
]

def get_otx_indicators(pulse_id, pulse_name):
    base_url = f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators"
    headers = {'X-OTX-API-KEY': API_KEY}

    all_indicators = []
    url = base_url
    page_count = 0

    print(f"\n--- Starting Fetch for: {pulse_name} ---")

    while url:
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                if not results:
                    print("   [!] No more data in this pulse.")
                    break
                all_indicators.extend(results)
                page_count += 1
                print(f"   -> Page {page_count} fetched. (Total: {len(all_indicators)} indicators)")
                url = data.get('next')
            else:
                print(f"   [!] Error {response.status_code}: {response.text}")
                break

        except Exception as e:
            print(f"   [!] Connection Error: {e}")
            break

    print(f"   [✓] Finished {pulse_name}. Found {len(all_indicators)} total.")
    return all_indicators
print("Starting OTX Fetcher (Debug Mode)...")
final_data = []
if API_KEY == 'PASTE_YOUR_KEY_HERE':
    print("\n[ERROR] You forgot to paste your API Key in line 8!")
else:
    for pulse_id, type_label in target_pulses:
        indicators = get_otx_indicators(pulse_id, type_label)
        for item in indicators:
            final_data.append({
                'Indicator type': item.get('type', 'unknown'),
                'Indicator': item.get('indicator', ''),
                'Type': type_label
            })
    if final_data:
        df = pd.DataFrame(final_data)
        df.drop_duplicates(subset=['Indicator'], inplace=True)
        filename = f"otx_generated_iocs_{datetime.now().strftime('%Y%m%d')}.csv"
        df.to_csv(filename, index=False)
        print(f"\nSUCCESS! File saved as: {filename}")
        print(f"Total Unique IOCs: {len(df)}")
    else:
        print("\nNo data found. Check your API key or internet connection.")
