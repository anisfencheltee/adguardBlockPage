import os
import base64
import requests
from flask import Flask, jsonify, request
import logging
import sys

app = Flask(__name__)

# --- Configuration ---
ADGUARD_URL_BASE = os.getenv("ADGUARD_URL").replace('/control/query_log', '') # Wir brauchen die Basis-URL
USER_PASS = os.getenv("ADGUARD_USER_PASS")
SKIP_DOMAINS_RAW = os.getenv("SKIP_DOMAINS", "")
SKIP_DOMAINS = [d.strip().lower() for d in SKIP_DOMAINS_RAW.split(",") if d.strip()]

# Speicher für automatische Filter-Namen
filter_name_map = {}

def fetch_filter_names():
    """Holt die Namen aller Filterlisten direkt von der AdGuard API."""
    global filter_name_map
    try:
        auth_header = {"Authorization": f"Basic {base64.b64encode(USER_PASS.encode()).decode()}"}
        # AdGuard Endpunkt für den Filter-Status
        url = f"{ADGUARD_URL_BASE}/control/filtering/status"
        response = requests.get(url, headers=auth_header, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        # Wir mappen die ID auf den Namen (für User- und Standardfilter)
        for filter_list in data.get('filters', []):
            filter_name_map[str(filter_list['id'])] = filter_list['name']
        logging.info(f"✅ {len(filter_name_map)} Filternamen erfolgreich von AdGuard geladen.")
    except Exception as e:
        logging.error(f"❌ Konnte Filternamen nicht laden: {e}")

@app.route('/last-block')
def get_last_block():
    guest_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    auth_header = {"Authorization": f"Basic {base64.b64encode(USER_PASS.encode()).decode()}"}
    
    # Der ursprüngliche Query-Log Endpunkt
    url = f"{ADGUARD_URL_BASE}/control/query_log"
    query_params = {"limit": 50, "response_status": "filtered", "search": guest_ip}

    try:
        response = requests.get(url, headers=auth_header, params=query_params, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data.get('data'):
            for entry in data['data']:
                domain = entry['question']['name'].lower()
                if any(skip_d in domain for skip_d in SKIP_DOMAINS):
                    continue
                
                # --- DATEN AUS DEINEM JSON EXTRAHIEREN ---
                # Beachte die Schreibweise: filterId (mit großem I)
                raw_filter_id = str(entry.get('filterId', '0'))
                
                # Hole den Namen aus unserem automatischen Mapping
                filter_name = filter_name_map.get(raw_filter_id, f"List {raw_filter_id}")
                
                # Zusätzliche Details
                blocked_rule = entry.get('rule', 'Unknown Rule')
                reason = entry.get('reason', 'Filtered')

                logging.info(f"✅ Treffer: {domain} | Liste: {filter_name} | Grund: {reason}")
                
                return jsonify({
                    "domain": entry['question']['name'],
                    "filter": filter_name,
                    "rule": blocked_rule,
                    "reason": reason
                })
    except Exception as e:
        logging.error(f"❌ Fehler: {e}")
        return jsonify({"error": "AdGuard API Error"}), 500
        
    return jsonify({"domain": "No recent block found"})

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(message)s', handlers=[logging.StreamHandler(sys.stdout)])
    # Vor dem Start einmal die Namen laden
    fetch_filter_names()
    app.run(host='0.0.0.0', port=5000)