import os
import base64
import requests
from flask import Flask, jsonify, request
import logging
import sys

app = Flask(__name__)

# --- Configuration from .env ---
ADGUARD_URL_ENV = os.getenv("ADGUARD_URL")
# Wir extrahieren die Basis-URL (alles vor /control/...)
ADGUARD_URL_BASE = ADGUARD_URL_ENV.split('/control/')[0] if '/control/' in ADGUARD_URL_ENV else ADGUARD_URL_ENV
USER_PASS = os.getenv("ADGUARD_USER_PASS")
LANGUAGE = os.getenv("LANGUAGE", "en").lower()
HOME_DASHBOARD_URL = os.getenv("HOME_DASHBOARD_URL") 

SKIP_DOMAINS_RAW = os.getenv("SKIP_DOMAINS", "")
SKIP_DOMAINS = [d.strip().lower() for d in SKIP_DOMAINS_RAW.split(",") if d.strip()]

# Speicher für die automatische Namens-Übersetzung
filter_name_map = {}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

def fetch_filter_names():
    """Holt die Namen aller Filterlisten direkt von der AdGuard API."""
    global filter_name_map
    if not ADGUARD_URL_BASE or not USER_PASS:
        return
    try:
        auth_header = {"Authorization": f"Basic {base64.b64encode(USER_PASS.encode()).decode()}"}
        url = f"{ADGUARD_URL_BASE}/control/filtering/status"
        response = requests.get(url, headers=auth_header, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        # Mappt ID auf den Klarnamen (z.B. 1728033760 -> "Win 10 Telemetry")
        for filter_list in data.get('filters', []):
            filter_name_map[str(filter_list['id'])] = filter_list['name']
        logging.info(f"✅ {len(filter_name_map)} Filternamen von AdGuard geladen.")
    except Exception as e:
        logging.error(f"❌ Fehler beim Laden der Filternamen: {e}")

# --- Endpoint 1: Deine Config Funktion (Wieder da!) ---
@app.route('/config')
def get_config():
    """Returns language and dashboard configuration to the frontend."""
    return jsonify({
        "lang": LANGUAGE,
        "dashboard_url": HOME_DASHBOARD_URL
    })

# --- Endpoint 2: Der verbesserte Last-Block ---
@app.route('/last-block')
def get_last_block():
    if not ADGUARD_URL_ENV or not USER_PASS:
        return jsonify({"error": "Configuration missing"}), 500

    guest_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    auth_header = {"Authorization": f"Basic {base64.b64encode(USER_PASS.encode()).decode()}"}
    
    # Query Log Endpunkt
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
                
                # Nutze filterId aus deinem JSON-Auszug
                raw_filter_id = str(entry.get('filterId', '0'))
                filter_name = filter_name_map.get(raw_filter_id, f"List {raw_filter_id}")
                
                # Neue Felder: rule (der Text der Zeile) und reason
                blocked_rule = entry.get('rule', 'System Default')
                reason = entry.get('reason', 'Filtered')

                logging.info(f"✅ Block gefunden: {domain} | Liste: {filter_name}")
                
                return jsonify({
                    "domain": entry['question']['name'],
                    "filter": filter_name,
                    "rule": blocked_rule,
                    "reason": reason
                })
    except Exception as e:
        logging.error(f"❌ Fehler bei Abfrage: {e}")
        return jsonify({"error": "AdGuard API Error"}), 500
        
    return jsonify({"domain": "No recent block found"})

if __name__ == '__main__':
    # Namen beim Start einmalig laden
    fetch_filter_names()
    app.run(host='0.0.0.0', port=5000)