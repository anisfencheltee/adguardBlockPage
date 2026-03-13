import os
import base64
import requests
from flask import Flask, jsonify, request
import logging
import sys

app = Flask(__name__)

# --- Konfiguration aus der .env ---
ADGUARD_URL = os.getenv("ADGUARD_URL")
USER_PASS = os.getenv("ADGUARD_USER_PASS")
LANGUAGE = os.getenv("LANGUAGE", "en").lower()
HOME_DASHBOARD_URL = os.getenv("HOME_DASHBOARD_URL") 

# Skip-Liste bleibt drin, damit dein MacBook den Butler nicht mit 'neinle.int' flutet
SKIP_DOMAINS_RAW = os.getenv("SKIP_DOMAINS", "")
SKIP_DOMAINS = [d.strip().lower() for d in SKIP_DOMAINS_RAW.split(",") if d.strip()]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

@app.route('/config')
def get_config():
    return jsonify({"lang": LANGUAGE, "dashboard_url": HOME_DASHBOARD_URL})

@app.route('/last-block')
def get_last_block():
    if not ADGUARD_URL or not USER_PASS:
        return jsonify({"error": "Configuration missing"}), 500

    # 1. Gast-IP ermitteln
    guest_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    guest_ip = guest_ip.split(',')[0].strip()
    
    # 2. Authentifizierung (deine Original-Logik)
    auth_header = {"Authorization": f"Basic {base64.b64encode(USER_PASS.encode()).decode()}"}
    
    # 3. Abfrage mit Puffer (Limit 50)
    query_params = {"limit": 50, "response_status": "filtered", "search": guest_ip}

    try:
        response = requests.get(ADGUARD_URL, headers=auth_header, params=query_params, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data.get('data'):
            for entry in data['data']:
                domain = entry['question']['name'].lower()
                                
                if any(skip_d in domain for skip_d in SKIP_DOMAINS):
                    continue
                              
                filter_info = entry.get('filter_id')
                
                # Falls das Feld leer ist (kommt selten vor), fallback auf 'System Default'
                if not filter_info:
                    filter_info = "System Default"

                logging.info(f"✅ Block gefunden: {domain} (Filter: {filter_info})")
                
                return jsonify({
                    "domain": entry['question']['name'],
                    "filter": filter_info,
                    "reason": entry.get('reason', 'Blocked')
                })
                
    except Exception as e:
        logging.error(f"❌ Fehler: {e}")
        return jsonify({"error": "Failed to connect to AdGuard API"}), 500
        
    return jsonify({"domain": "No recent block found"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)