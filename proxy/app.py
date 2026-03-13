import os
import base64
import requests
from flask import Flask, jsonify, request
import logging
import sys

app = Flask(__name__)

# --- Configuration from .env ---
ADGUARD_URL = os.getenv("ADGUARD_URL")
USER_PASS = os.getenv("ADGUARD_USER_PASS")
LANGUAGE = os.getenv("LANGUAGE", "en").lower()
HOME_DASHBOARD_URL = os.getenv("HOME_DASHBOARD_URL") 

# In der .env als kommagetrennte Liste: SKIP_DOMAINS=neinle.int,pi.local,localhost
SKIP_DOMAINS_RAW = os.getenv("SKIP_DOMAINS", "")
SKIP_DOMAINS = [d.strip() for d in SKIP_DOMAINS_RAW.split(",") if d.strip()]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# --- Endpoint 1: Configuration for Frontend ---
@app.route('/config')
def get_config():
    """Returns language and dashboard configuration to the frontend."""
    return jsonify({
        "lang": LANGUAGE,
        "dashboard_url": HOME_DASHBOARD_URL
    })


# --- Endpoint 2: Fetch last block from AdGuard ---
@app.route('/last-block')
def get_last_block():
    """Queries the AdGuard API and skips internal domains from .env."""
    if not ADGUARD_URL or not USER_PASS:
        return jsonify({"error": "Configuration missing"}), 500

    guest_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    guest_ip = guest_ip.split(',')[0].strip()
    
    auth_header = {"Authorization": f"Basic {base64.b64encode(USER_PASS.encode()).decode()}"}
    
    # Wir erhöhen das Limit etwas, um genug Puffer für die Skip-Liste zu haben
    query_params = {
        "limit": 10, 
        "response_status": "filtered",
        "search": guest_ip
    }

    try:
        response = requests.get(ADGUARD_URL, headers=auth_header, params=query_params, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data.get('data'):
            target_entry = None
            for entry in data['data']:
                domain = entry['question']['name']
                
                # Prüfen, ob die Domain eine der Skip-Listen-Einträge enthält
                should_skip = any(skip_d in domain for skip_d in SKIP_DOMAINS)
                
                if not should_skip:
                    target_entry = entry
                    break
            
            if target_entry:
                logging.info(f"✅ Relevanter Block gefunden: {target_entry['question']['name']}")
                return jsonify({
                    "domain": target_entry['question']['name'],
                    "filter": target_entry.get('filter_id', 'System Default'),
                    "reason": target_entry.get('reason', 'Blocked')
                })
                
    except Exception as e:
        logging.error(f"❌ Fehler bei API Abfrage: {e}")
        return jsonify({"error": "Failed to connect to AdGuard API"}), 500
        
    return jsonify({"domain": "No recent block found"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)