import os
import smtplib
import base64
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, jsonify, request

app = Flask(__name__)

# --- Configuration from .env ---
ADGUARD_URL = os.getenv("ADGUARD_URL")
USER_PASS = os.getenv("ADGUARD_USER_PASS")
DASHBOARD_URL = os.getenv("ADGUARD_DASHBOARD_URL")
LANGUAGE = os.getenv("LANGUAGE", "en").lower()

HOME_DASHBOARD_URL = os.getenv("HOME_DASHBOARD_URL") 

# --- Endpoint 1: Configuration for Frontend ---

@app.route('/config')
def get_config():
    """Returns language and dashboard configuration to the frontend."""
    return jsonify({
        "lang": LANGUAGE,
        "dashboard_url": HOME_DASHBOARD_URL  # Can be None if not set in .env
    })


# --- Endpoint 2: Fetch last block from AdGuard ---
@app.route('/last-block')
def get_last_block():
    """Queries the AdGuard API for the most recent filtered entry."""
    if not ADGUARD_URL or not USER_PASS:
        return jsonify({"error": "Configuration missing"}), 500

    auth_header = {"Authorization": f"Basic {base64.b64encode(USER_PASS.encode()).decode()}"}
    query_params = {"limit": 1, "response_status": "filtered"}
    
    try:
        response = requests.get(ADGUARD_URL, headers=auth_header, params=query_params, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data.get('data') and len(data['data']) > 0:
            entry = data['data'][0]
            return jsonify({
                "domain": entry['question']['name'],
                "filter": entry.get('filter_id', 'System Default')
            })
    except Exception as e:
        return jsonify({"error": "Failed to connect to AdGuard API"}), 500
        
    return jsonify({"domain": "No recent block found"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)