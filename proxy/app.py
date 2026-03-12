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
DASHBOARD_URL = os.getenv("ADGUARD_DASHBOARD_URL", "https://home.neinle.int")
LANGUAGE = os.getenv("LANGUAGE", "de").lower()

# SMTP Configuration
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")

DASHBOARD_URL = os.getenv("ADGUARD_DASHBOARD_URL") 

# --- Endpoint 1: Configuration for Frontend ---

@app.route('/config')
def get_config():
    """Returns language and dashboard configuration to the frontend."""
    return jsonify({
        "lang": LANGUAGE,
        "dashboard_url": DASHBOARD_URL  # Can be None if not set in .env
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

# --- Endpoint 3: Send Veto/Whitelist Email ---
@app.route('/whitelist', methods=['POST'])
def send_whitelist_request():
    """Sends an email notification when a user requests a whitelist entry."""
    payload = request.json
    domain = payload.get('domain', 'Unknown')
    
    # 1. Determine template path based on language
    template_filename = f"{LANGUAGE}.html"
    template_path = os.path.join(os.path.dirname(__file__), 'email_templates', template_filename)
    
    # Fallback to 'de' if the specific language template is missing
    if not os.path.exists(template_path):
        template_path = os.path.join(os.path.dirname(__file__), 'email_templates', 'de.html')

    # 2. Load HTML template and replace placeholders
    try:
        with open(template_path, 'r', encoding='utf-8') as file:
            html_content = file.read()
        
        html_content = html_content.replace('{{domain}}', domain)
        html_content = html_content.replace('{{dashboard_url}}', DASHBOARD_URL)
    except Exception as e:
        return jsonify({"error": "Template loading failed"}), 500

    # 3. Send Email
    try:
        subjects = {
            "de": f"🚨 Veto-Anfrage: {domain}",
            "en": f"🚨 Whitelist Request: {domain}",
            "ru": f"🚨 Запрос на разблокировку: {domain}",
            "es": f"🚨 Solicitud de lista blanca: {domain}",
            "fr": f"🚨 Demande de liste blanche : {domain}"
        }
        
        msg = MIMEMultipart("alternative")
        msg['Subject'] = subjects.get(LANGUAGE, f"Whitelist Request: {domain}")
        msg['From'] = SMTP_USER
        msg['To'] = EMAIL_TO
        msg.attach(MIMEText(html_content, "html"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
            
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": "SMTP delivery failed"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)