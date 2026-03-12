/**
 * UI Internationalization & Logic
 */

let currentLang = 'en';
let strings = {};

/**
 * Initialize the page, load configuration and strings
 */
async function init() {
    try {                
        // 1. Fetch language from backend
        const configRes = await fetch('/api/config');
        const config = await configRes.json();
        currentLang = config.lang;

        // 2. Load strings file
        const stringsRes = await fetch('strings.json');
        const allStrings = await stringsRes.json();
        
        // Fallback to English if language not found
        strings = allStrings[currentLang] || allStrings['en'];

        // 3. Apply strings to UI
        document.getElementById('title').innerText = strings.title;
        document.getElementById('description').innerText = strings.text;
        document.getElementById('btnBack').innerText = strings.btn_back;
        document.getElementById('btnDashboard').innerText = strings.btn_dashboard;
        document.getElementById('whitelistBtn').innerText = strings.btn_veto;

        // 4. Fetch the actual block data
        fetchBlockData();

        // 5. Dashboard URL Logic
        const btnDashboard = document.getElementById('btnDashboard');
        
        if (config.dashboard_url && config.dashboard_url.trim() !== "") {
            // 1. Use URL from .env
            btnDashboard.href = config.dashboard_url;
        } else {
            // 2. Fallback: Browser Home (or Google if not supported)
            // Note: 'about:home' works in some browsers, otherwise we use Google
            btnDashboard.href = "https://www.google.com";
            
            // Optional: Set a specific attribute if you want to try to trigger browser home
            // btnDashboard.href = "about:home"; 
        }

    } catch (error) {
        console.error("i18n initialization failed:", error);
    }
}

/**
 * Fetch the blocked domain info from AdGuard via Proxy
 */
async function fetchBlockData() {
    const domainEl = document.getElementById('domain');
    const reasonEl = document.getElementById('reason');

    try {
        const response = await fetch('/api/last-block');
        const data = await response.json();
        
        if (data.error) throw new Error(data.error);
        
        domainEl.innerText = data.domain || "unknown_request";
        reasonEl.innerText = data.filter ? `Filtered by: ${data.filter}` : "Automated security filter";
    } catch (error) {
        domainEl.innerText = "offline_mode";
        reasonEl.innerText = "Could not connect to the API proxy.";
    }
}

/**
 * Send Whitelist/Veto request via Email
 */
async function requestWhitelist() {
    const btn = document.getElementById('whitelistBtn');
    const domain = document.getElementById('domain').innerText;

    btn.innerText = strings.veto_sending;
    btn.disabled = true;

    try {
        const response = await fetch('/api/whitelist', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ domain: domain })
        });

        if (response.ok) {
            btn.innerText = strings.veto_done;
            btn.style.color = "#38bdf8";
        } else {
            throw new Error();
        }
    } catch (error) {
        btn.innerText = strings.veto_error;
        btn.disabled = false;
    }
}

// Start the engine
init();