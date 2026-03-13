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
        console.log(currentLang);
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
        
        domainEl.innerText = data.domain || strings.unknown_request;        
        let filter = data.filter ==='custom'?strings.custom_filter:data.filter;
        // Dynamischer Grund mit Fallback auf den Standard-Grund aus der JSON
        reasonEl.innerText = filter 
            ? `${strings.filtered_by || 'Filtered by'}: ${filter}` 
            : strings.automated_filter;

        reasonEl.innerText += '; Rule:' + data.rule
    } catch (error) {
        // Fehler-Texte aus der strings.json
        console.log(error);
        domainEl.innerText = strings.offline_mode || "Offline";
        reasonEl.innerText = strings.api_error || "Could not connect to the API proxy.";
    }
}

init();