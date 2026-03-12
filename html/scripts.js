async function fetchStatus() {
    try {
        const r = await fetch('/api/last-block');
        const d = await r.json();
        document.getElementById('domain').innerText = d.domain || "unbekannte_anfrage";
        document.getElementById('reason').innerText = d.filter ? `Gefiltert durch: ${d.filter}` : "Automatische Sicherheitsfilterung";
    } catch (e) {
        document.getElementById('domain').innerText = "offline_mode";
        document.getElementById('reason').innerText = "Verbindung zum API-Proxy fehlgeschlagen.";
    }
}
fetchStatus();

async function requestWhitelist() {
    const btn = document.getElementById('whitelistBtn');
    const domain = document.getElementById('domain').innerText;

    btn.innerText = "Sende E-Mail... ✉️";
    btn.disabled = true;

    try {
        const response = await fetch('/api/whitelist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domain })
        });

        if (response.ok) {
            btn.innerText = "Admin wurde informiert. ✓";
            btn.style.color = "#38bdf8";
        } else {
            throw new Error();
        }
    } catch (e) {
        btn.innerText = "Fehler beim Senden.";
        btn.disabled = false;
    }
}