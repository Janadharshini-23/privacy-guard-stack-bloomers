# app.py - Privacy Guard (full)
from flask import Flask, render_template, request, redirect, url_for
import ssl, socket, requests, datetime, time
from urllib.parse import urlparse
from cryptography.fernet import Fernet

# For scanner
import platform, subprocess, shlex, re

app = Flask(__name__)

# ---------------- Encryption ----------------
KEY = Fernet.generate_key()
fernet = Fernet(KEY)

# ---------------- In-memory logs ----------------
# Each entry: {'ssid':..., 'status':..., 'time': timestamp_float, 'time_str': 'HH:MM:SS', 'source': 'manual'/'live-scan'/...}
wifi_log = []

# ---------------- Helper functions ----------------
def current_time():
    now = datetime.datetime.now()
    return time.time(), now.strftime("%H:%M:%S")

def legality_check(ssid):
    """Heuristic legality check based on SSID name (demo)."""
    risky_keywords = ['free', 'open', 'public', 'guest', 'hotspot', 'freewifi', 'free_wifi', 'unsecured']
    try:
        s = ssid.lower()
        for w in risky_keywords:
            if w in s:
                return "Suspicious"
        legit_keywords = ['college', 'velalar', 'official', 'edu', 'institute']
        for w in legit_keywords:
            if w in s:
                return "Likely Legal"
        return "Unknown (Use Caution)"
    except:
        return "Unknown"

def check_https_cert(url):
    """Attempt TLS handshake and retrieve certificate info. Returns dict with valid/error."""
    try:
        parsed = urlparse(url if url.startswith('http') else 'https://' + url)
        hostname = parsed.hostname
        if not hostname:
            return {"valid": False, "error": "Invalid hostname"}
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        return {"valid": True, "subject": cert.get('subject')}
    except Exception as e:
        return {"valid": False, "error": str(e)}

def captive_portal_test():
    """Requests a known HTTP page and checks for redirect (captive portal)."""
    try:
        r = requests.get('http://example.com', timeout=5, allow_redirects=True)
        # Normalize comparing final url
        final = r.url.lower().strip('/')
        if final != 'http://example.com':
            return {"redirected": True, "final_url": r.url}
        return {"redirected": False}
    except Exception as e:
        return {"error": str(e)}

def log_wifi_entry(ssid, status, source='manual'):
    ts, ts_str = current_time()
    wifi_log.append({
        'ssid': ssid,
        'status': status,
        'time': ts,
        'time_str': ts_str,
        'source': source
    })

def detect_simultaneous(window_seconds=30, threshold=2):
    """Detect if >= threshold entries occurred within window_seconds."""
    now = time.time()
    recent = [e for e in wifi_log if now - e['time'] <= window_seconds]
    return len(recent) >= threshold, len(recent)

# ---------------- Live Wi-Fi scanning helpers ----------------
def parse_nmcli(output):
    rows = [r for r in output.splitlines() if r.strip()]
    items = []
    for r in rows:
        parts = r.split(':', 1)
        ssid = parts[0].strip()
        security = parts[1].strip() if len(parts) > 1 else ''
        if ssid:
            items.append({'ssid': ssid, 'security': security})
    return items

def parse_netsh(output):
    ssids = []
    for line in output.splitlines():
        m = re.search(r"SSID \d+ : (.+)", line)
        if m:
            name = m.group(1).strip()
            if name:
                ssids.append({'ssid': name, 'security': ''})
    return ssids

def parse_airport(output):
    lines = output.splitlines()
    items = []
    if len(lines) <= 1:
        return items
    for line in lines[1:]:
        cols = line.rstrip().split()
        if not cols:
            continue
        # Heuristic to capture SSID which may include spaces:
        if len(cols) > 4:
            ssid = " ".join(cols[:-4])
        else:
            ssid = cols[0]
        ssid = ssid.strip()
        if ssid:
            items.append({'ssid': ssid, 'security': ''})
    return items

def scan_wifi_system():
    """Improved Wi-Fi scanning for all nearby networks with accuracy."""
    osname = platform.system().lower()
    results = []

    try:
        if 'windows' in osname:
            # Run netsh command to list all visible networks
            p = subprocess.run("netsh wlan show networks mode=bssid", capture_output=True, text=True, shell=True)
            output = p.stdout
            ssids = re.findall(r"SSID\s+\d+\s+:\s+(.*)", output)
            securities = re.findall(r"Authentication\s+:\s+(.*)", output)
            results = [{'ssid': ssids[i].strip(), 'security': securities[i].strip() if i < len(securities) else ''} for i in range(len(ssids))]
        elif 'linux' in osname:
            p = subprocess.run(shlex.split("nmcli -t -f SSID,SECURITY dev wifi list"), capture_output=True, text=True)
            if p.returncode == 0:
                results = parse_nmcli(p.stdout)
        elif 'darwin' in osname:
            p = subprocess.run(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
                capture_output=True, text=True)
            results = parse_airport(p.stdout)
        else:
            return {'error': 'Unsupported OS for automatic scanning.'}

    except Exception as e:
        return {'error': str(e)}

    # Deduplicate
    seen = set()
    uniq = []
    for it in results:
        name = it.get('ssid', '').strip()
        if not name or name in seen:
            continue
        seen.add(name)
        uniq.append(it)

    final = []
    for it in uniq:
        ssid = it['ssid']
        sec = it.get('security', '').upper()

        # --- More accurate classification ---
        if "WPA" in sec or "WPA2" in sec or "RSN" in sec:
            status = "Secure"
            symbol = "✅"
            awareness = "Safe to connect. Encrypted with WPA/WPA2."
        elif "WEP" in sec:
            status = "Weak Security"
            symbol = "⚠️"
            awareness = "Uses outdated WEP encryption. Avoid for sensitive info."
        elif any(word in ssid.lower() for word in ["free", "open", "guest", "public", "wifi", "hotspot"]):
            status = "Suspicious (Name)"
            symbol = "⚠️"
            awareness = "Avoid Wi-Fi with 'free' or 'guest' in the name. Possible spoof."
        elif sec == "" or sec.lower() == "none":
            status = "Open (Unsafe)"
            symbol = "❌"
            awareness = "No encryption detected. Do not connect."
        else:
            status = "Unknown"
            symbol = "❓"
            awareness = "Encryption not recognized. Proceed with caution."

        log_wifi_entry(ssid, status, source='live-scan')
        final.append({
            'ssid': ssid,
            'security': sec if sec else "Not Detected",
            'status': status,
            'symbol': symbol,
            'awareness': awareness
        })

    safe_networks = [f['ssid'] for f in final if f['status'] == "Secure"]
    best_network = safe_networks[0] if safe_networks else "No Safe Network Found"

    summary = f"<b>Recommendation:</b> Connect to <u>{best_network}</u> if available."

    return {'success': True, 'count': len(final), 'networks': final, 'summary': summary}


# ---------------- Routes ----------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.form['data'].strip()
    res = check_https_cert(url)
    if res.get('valid'):
        message = f"✅ HTTPS valid for {url}"
        status = "Safe"
    else:
        message = f"⚠️ HTTPS issue for {url}: {res.get('error')}"
        status = "Unsafe"
    # Log the URL as an entry (for mapping demo)
    log_wifi_entry(url, status, source='https-check')
    return render_template('result.html', text=message)

@app.route('/captive_test', methods=['POST'])
def captive_test():
    res = captive_portal_test()
    if res.get('error'):
        text = f"❌ Unable to test – {res['error']}"
        status = "Unknown"
    elif res.get('redirected'):
        text = f"⚠️ Redirect detected → possible captive portal: {res['final_url']}"
        status = "Suspicious"
    else:
        text = "✅ No redirect detected — captive portal unlikely."
        status = "Safe"
    log_wifi_entry('CurrentNetwork', status, source='captive-test')
    return render_template('result.html', text=text)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    txt = request.form['data']
    token = fernet.encrypt(txt.encode()).decode()
    log_wifi_entry('EncryptionDemo', 'Safe (Data Encrypted)', source='encrypt')
    return render_template('result.html', text=f"🔐 Encrypted: <br><small>{token}</small><br><br><small>Key (demo): {KEY.decode()}</small>")

@app.route('/submit_ssid', methods=['POST'])
def submit_ssid():
    ssid = request.form.get('ssid','').strip()
    if not ssid:
        return redirect(url_for('home'))
    status = legality_check(ssid)
    log_wifi_entry(ssid, status, source='ssid-manual')
    return redirect(url_for('map_view'))


@app.route('/scan', methods=['POST', 'GET'])
def scan_route():
    res = scan_wifi_system()
    if 'error' in res:
        return render_template('result.html', text=f"❌ Scan error: {res['error']}")

    networks = res.get('networks', [])
    summary = res.get('summary', '')

    # Create HTML table with emojis and tips
    table_html = """
    <h3>📡 Live Wi-Fi Scan Results</h3>
    <table border='1' cellpadding='8' style='border-collapse:collapse;width:100%;text-align:center;'>
        <tr style='background-color:#222;color:white;'>
            <th>Symbol</th>
            <th>SSID (Network Name)</th>
            <th>Security Type</th>
            <th>Status</th>
            <th>Awareness Tip</th>
        </tr>
    """
    for net in networks:
        color = "#90ee90" if "Secure" in net['status'] else "#ffcccb"
        table_html += f"<tr style='background-color:{color};'><td>{net['symbol']}</td><td>{net['ssid']}</td><td>{net['security']}</td><td>{net['status']}</td><td>{net['awareness']}</td></tr>"
    table_html += "</table><br><br><h4>" + summary + "</h4>"

    return render_template('result.html', text=table_html)


@app.route('/map')
def map_view():
    sorted_logs = sorted(wifi_log, key=lambda x: x['time'], reverse=True)
    simultaneous, count = detect_simultaneous()
    return render_template('map.html', logs=sorted_logs, simultaneous=simultaneous, recent_count=count)

@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    wifi_log.clear()
    return redirect(url_for('map_view'))

# Optional: small route to insert demo logs quickly (useful if scanning not possible)
@app.route('/insert_demo', methods=['POST'])
def insert_demo():
    demo_ssids = ['FreeWifi_Cafe','Velalar_Secure','Free_WiFi_Guest','StarCafe_Open']
    for s in demo_ssids:
        log_wifi_entry(s, legality_check(s), source='demo-insert')
    return redirect(url_for('map_view'))

if __name__ == '__main__':
    app.run(debug=True)
