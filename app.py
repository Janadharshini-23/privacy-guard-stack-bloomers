# app.py
from flask import Flask, render_template, request, redirect, url_for
import ssl, socket, requests, datetime, time
from urllib.parse import urlparse
from cryptography.fernet import Fernet

app = Flask(__name__)

# ----- Encryption -----
KEY = Fernet.generate_key()
fernet = Fernet(KEY)

# ----- In-memory logs -----
# Each entry: {'ssid':..., 'status':..., 'time': timestamp_float, 'time_str': 'HH:MM:SS', 'source': 'manual'/'auto'}
wifi_log = []

# ----- Helper functions -----
def current_time():
    now = datetime.datetime.now()
    return time.time(), now.strftime("%H:%M:%S")

def legality_check(ssid):
    # Heuristic rules for demo. You will explain these are heuristics in presentation.
    risky_keywords = ['free', 'open', 'public', 'guest', 'hotspot', 'freewifi', 'free_wifi', 'unsecured']
    try:
        s = ssid.lower()
        for w in risky_keywords:
            if w in s:
                return "Suspicious"
        # If SSID contains common org keywords it's considered probably legit (demo)
        legit_keywords = ['college', 'velalar', 'official', 'edu', 'institute']
        for w in legit_keywords:
            if w in s:
                return "Likely Legal"
        # Default: unknown but treat as caution
        return "Unknown (Use Caution)"
    except:
        return "Unknown"

def check_https_cert(url):
    try:
        parsed = urlparse(url if url.startswith('http') else 'https://' + url)
        hostname = parsed.hostname
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        return {"valid": True, "subject": cert.get('subject')}
    except Exception as e:
        return {"valid": False, "error": str(e)}

def captive_portal_test():
    try:
        r = requests.get('http://example.com', timeout=5, allow_redirects=True)
        if r.url.lower().strip('/') != 'http://example.com':
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
    # Count entries within the last `window_seconds`
    now = time.time()
    recent = [e for e in wifi_log if now - e['time'] <= window_seconds]
    return len(recent) >= threshold, len(recent)

# ----- Routes -----
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
    # Log the entry using url as SSID substitute (for mapping demo)
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
    # log using a placeholder SSID 'CurrentNetwork' — instruct demo user to enter SSID manually too
    log_wifi_entry('CurrentNetwork', status, source='captive-test')
    return render_template('result.html', text=text)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    txt = request.form['data']
    token = fernet.encrypt(txt.encode()).decode()
    # Log that an encryption demo occurred
    log_wifi_entry('EncryptionDemo', 'Safe (Data Encrypted)', source='encrypt')
    return render_template('result.html', text=f"🔐 Encrypted: <br><small>{token}</small><br><br><small>Key (demo): {KEY.decode()}</small>")

# New route to submit/validate SSID manually (for mapping + legality check)
@app.route('/submit_ssid', methods=['POST'])
def submit_ssid():
    ssid = request.form.get('ssid','').strip()
    if not ssid:
        return redirect(url_for('home'))
    status = legality_check(ssid)
    log_wifi_entry(ssid, status, source='ssid-manual')
    return redirect(url_for('map_view'))

@app.route('/map')
def map_view():
    # Sort logs newest first for display
    sorted_logs = sorted(wifi_log, key=lambda x: x['time'], reverse=True)
    simultaneous, count = detect_simultaneous()
    return render_template('map.html', logs=sorted_logs, simultaneous=simultaneous, recent_count=count)

# Endpoint to clear logs (for demo reset)
@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    wifi_log.clear()
    return redirect(url_for('map_view'))

if __name__ == '__main__':
    app.run(debug=True)
