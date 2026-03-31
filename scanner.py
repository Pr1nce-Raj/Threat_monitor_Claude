import json
import os
import time
import asyncio
import nmap
import socket
import threading
import psutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp
from datetime import datetime
from bleak import BleakScanner
from mac_vendor_lookup import MacLookup
from flask import Flask, jsonify, render_template   # ← add render_template
from flask_cors import CORS
from plyer import notification 

# ─────────────────────────────────────────
#  INIT
# ─────────────────────────────────────────
vendor_lookup = MacLookup()
try:
    vendor_lookup.update_vendors()
except:
    pass

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

DB_FILE       = "known_devices.json"
LOG_FILE      = "activity_log.txt"
BT_FILE       = "bt_devices.json"
SCAN_INTERVAL = 60   

_latest_wifi = []    
_latest_bt   = []    
_scan_meta   = {"last_scan": None, "network": "detecting..."}
_state_lock  = threading.Lock()
_net_stats = {"upload_speed": "0 KB/s", "download_speed": "0 KB/s"}

# ─────────────────────────────────────────
#  LOGGING & ALERTS
# ─────────────────────────────────────────
def log_activity(message):
    with open(LOG_FILE, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

def send_alert(title, message):
    try:
        notification.notify(
            title=title,
            message=message,
            app_name='Threat Monitor',
            timeout=10
        )
    except Exception as e:
        print(f"Notification Error: {e}")

def read_logs(n=100):
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()[-n:]
    result = []
    for line in reversed(lines):
        line = line.strip()
        if not line: continue
        try:
            ts  = line[1:20]
            msg = line[22:]
        except:
            ts, msg = "", line
        severity = "ok"
        if any(x in msg for x in ["ALERT", "NEW DEVICE", "SUSPICIOUS BT"]):
            severity = "alert"
        elif any(x in msg for x in ["SUSPICIOUS", "Spoofing"]):
            severity = "warn"
        result.append({"time": ts, "msg": msg, "type": severity})
    return result


# ─────────────────────────────────────────
#  DEVICE DATABASE
# ─────────────────────────────────────────
def load_known_devices():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r") as f:
                content = f.read().strip()
                if not content:          # file is empty
                    return {}
                return json.loads(content)
        except json.JSONDecodeError:     # file is corrupted
            print(f"{YELLOW}[!] {DB_FILE} is corrupted. Resetting...{RESET}")
            os.remove(DB_FILE)
            return {}
    return {}


def save_device(mac, ip, hostname, vendor, ports, os_guess):
    known  = load_known_devices()
    is_new = False
    now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if mac not in known:
        known[mac] = {
            "ip": ip, "hostname": hostname, "vendor": vendor,
            "status": "unknown", "os": os_guess, "ports": ports,
            "history": [ip], "first_seen": now, "last_seen": now,
        }
        is_new = True
        send_alert("⚠️ New Device Detected", f"{vendor} ({mac}) at {ip}")
    else:
        entry = known[mac]
        if entry["ip"] != ip:
            log_activity(f"SUSPICIOUS: MAC Spoofing? {mac} moved to {ip}")
            send_alert("🚨 Security Alert", f"MAC Spoofing? {mac} moved to {ip}")
            entry["history"] = entry.get("history", []) + [ip]
            # ✅ Don't overwrite trusted/blocked with suspicious
            if entry["status"] not in ("trusted", "blocked"):
                entry["status"] = "suspicious"

        # ✅ Never overwrite a manually set trusted or blocked status
        protected_status = entry.get("status") in ("trusted", "blocked")
        entry.update({"ip": ip, "hostname": hostname, "vendor": vendor,
                      "ports": ports, "os": os_guess, "last_seen": now})
        if protected_status:
            entry["status"] = known[mac]["status"]  # restore it

    with open(DB_FILE, "w") as f:
        json.dump(known, f, indent=4)
    return is_new


# ─────────────────────────────────────────
#  NETWORK AUDIT
# ─────────────────────────────────────────
DANGEROUS_PORTS = {23: "Telnet", 1337: "Hacking Tool", 4444: "Metasploit", 3389: "RDP", 5900: "VNC", 8080: "Alt HTTP"}

def check_suspicious_ports(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-O -sV --top-ports 20')
        results = {"ports": [], "os": "Unknown"}
        if ip in nm.all_hosts():
            if nm[ip].get("osmatch"):
                results["os"] = nm[ip]["osmatch"][0]["name"]
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto].keys():
                    if nm[ip][proto][port]["state"] == "open":
                        results["ports"].append(port)
                        if port in DANGEROUS_PORTS:
                            log_activity(f"ALERT: {ip} port {port} open ({DANGEROUS_PORTS[port]})")
        return results
    except:
        return {"ports": [], "os": "Unknown"}


# ─────────────────────────────────────────
#  BLUETOOTH SCAN
# ─────────────────────────────────────────
async def _bt_scan():
    print(f"\n{CYAN}[*] Scanning Bluetooth...{RESET}")
    try:
        discovered = await BleakScanner.discover(timeout=5.0)
        found = []
        for d in discovered:
            name = d.name if d.name else "Unknown/Hidden"
            is_suspicious = not d.name
            
            # UPDATED: We still log the activity, but we REMOVED send_alert() here
            if is_suspicious:
                log_activity(f"SUSPICIOUS BT: Hidden device at {d.address}")
                # send_alert is now disabled for Bluetooth to prevent annoyance
            
            found.append({"address": d.address, "name": name, "signal": getattr(d, "rssi", "N/A"), "suspicious": is_suspicious})
        return found
    except Exception as e:
        print(f"{RED}[!] BT Error: {e}{RESET}")
        return []

def scan_bluetooth():
    return asyncio.run(_bt_scan())


# ─────────────────────────────────────────
#  WIFI SCAN & BANDWIDTH
# ─────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except: return "127.0.0.1"

def get_ip_range(local_ip):
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

def scan_wifi(ip_range, local_ip):
    print(f"\n{CYAN}[*] Scanning Wi-Fi: {ip_range}...{RESET}")
    result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=3, verbose=False)[0]
    
    devices_to_audit = []
    known = load_known_devices()

    for _, received in result:
        ip, mac = received.psrc, received.hwsrc
        try: hostname = socket.gethostbyaddr(ip)[0]
        except: hostname = "Unnamed Device"
        try: vendor = vendor_lookup.lookup(mac)
        except: vendor = "Unknown Manufacturer"
        devices_to_audit.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})

    def audit_task(dev):
        ip, mac = dev['ip'], dev['mac']
        if ip == local_ip:
            return {**dev, "status": "self", "ports": [], "os": "This machine", "last_seen": "Now"}
        
        prev_entry  = known.get(mac)
        prev_status = prev_entry["status"] if prev_entry else None
        # Only run expensive nmap scan on brand-new devices or confirmed suspicious ones
        if prev_status is None or prev_status == "suspicious":
            audit    = check_suspicious_ports(ip)
            ports    = audit["ports"]
            os_guess = audit["os"]
        else:
            ports    = prev_entry.get("ports", [])
            os_guess = prev_entry.get("os", "Unknown")

        is_new = save_device(mac, ip, dev['hostname'], dev['vendor'], ports, os_guess)
        status = load_known_devices().get(mac, {}).get("status", "unknown")
        return {**dev, "status": status, "ports": ports, "os": os_guess, "is_new": is_new, "last_seen": datetime.now().strftime("%H:%M:%S")}

    with ThreadPoolExecutor(max_workers=10) as executor:
        return list(executor.map(audit_task, devices_to_audit))

def monitor_bandwidth():
    global _net_stats
    old_value = psutil.net_io_counters()
    while True:
        time.sleep(1)
        new_value = psutil.net_io_counters()
        upload = new_value.bytes_sent - old_value.bytes_sent
        download = new_value.bytes_recv - old_value.bytes_recv
        with _state_lock:
            _net_stats["upload_speed"] = f"{upload / 1024:.1f} KB/s"
            _net_stats["download_speed"] = f"{download / 1024:.1f} KB/s"
            if upload > 5 * 1024 * 1024: 
                send_alert("🚀 High Upload Detected", f"Network uploading at {upload / 1024 / 1024:.1f} MB/s")
        old_value = new_value
        
# ─────────────────────────────────────────
#  MAIN LOOP & API
# ─────────────────────────────────────────
def scan_loop():
    global _latest_wifi, _latest_bt, _scan_meta
    while True:
        l_ip = get_local_ip()
        ip_r = get_ip_range(l_ip)
        w_devs, b_devs = scan_wifi(ip_r, l_ip), scan_bluetooth()
        with _state_lock:
            _latest_wifi, _latest_bt = w_devs, b_devs
            _scan_meta = {"last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "network": ip_r}
        log_activity(f"Full scan completed. Local IP: {l_ip}. Devices found: {len(w_devs)}")
        print(f"\n[*] Cycle complete. Next scan in {SCAN_INTERVAL}s...")
        time.sleep(SCAN_INTERVAL)

import sys
BASE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))

CORS(app)

@app.route("/api/status")
def api_status():
    with _state_lock:
        total    = len(_latest_wifi)
        unknown  = sum(1 for d in _latest_wifi if d.get("status") in ("unknown", "suspicious"))
        ports    = sum(len(d.get("ports", [])) for d in _latest_wifi)
        bt       = len(_latest_bt)
        return jsonify({
            **_scan_meta,
            "total":      total,
            "unknown":    unknown,
            "open_ports": ports,
            "bt_nearby":  bt,
            "bandwidth":  _net_stats,
        })

@app.route("/api/devices")
def api_devices():
    with _state_lock:
        data = list(_latest_wifi)
    known = load_known_devices()
    # Overlay persisted status onto live scan results
    for device in data:
        mac = device.get("mac")
        if mac and mac in known:
            device["status"]     = known[mac].get("status", device.get("status"))
            device["first_seen"] = known[mac].get("first_seen")
            device["history"]    = known[mac].get("history", [device.get("ip")])
    return jsonify(data)


@app.route("/api/bluetooth")
def api_bluetooth():
    with _state_lock: return jsonify(list(_latest_bt))

@app.route("/api/logs")
def api_logs(): return jsonify(read_logs(100))


def block_ip_on_windows(ip, mac):
    rule_name = f"BLOCKED_{mac.replace(':', '-')}"
    try:
        # Block all inbound and outbound traffic from that IP
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes"
        ], check=True, capture_output=True)
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}_OUT",
            "dir=out", "action=block",
            f"remoteip={ip}", "enable=yes"
        ], check=True, capture_output=True)
        log_activity(f"FIREWALL: Blocked IP {ip} (MAC: {mac})")
        return True
    except subprocess.CalledProcessError as e:
        log_activity(f"FIREWALL ERROR: Could not block {ip} — {e}")
        return False


def unblock_ip_on_windows(mac):
    rule_name = f"BLOCKED_{mac.replace(':', '-')}"
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], capture_output=True)
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_OUT"], capture_output=True)
        log_activity(f"FIREWALL: Unblocked MAC {mac}")
    except:
        pass


def mark_blocked(mac):
    known = load_known_devices()
    if mac in known:
        known[mac]["status"] = "blocked"
        with open(DB_FILE, "w") as f:
            json.dump(known, f, indent=4)
        # Actually enforce the block
        ip = known[mac].get("ip")
        if ip:
            block_ip_on_windows(ip, mac)
        return True
    return False

def mark_trusted(mac):
    known = load_known_devices()
    if mac in known:
        known[mac]["status"] = "trusted"
        with open(DB_FILE, "w") as f:
            json.dump(known, f, indent=4)
        unblock_ip_on_windows(mac)  # ← remove firewall rule if it existed
        return True
    return False

@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/trust/<mac>", methods=["POST"])
def api_trust(mac):
    mac = mac.replace("-", ":")
    ok  = mark_trusted(mac)
    if ok:
        log_activity(f"User marked {mac} as TRUSTED")
    return jsonify({"ok": ok})

@app.route("/api/scan/now", methods=["POST"])
def api_scan_now():
    def do_scan():
        global _latest_wifi, _latest_bt, _scan_meta
        l_ip = get_local_ip()
        ip_r = get_ip_range(l_ip)
        w_devs, b_devs = scan_wifi(ip_r, l_ip), scan_bluetooth()
        with _state_lock:
            _latest_wifi, _latest_bt = w_devs, b_devs
            _scan_meta = {"last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "network": ip_r}
        log_activity(f"Manual scan triggered. Devices found: {len(w_devs)}")
    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({"ok": True, "msg": "Scan started"})

from flask import Flask, jsonify, render_template, send_from_directory

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(BASE_DIR),
        'icon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

@app.route("/api/block/<mac>", methods=["POST"])
def api_block(mac):
    mac = mac.replace("-", ":")
    ok  = mark_blocked(mac)
    if ok:
        log_activity(f"User marked {mac} as BLOCKED")
    return jsonify({"ok": ok})

@app.route("/api/known")
def api_known():
    return jsonify(load_known_devices())

if __name__ == "__main__":
    threading.Thread(target=scan_loop, daemon=True).start()
    threading.Thread(target=monitor_bandwidth, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)