import threading
import webbrowser
import time
import sys
import os
from PIL import Image, ImageDraw
import pystray

# ── Point imports to scanner.py's internals ──
from scanner import app, scan_loop, monitor_bandwidth

SERVER_URL = "http://localhost:5000"

def create_icon_image():
    # Simple green circle icon if you don't have an .ico
    img = Image.new("RGB", (64, 64), color=(13, 15, 20))
    draw = ImageDraw.Draw(img)
    draw.ellipse([16, 16, 48, 48], fill=(34, 201, 122))
    return img

def open_dashboard(icon, item):
    webbrowser.open(SERVER_URL)

def quit_app(icon, item):
    icon.stop()
    os._exit(0)

def start_flask():
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

def main():
    # Start background threads
    threading.Thread(target=scan_loop,        daemon=True).start()
    threading.Thread(target=monitor_bandwidth, daemon=True).start()
    threading.Thread(target=start_flask,       daemon=True).start()

    # Wait a moment then auto-open browser
    def auto_open():
        time.sleep(3)
        webbrowser.open(SERVER_URL)
    threading.Thread(target=auto_open, daemon=True).start()

    # System tray icon
    icon_image = create_icon_image()
    tray_icon = pystray.Icon(
        name="ThreatMonitor",
        icon=icon_image,
        title="Threat Monitor",
        menu=pystray.Menu(
            pystray.MenuItem("📡 Open Dashboard", open_dashboard, default=True),
            pystray.MenuItem("❌ Quit",            quit_app),
        )
    )
    tray_icon.run()

if __name__ == "__main__":
    main()

    
import subprocess
import sys

# Hide console windows spawned by subprocesses (netsh, nmap etc.)
if sys.platform == "win32":
    import ctypes
    ctypes.windll.kernel32.SetConsoleWindowInfo(
        ctypes.windll.kernel32.GetConsoleWindow(), True,
        ctypes.byref((ctypes.c_short * 4)(0, 0, 0, 0))
    )

# Patch subprocess to never show a window
_original_popen = subprocess.Popen
def _silent_popen(*args, **kwargs):
    kwargs.setdefault('creationflags', 0x08000000)  # CREATE_NO_WINDOW
    return _original_popen(*args, **kwargs)
subprocess.Popen = _silent_popen
