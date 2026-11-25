"""
SCITBOSS ANDROID FORENSIC & SECURITY ANALYZER PRO
=================================================
A Professional Windows Desktop Application for Authorized Android Digital Forensics,
Security Auditing, Malware Indicator Inspection, and Vulnerability Assessment.

PROJECT CREDIT:
DEVELOP BY SCITBOSS
GITHUB: https://github.com/scitboss

COMPATIBILITY:
- Windows 10 / Windows 11
- Python 3.8+ (No external third-party dependencies required; uses Tkinter & built-ins)
- Standalone Windows Executable compatible via PyInstaller:
    pyinstaller --onefile --windowed --name SCITBOSS_ANDROID_FORENSIC_PRO scitboss_android_forensic_pro.py

LEGAL & ETHICAL NOTICE:
This tool is intended strictly for authorized security auditing, ethical hacking,
digital forensics research, and personal device analysis with explicit owner consent.
The application respects Android security boundaries and non-intrusively queries
standard Android Debug Bridge (ADB) interfaces.
"""

import os
import sys
import subprocess
import threading
import json
import csv
import re
import datetime
import time
import queue
import shutil
import webbrowser
import platform
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Windows High-DPI Awareness and Console Settings
if sys.platform.startswith("win"):
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            import ctypes
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

# Windows Subprocess Flags (Hide CMD window popups)
SUBPROCESS_FLAGS = 0
if sys.platform.startswith("win"):
    SUBPROCESS_FLAGS = 0x08000000  # CREATE_NO_WINDOW

# ==============================================================================
# UI THEMING & CONSTANTS
# ==============================================================================
APP_NAME = "SCITBOSS ANDROID FORENSIC & SECURITY ANALYZER PRO"
APP_SHORT_NAME = "SCITBOSS FORENSIC PRO"
APP_VERSION = "2.4.0 PRO"
AUTHOR_NAME = "SCITBOSS"
GITHUB_URL = "https://github.com/scitboss"

# Hacker / Cyber Dark Theme Palette
THEME = {
    "bg_root": "#080b11",        # Deepest obsidian
    "bg_sidebar": "#0d111a",     # Sidebar dark navy
    "bg_card": "#121824",        # Card/Frame background
    "bg_card_alt": "#172030",    # Secondary card surface
    "bg_input": "#0b0f17",       # Textbox/Entry background
    "border": "#1e293b",         # Sleek dark border
    "border_highlight": "#00ff66",# Neon green border for active
    "accent_green": "#00ff66",   # Cyber Neon Green
    "accent_cyan": "#00e5ff",    # Cyber Electric Cyan
    "accent_blue": "#3b82f6",    # Forensic Slate Blue
    "accent_amber": "#f59e0b",   # Warning Amber
    "accent_red": "#ef4444",     # Critical Alarm Red
    "accent_purple": "#a855f7",  # Audit Violet
    "text_primary": "#f8fafc",   # Crisp White Text
    "text_secondary": "#94a3b8", # Muted Slate Text
    "text_dim": "#64748b",       # Dim Text
    "text_green": "#00ff66",     # Terminal Green
    "status_connected": "#00ff66",
    "status_unauthorized": "#f59e0b",
    "status_disconnected": "#ef4444",
}

FONT_FAMILY = "Segoe UI" if sys.platform.startswith("win") else "Helvetica"
FONT_MONO = "Consolas" if sys.platform.startswith("win") else "Courier"

# Permission categories for forensic analysis
SENSITIVE_PERMISSIONS = {
    "SMS": [
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_WAP_PUSH",
    ],
    "CONTACTS": [
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
    ],
    "CALL_PHONE": [
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.ANSWER_PHONE_CALLS",
    ],
    "CAMERA": [
        "android.permission.CAMERA",
    ],
    "MICROPHONE": [
        "android.permission.RECORD_AUDIO",
    ],
    "LOCATION": [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
    ],
    "STORAGE": [
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
    ],
    "ACCESSIBILITY": [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    ],
    "DEVICE_ADMIN": [
        "android.permission.BIND_DEVICE_ADMIN",
    ],
    "SPECIAL_PRIVILEGES": [
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.ACCESS_NOTIFICATION_POLICY",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.WRITE_SETTINGS",
        "android.permission.MANAGE_OVERLAY_PERMISSION",
    ]
}

# Known root management app signatures
KNOWN_ROOT_PACKAGES = [
    "com.topjohnwu.magisk",
    "io.github.a13e300.ksu",
    "me.bmax.apatch",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.noshufou.android.su",
    "com.thirdparty.superuser",
    "com.yellowes.su",
]

# Known suspicious / risk keywords in package names
SUSPICIOUS_PACKAGE_KEYWORDS = [
    "spy", "keylog", "stealer", "rat", "payload", "agent_v", "hacktool",
    "stalker", "monitor_call", "sms_forward", "silent_cam", "tracker_pro",
    "secret_record", "hidden_track", "device_tap", "ghost_sms"
]

# ==============================================================================
# LOGGING SYSTEM
# ==============================================================================
class LogManager:
    """Thread-safe logging mechanism routed to the UI live console."""
    def __init__(self):
        self.queue = queue.Queue()

    def log(self, level: str, message: str):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.queue.put((level, timestamp, message))

    def info(self, msg: str): self.log("INFO", msg)
    def success(self, msg: str): self.log("SUCCESS", msg)
    def warning(self, msg: str): self.log("WARN", msg)
    def error(self, msg: str): self.log("ERROR", msg)
    def audit(self, msg: str): self.log("AUDIT", msg)

GLOBAL_LOGGER = LogManager()

# ==============================================================================
# ADB ENGINE
# ==============================================================================
class AdbEngine:
    """
    Robust ADB controller handling device discovery, command execution,
    exception handling, and non-intrusive forensic data extraction.
    """
    def __init__(self, logger: LogManager):
        self.logger = logger
        self.adb_path = None
        self.selected_device = None
        self.devices = []
        self.ensure_universal_vendor_ids()
        self.locate_adb()

    def locate_adb(self) -> str:
        """Find ADB in PATH, bundled directory, adjacent executable path, or standard Android SDK locations."""
        candidates = []
        
        # 1. Custom path override or environment variable
        env_adb = os.environ.get("ADB_PATH")
        if env_adb and os.path.isfile(env_adb):
            candidates.append(env_adb)

        # 2. PyInstaller _MEIPASS extraction directory (when running as frozen onefile EXE)
        if hasattr(sys, '_MEIPASS'):
            candidates.append(os.path.join(sys._MEIPASS, "platform-tools", "adb.exe"))
            candidates.append(os.path.join(sys._MEIPASS, "adb.exe"))

        # 3. Directory where the running executable (.exe) is located
        exe_path = os.path.abspath(sys.executable)
        exe_dir = os.path.dirname(exe_path)
        candidates.append(os.path.join(exe_dir, "platform-tools", "adb.exe"))
        candidates.append(os.path.join(exe_dir, "adb.exe"))

        # 4. Parent directory of the executable (e.g. if EXE is inside 'dist/', checks project root)
        parent_dir = os.path.dirname(exe_dir)
        candidates.append(os.path.join(parent_dir, "platform-tools", "adb.exe"))
        candidates.append(os.path.join(parent_dir, "adb.exe"))

        # 5. Directory where this python script is located (when running uncompiled)
        if '__file__' in globals():
            script_dir = os.path.dirname(os.path.abspath(__file__))
            candidates.append(os.path.join(script_dir, "platform-tools", "adb.exe"))
            candidates.append(os.path.join(script_dir, "adb.exe"))

        # 6. Current working directory
        candidates.append(os.path.join(os.getcwd(), "platform-tools", "adb.exe"))
        candidates.append(os.path.join(os.getcwd(), "adb.exe"))

        # 7. System PATH
        path_adb = shutil.which("adb")
        if path_adb:
            candidates.append(path_adb)

        # 8. Standard Windows Android SDK paths
        if sys.platform.startswith("win"):
            local_appdata = os.environ.get("LOCALAPPDATA", "")
            prog_files = os.environ.get("PROGRAMFILES", "C:\\Program Files")
            prog_files_x86 = os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")
            user_prof = os.environ.get("USERPROFILE", "")

            sdk_paths = [
                os.path.join(local_appdata, "Android", "Sdk", "platform-tools", "adb.exe"),
                os.path.join(user_prof, "AppData", "Local", "Android", "Sdk", "platform-tools", "adb.exe"),
                os.path.join(prog_files, "Android", "platform-tools", "adb.exe"),
                os.path.join(prog_files_x86, "Android", "platform-tools", "adb.exe"),
                "C:\\platform-tools\\adb.exe",
                "C:\\Android\\platform-tools\\adb.exe",
            ]
            candidates.extend(sdk_paths)

        # Normalize and filter candidates
        seen = set()
        for path in candidates:
            if not path:
                continue
            norm_path = os.path.normpath(path)
            if norm_path in seen:
                continue
            seen.add(norm_path)
            if os.path.isfile(norm_path):
                self.adb_path = norm_path
                # Add ADB directory to os.environ["PATH"] so child processes and DLLs link seamlessly
                adb_dir = os.path.dirname(self.adb_path)
                if adb_dir not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = adb_dir + os.pathsep + os.environ.get("PATH", "")
                self.logger.success(f"⚡ [ADB ENGINE] ADB binary located: {self.adb_path}")
                # Verify ADB works
                ver_ok, ver_msg = self.check_adb_version()
                if ver_ok:
                    self.logger.success(f"⚡ [ADB ENGINE] Daemon status: {ver_msg}")
                else:
                    self.logger.warning("⚡ [ADB ENGINE] Starting ADB server daemon...")
                    self.restart_adb_server()
                return self.adb_path

        # If not found anywhere, fallback to 'adb' and warn user
        self.adb_path = "adb"
        self.logger.error("⚠️ [ADB ENGINE] ADB binary not found! Please ensure 'platform-tools' folder is placed next to SCITBOSS_ANDROID_FORENSIC_PRO.exe")
        return self.adb_path

    def run_cmd(self, args: list, timeout: int = 15) -> tuple[bool, str, str]:
        """Execute an ADB command with timeout and hidden console window."""
        if not self.adb_path:
            self.locate_adb()

        cmd = [self.adb_path] + args
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                creationflags=SUBPROCESS_FLAGS,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            stdout, stderr = process.communicate(timeout=timeout)
            return (process.returncode == 0, stdout.strip(), stderr.strip())
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except Exception:
                pass
            return (False, "", f"Operation timed out after {timeout} seconds")
        except FileNotFoundError:
            return (False, "", "ADB executable not found. Please verify ADB installation.")
        except Exception as e:
            return (False, "", f"Execution error: {str(e)}")

    def run_shell(self, shell_cmd: str, timeout: int = 15) -> tuple[bool, str, str]:
        """Run an adb shell command on the currently selected device."""
        if not self.selected_device:
            return (False, "", "No Android device selected or connected")
        args = ["-s", self.selected_device, "shell", shell_cmd]
        return self.run_cmd(args, timeout=timeout)

    def check_adb_version(self) -> tuple[bool, str]:
        """Verify ADB is responsive and return its version."""
        success, stdout, stderr = self.run_cmd(["version"], timeout=5)
        if success and "Android Debug Bridge" in stdout:
            first_line = stdout.splitlines()[0]
            return (True, first_line)
        return (False, stderr or "ADB unavailable")

    def restart_adb_server(self) -> bool:
        """Kill and restart ADB server to refresh USB drivers and connections."""
        self.logger.info("Restarting ADB server daemon...")
        self.run_cmd(["kill-server"], timeout=6)
        time.sleep(0.5)
        success, stdout, stderr = self.run_cmd(["start-server"], timeout=10)
        if success or "daemon started successfully" in stdout or "daemon started successfully" in stderr:
            self.logger.success("ADB server restarted successfully.")
            return True
        else:
            self.logger.warning(f"ADB restart notice: {stdout or stderr}")
            return False

    def ensure_universal_vendor_ids(self):
        """Register all 31+ Android OEM Vendor IDs in ~/.android/adb_usb.ini for universal device detection."""
        try:
            android_dir = os.path.expanduser("~/.android")
            os.makedirs(android_dir, exist_ok=True)
            ini_file = os.path.join(android_dir, "adb_usb.ini")
            vendor_ids = [
                "0x18d1", "0x04e8", "0x2717", "0x1782", "0x0e8d", "0x12d1",
                "0x22d9", "0x2b4c", "0x2a70", "0x22b8", "0x17ef", "0x1004",
                "0x0fce", "0x0b05", "0x19d2", "0x05c6", "0x0bb4", "0x2a45",
                "0x1bbb", "0x0409", "0x0489", "0x04da", "0x0502", "0x0955",
                "0x10a9", "0x1949", "0x2006", "0x201e", "0x2314", "0x2970", "0x413c"
            ]
            existing = set()
            if os.path.exists(ini_file):
                with open(ini_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            existing.add(line.lower())
            missing = [v for v in vendor_ids if v.lower() not in existing]
            if missing or not os.path.exists(ini_file):
                with open(ini_file, "a" if os.path.exists(ini_file) else "w", encoding="utf-8") as f:
                    if not os.path.exists(ini_file):
                        f.write("# Universal Android OEM Vendor IDs by SCITBOSS\n")
                    for vid in missing:
                        f.write(f"{vid}\n")
        except Exception:
            pass

    def connect_wireless(self, ip_port: str) -> tuple[bool, str]:
        """Connect to Android device over Wi-Fi / IP (Wireless ADB)."""
        ip_port = ip_port.strip()
        if not ip_port:
            return (False, "Please enter IP address and Port (e.g. 192.168.1.100:5555)")
        self.logger.info(f"Connecting to wireless device: {ip_port}...")
        success, stdout, stderr = self.run_cmd(["connect", ip_port], timeout=10)
        if success and ("connected to" in stdout.lower() or "already connected" in stdout.lower()):
            self.logger.success(f"Successfully connected to {ip_port}")
            self.scan_devices()
            return (True, stdout)
        return (False, stdout or stderr or "Wireless connection timed out")

    def get_driver_dir(self) -> str:
        """Find usb_driver directory in MEIPASS, adjacent to EXE, parent, or cwd."""
        candidate_dirs = []
        if hasattr(sys, '_MEIPASS'):
            candidate_dirs.append(os.path.join(sys._MEIPASS, "usb_driver"))
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidate_dirs.append(os.path.join(exe_dir, "usb_driver"))
        candidate_dirs.append(os.path.join(os.path.dirname(exe_dir), "usb_driver"))
        if '__file__' in globals():
            candidate_dirs.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "usb_driver"))
        candidate_dirs.append(os.path.join(os.getcwd(), "usb_driver"))

        for d in candidate_dirs:
            if os.path.isdir(d):
                return d
        return os.path.join(exe_dir, "usb_driver")

    def auto_install_usb_driver(self) -> tuple[bool, str]:
        """Download official Google & Universal USB Drivers and install into Windows Driver Store."""
        import urllib.request, zipfile
        target_dir = self.get_driver_dir()
        os.makedirs(target_dir, exist_ok=True)
        universal_inf = os.path.join(target_dir, "universal_android_winusb.inf")
        google_inf = os.path.join(target_dir, "android_winusb.inf")

        if not os.path.exists(google_inf) and not os.path.exists(universal_inf):
            self.logger.info("⚡ [DRIVER SETUP] Downloading official Google Android USB Driver...")
            zip_path = os.path.join(target_dir, "usb_driver_temp.zip")
            url = "https://dl.google.com/android/repository/usb_driver_r13-windows.zip"
            try:
                urllib.request.urlretrieve(url, zip_path)
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(target_dir)
                if os.path.exists(zip_path):
                    os.remove(zip_path)
                self.logger.success("⚡ [DRIVER SETUP] USB Driver files extracted successfully.")
            except Exception as e:
                return (False, f"Failed to download USB driver: {str(e)}")

        infs_to_install = [f for f in [universal_inf, google_inf] if os.path.exists(f)]
        if not infs_to_install:
            return (False, "No driver INF files found to install.")

        self.logger.info("⚡ [DRIVER SETUP] Installing Universal Android Drivers into Windows Driver Store...")
        try:
            # Install driver INF files with elevation
            for inf in infs_to_install:
                ps_script = f"Start-Process pnputil -ArgumentList '/add-driver \"{inf}\" /install' -Verb RunAs -Wait"
                subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True)

            # Trigger Windows hardware bus rescan
            ps_rescan = "Start-Process pnputil -ArgumentList '/scan-devices' -Verb RunAs -Wait"
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_rescan], capture_output=True, text=True)

            self.logger.success("⚡ [DRIVER SETUP] Universal Android drivers registered in Windows Driver Store.")
            self.ensure_universal_vendor_ids()
            self.restart_adb_server()
            return (True, "All Universal Android OEM Drivers successfully installed!")
        except Exception as e:
            return (False, f"Driver installation error: {str(e)}")

    def check_physical_usb_hardware(self) -> dict:
        """Query Windows WMI / PnP to detect if any Android phone is physically connected on USB."""
        result = {"has_usb_device": False, "devices": [], "android_match": False, "vendor_name": "Unknown"}
        known_vendors = {
            "18d1": "Google / Android Standard",
            "04e8": "Samsung",
            "2717": "Xiaomi / Redmi / Poco",
            "1782": "Unisoc / Spreadtrum / itel / Tecno",
            "0e8d": "MediaTek (MTK)",
            "12d1": "Huawei / Honor",
            "22d9": "Oppo / Realme",
            "2a70": "OnePlus",
            "22b8": "Motorola",
            "2b4c": "Vivo / iQOO",
            "1bbb": "TCL / Alcatel",
            "05c6": "Qualcomm Android"
        }
        
        raw_output = ""
        # 1. Try wmic first
        try:
            cmd = ["wmic", "path", "Win32_PnPEntity", "where", "Status='OK'", "get", "Name,DeviceID"]
            proc = subprocess.run(cmd, capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS, timeout=5)
            if proc.returncode == 0 and proc.stdout:
                raw_output = proc.stdout
        except Exception:
            pass

        # 2. Fallback to PowerShell Get-CimInstance if wmic didn't return output
        if not raw_output:
            try:
                ps_cmd = ["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_PnPEntity | Select-Object -ExpandProperty DeviceID"]
                proc = subprocess.run(ps_cmd, capture_output=True, text=True, creationflags=SUBPROCESS_FLAGS, timeout=6)
                if proc.returncode == 0 and proc.stdout:
                    raw_output = proc.stdout
            except Exception:
                pass

        for line in raw_output.splitlines():
            if "VID_" in line:
                result["has_usb_device"] = True
                match = re.search(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", line)
                if match:
                    vid = match.group(1).lower()
                    pid = match.group(2).lower()
                    if vid in known_vendors:
                        result["android_match"] = True
                        result["vendor_name"] = known_vendors[vid]
                        result["devices"].append({
                            "vendor": known_vendors[vid],
                            "vid": vid,
                            "pid": pid,
                            "raw": line.strip()
                        })
        return result

    def scan_devices(self, silent: bool = False) -> list[dict]:
        """Detect all connected Android devices and their authorization status."""
        self.devices = []
        VALID_ADB_STATES = {
            "device", "unauthorized", "offline", "recovery", "sideload",
            "bootloader", "authorizing", "connecting", "no permissions", "host"
        }
        success, stdout, stderr = self.run_cmd(["devices", "-l"], timeout=8)
        if not success:
            if not silent:
                self.logger.error(f"Failed to scan devices: {stderr}")
            return []

        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("*") or line.lower().startswith("list of devices attached"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1].lower() in VALID_ADB_STATES:
                serial = parts[0]
                status = parts[1].lower()
                details = " ".join(parts[2:])

                # Parse model, product, device if available
                model_match = re.search(r"model:([^\s]+)", details)
                product_match = re.search(r"product:([^\s]+)", details)
                device_match = re.search(r"device:([^\s]+)", details)

                dev_info = {
                    "serial": serial,
                    "status": status,
                    "model": model_match.group(1) if model_match else "Device",
                    "product": product_match.group(1) if product_match else "Unknown",
                    "device": device_match.group(1) if device_match else "Unknown",
                    "raw": line
                }
                self.devices.append(dev_info)

        if self.devices:
            # Auto-select the first authorized device if none currently selected
            if not self.selected_device or self.selected_device not in [d["serial"] for d in self.devices]:
                authorized = [d for d in self.devices if d["status"] == "device"]
                if authorized:
                    self.selected_device = authorized[0]["serial"]
                else:
                    self.selected_device = self.devices[0]["serial"]
        else:
            self.selected_device = None

        return self.devices

    # --------------------------------------------------------------------------
    # FORENSIC DATA COLLECTORS
    # --------------------------------------------------------------------------
    def get_system_properties(self) -> dict:
        """Fetch all Android system properties via getprop."""
        props = {}
        success, stdout, stderr = self.run_shell("getprop", timeout=12)
        if not success:
            return props

        # Format: [key]: [value]
        matches = re.findall(r"\[(.*?)\]:\s*\[(.*?)\]", stdout)
        for key, val in matches:
            props[key.strip()] = val.strip()
        return props

    def get_battery_info(self) -> dict:
        """Parse battery status, level, health, temp from dumpsys battery."""
        battery = {
            "level": "N/A", "status": "N/A", "health": "N/A",
            "temperature": "N/A", "voltage": "N/A", "technology": "N/A",
            "ac_powered": "N/A", "usb_powered": "N/A"
        }
        success, stdout, _ = self.run_shell("dumpsys battery", timeout=8)
        if not success or not stdout:
            return battery

        status_map = {1: "Unknown", 2: "Charging", 3: "Discharging", 4: "Not Charging", 5: "Full"}
        health_map = {1: "Unknown", 2: "Good", 3: "Overheat", 4: "Dead", 5: "Over Voltage", 6: "Unspecified Failure", 7: "Cold"}

        for line in stdout.splitlines():
            line = line.strip()
            if ":" in line:
                k, v = [x.strip() for x in line.split(":", 1)]
                if k == "level": battery["level"] = f"{v}%"
                elif k == "status": battery["status"] = status_map.get(int(v), v) if v.isdigit() else v
                elif k == "health": battery["health"] = health_map.get(int(v), v) if v.isdigit() else v
                elif k == "temperature":
                    try:
                        temp_c = float(v) / 10.0
                        battery["temperature"] = f"{temp_c:.1f}°C ({temp_c*9/5+32:.1f}°F)"
                    except Exception:
                        battery["temperature"] = v
                elif k == "voltage":
                    try:
                        battery["voltage"] = f"{float(v)/1000.0:.2f} V"
                    except Exception:
                        battery["voltage"] = v
                elif k == "technology": battery["technology"] = v
                elif k == "AC powered": battery["ac_powered"] = v
                elif k == "USB powered": battery["usb_powered"] = v

        return battery

    def get_display_info(self) -> dict:
        """Parse display resolution and density."""
        disp = {"resolution": "N/A", "density": "N/A"}
        _, size_out, _ = self.run_shell("wm size", timeout=5)
        if size_out:
            m = re.search(r"size:\s*([0-9]+x[0-9]+)", size_out)
            if m: disp["resolution"] = m.group(1)

        _, dens_out, _ = self.run_shell("wm density", timeout=5)
        if dens_out:
            m = re.search(r"density:\s*([0-9]+)", dens_out)
            if m: disp["density"] = f"{m.group(1)} dpi"

        return disp

    def get_memory_info(self) -> dict:
        """Parse /proc/meminfo for RAM telemetry."""
        mem = {"total": "N/A", "free": "N/A", "available": "N/A"}
        success, stdout, _ = self.run_shell("cat /proc/meminfo", timeout=5)
        if success and stdout:
            for line in stdout.splitlines():
                if "MemTotal:" in line:
                    val = line.split(":")[1].strip().split()[0]
                    mem["total"] = f"{int(val) // 1024} MB ({int(val) // 1048576:.1f} GB)"
                elif "MemFree:" in line:
                    val = line.split(":")[1].strip().split()[0]
                    mem["free"] = f"{int(val) // 1024} MB"
                elif "MemAvailable:" in line:
                    val = line.split(":")[1].strip().split()[0]
                    mem["available"] = f"{int(val) // 1024} MB"
        return mem

    def get_storage_info(self) -> dict:
        """Query storage usage for /data and /sdcard."""
        storage = {"data_total": "N/A", "data_used": "N/A", "data_free": "N/A", "percent": "N/A"}
        success, stdout, _ = self.run_shell("df -h /data", timeout=6)
        if success and stdout:
            lines = stdout.splitlines()
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 5:
                    # Filesystem Size Used Avail Use% Mounted
                    storage["data_total"] = parts[1]
                    storage["data_used"] = parts[2]
                    storage["data_free"] = parts[3]
                    storage["percent"] = parts[4]
        return storage

    def get_uptime(self) -> str:
        """Get human-readable system uptime."""
        success, stdout, _ = self.run_shell("cat /proc/uptime", timeout=5)
        if success and stdout:
            try:
                seconds = float(stdout.split()[0])
                days = int(seconds // 86400)
                hours = int((seconds % 86400) // 3600)
                minutes = int((seconds % 3600) // 60)
                return f"{days}d {hours}h {minutes}m ({int(seconds)}s)"
            except Exception:
                pass
        return "Unknown"

    def get_kernel_version(self) -> str:
        """Retrieve kernel release and build details."""
        success, stdout, _ = self.run_shell("cat /proc/version", timeout=5)
        if success and stdout:
            return stdout.strip()
        _, uname_out, _ = self.run_shell("uname -a", timeout=5)
        return uname_out.strip() if uname_out else "N/A"

    def check_root_indicators(self, props: dict) -> dict:
        """
        Non-intrusively check for root binaries, test-keys,
        and superuser package indicators.
        """
        root_data = {
            "is_rooted": False,
            "indicators": [],
            "su_binary_found": False,
            "test_keys": False,
            "root_manager_found": False
        }

        # 1. Check test-keys
        build_tags = props.get("ro.build.tags", "")
        if "test-keys" in build_tags:
            root_data["test_keys"] = True
            root_data["indicators"].append("Build tags indicate test-keys (Non-release build)")

        # 2. Check SU binary presence in standard paths
        su_paths = [
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/sd/xbin/su", "/data/local/xbin/su",
            "/data/local/bin/su", "/system/app/Superuser.apk"
        ]
        test_cmd = " ".join([f"[ -f {p} ] && echo FOUND {p};" for p in su_paths])
        success, stdout, _ = self.run_shell(test_cmd, timeout=8)
        if success and "FOUND" in stdout:
            root_data["su_binary_found"] = True
            found_paths = [line.replace("FOUND", "").strip() for line in stdout.splitlines() if "FOUND" in line]
            root_data["indicators"].append(f"SU binary detected: {', '.join(found_paths)}")

        # 3. Check for root packages
        success, stdout, _ = self.run_shell("pm list packages", timeout=8)
        if success and stdout:
            installed = stdout.lower()
            for pkg in KNOWN_ROOT_PACKAGES:
                if f"package:{pkg}" in installed:
                    root_data["root_manager_found"] = True
                    root_data["indicators"].append(f"Root management package present: {pkg}")

        if root_data["su_binary_found"] or root_data["root_manager_found"]:
            root_data["is_rooted"] = True

        return root_data

    def get_selinux_mode(self) -> str:
        """Check SELinux enforcement status."""
        success, stdout, _ = self.run_shell("getenforce", timeout=5)
        if success and stdout:
            return stdout.strip()
        return "Unknown"

    def get_security_settings(self) -> dict:
        """Read accessible security settings via settings command."""
        sec = {
            "adb_enabled": "N/A",
            "dev_settings": "N/A",
            "install_non_market": "N/A",
            "verify_apps": "N/A"
        }
        _, out1, _ = self.run_shell("settings get global adb_enabled", timeout=5)
        if out1: sec["adb_enabled"] = "Enabled (1)" if out1.strip() == "1" else "Disabled (0)"

        _, out2, _ = self.run_shell("settings get global development_settings_enabled", timeout=5)
        if out2: sec["dev_settings"] = "Enabled (1)" if out2.strip() == "1" else "Disabled (0)"

        _, out3, _ = self.run_shell("settings get secure install_non_market_apps", timeout=5)
        if out3: sec["install_non_market"] = "Allowed (1)" if out3.strip() == "1" else "Disallowed (0)"

        _, out4, _ = self.run_shell("settings get global package_verifier_enable", timeout=5)
        if out4: sec["verify_apps"] = "Enabled (1)" if out4.strip() == "1" else "Disabled (0)"

        return sec

    def list_installed_packages(self) -> list[dict]:
        """List all packages, APK locations, and determine if system or third-party."""
        packages = []
        success, stdout, _ = self.run_shell("pm list packages -f -u", timeout=20)
        if not success or not stdout:
            # Fallback to simple pm list packages
            success, stdout, _ = self.run_shell("pm list packages", timeout=15)
            if not success or not stdout:
                return []
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("package:"):
                    pkg = line.replace("package:", "").strip()
                    packages.append({
                        "package_name": pkg,
                        "apk_path": "Unknown",
                        "is_system": False,
                        "type": "Unknown"
                    })
            return packages

        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                content = line.replace("package:", "")
                if "=" in content:
                    apk_path, pkg_name = content.rsplit("=", 1)
                    apk_path = apk_path.strip()
                    pkg_name = pkg_name.strip()
                    is_system = any(apk_path.startswith(prefix) for prefix in [
                        "/system/", "/vendor/", "/product/", "/apex/", "/system_ext/", "/odm/"
                    ])
                    packages.append({
                        "package_name": pkg_name,
                        "apk_path": apk_path,
                        "is_system": is_system,
                        "type": "System" if is_system else "User / 3rd Party"
                    })
        return packages

    def get_package_deep_info(self, package_name: str) -> dict:
        """Inspect deep package details: permissions, versions, install time."""
        info = {
            "package_name": package_name,
            "version_name": "N/A",
            "version_code": "N/A",
            "first_install": "N/A",
            "last_update": "N/A",
            "installer": "N/A",
            "requested_permissions": [],
            "granted_permissions": [],
            "sensitive_permissions": {},
            "has_accessibility": False,
            "has_device_admin": False,
            "has_overlay": False,
            "has_install_packages": False
        }

        success, stdout, _ = self.run_shell(f"dumpsys package {package_name}", timeout=10)
        if not success or not stdout:
            return info

        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("versionName="):
                info["version_name"] = line.split("=", 1)[1]
            elif line.startswith("versionCode="):
                info["version_code"] = line.split("=", 1)[1].split()[0]
            elif line.startswith("firstInstallTime="):
                info["first_install"] = line.split("=", 1)[1]
            elif line.startswith("lastUpdateTime="):
                info["last_update"] = line.split("=", 1)[1]
            elif line.startswith("installerPackageName="):
                info["installer"] = line.split("=", 1)[1]
            elif "permission." in line:
                # Detect permission strings
                perm_match = re.search(r"(android\.permission\.[A-Z0-9_]+)", line)
                if perm_match:
                    perm = perm_match.group(1)
                    if perm not in info["requested_permissions"]:
                        info["requested_permissions"].append(perm)
                    if "granted=true" in line and perm not in info["granted_permissions"]:
                        info["granted_permissions"].append(perm)

        # Categorize sensitive permissions
        for cat, perms in SENSITIVE_PERMISSIONS.items():
            matches = [p for p in info["requested_permissions"] if p in perms]
            if matches:
                info["sensitive_permissions"][cat] = matches

        info["has_accessibility"] = "android.permission.BIND_ACCESSIBILITY_SERVICE" in info["requested_permissions"]
        info["has_device_admin"] = "android.permission.BIND_DEVICE_ADMIN" in info["requested_permissions"]
        info["has_overlay"] = "android.permission.SYSTEM_ALERT_WINDOW" in info["requested_permissions"]
        info["has_install_packages"] = "android.permission.REQUEST_INSTALL_PACKAGES" in info["requested_permissions"]

        return info

    def scan_storage_directory(self, target_dir: str = "/sdcard/Download") -> list[dict]:
        """Enumerate accessible files, sizes, and timestamps in public storage."""
        files = []
        cmd = f"ls -la {target_dir}"
        success, stdout, _ = self.run_shell(cmd, timeout=12)
        if not success or "Permission denied" in stdout:
            return [{"name": "Feature unavailable due to Android security restrictions or insufficient permissions.", "size": "-", "date": "-", "path": target_dir, "is_suspicious": False}]

        lines = stdout.splitlines()
        for line in lines:
            line = line.strip()
            parts = line.split()
            # Standard ls -la: permissions links owner group size date time name
            if len(parts) >= 8 and not line.startswith("total"):
                name = " ".join(parts[7:])
                if name in [".", ".."]:
                    continue
                size = parts[4]
                date = f"{parts[5]} {parts[6]}"
                full_path = f"{target_dir.rstrip('/')}/{name}"
                is_dir = line.startswith("d")

                is_suspicious = False
                ext = os.path.splitext(name)[1].lower()
                if ext in [".apk", ".dex", ".jar", ".so", ".sh", ".py", ".elf", ".bat", ".exe"]:
                    is_suspicious = True
                if name.startswith(".") and not is_dir:
                    is_suspicious = True

                files.append({
                    "name": name,
                    "is_dir": is_dir,
                    "size": size,
                    "date": date,
                    "path": full_path,
                    "extension": ext,
                    "is_suspicious": is_suspicious
                })
        return files

# ==============================================================================
# SECURITY AUDIT ENGINE
# ==============================================================================
class SecurityAuditEngine:
    """
    Transparent rule-based security scoring engine assessing device posture,
    configuration weaknesses, patch lag, and dangerous permission privileges.
    """
    @staticmethod
    def audit(device_data: dict, app_inventory: list) -> dict:
        score = 100
        findings = []

        props = device_data.get("properties", {})
        battery = device_data.get("battery", {})
        root_info = device_data.get("root_info", {})
        sec_settings = device_data.get("security_settings", {})
        selinux = device_data.get("selinux", "Unknown")

        # 1. Root / Superuser Audit [CRITICAL]
        if root_info.get("is_rooted", False):
            score -= 25
            findings.append({
                "category": "Root Status",
                "severity": "Critical",
                "title": "Device is Rooted or SU Binary Detected",
                "evidence": "; ".join(root_info.get("indicators", ["Root detected"])),
                "remediation": "Unroot device or flash stock firmware to re-enable Android sandboxing and keystore security."
            })
        else:
            findings.append({
                "category": "Root Status",
                "severity": "Informational",
                "title": "No Direct Root Elevation Found",
                "evidence": "Standard SU binary paths clean; root managers not detected.",
                "remediation": "Maintain unrooted state."
            })

        # 2. SELinux Mode Audit [CRITICAL]
        if selinux.lower() == "permissive":
            score -= 20
            findings.append({
                "category": "SELinux",
                "severity": "Critical",
                "title": "SELinux Enforcement is PERMISSIVE",
                "evidence": f"getenforce returned '{selinux}'",
                "remediation": "Switch SELinux to Enforcing mode to prevent unauthorized privilege transitions."
            })
        elif selinux.lower() == "enforcing":
            findings.append({
                "category": "SELinux",
                "severity": "Informational",
                "title": "SELinux Enforcing Active",
                "evidence": "Mandatory Access Control is actively enforced by kernel.",
                "remediation": "None required."
            })
        else:
            score -= 5
            findings.append({
                "category": "SELinux",
                "severity": "Medium",
                "title": "SELinux State Indeterminate",
                "evidence": f"SELinux status: {selinux}",
                "remediation": "Verify SELinux is in Enforcing mode."
            })

        # 3. Security Patch Level Audit [HIGH/MEDIUM]
        patch_date_str = props.get("ro.build.version.security_patch", "")
        if patch_date_str:
            try:
                patch_date = datetime.datetime.strptime(patch_date_str, "%Y-%m-%d")
                now = datetime.datetime.now()
                days_old = (now - patch_date).days

                if days_old > 365:
                    score -= 15
                    findings.append({
                        "category": "Patch Management",
                        "severity": "High",
                        "title": "Security Patch Level Severely Outdated (>1 Year)",
                        "evidence": f"Security Patch: {patch_date_str} ({days_old} days ago)",
                        "remediation": "Update device firmware immediately to patch known zero-day and n-day vulnerabilities."
                    })
                elif days_old > 180:
                    score -= 10
                    findings.append({
                        "category": "Patch Management",
                        "severity": "Medium",
                        "title": "Security Patch Level Outdated (>6 Months)",
                        "evidence": f"Security Patch: {patch_date_str} ({days_old} days ago)",
                        "remediation": "Check for official OEM software updates."
                    })
                else:
                    findings.append({
                        "category": "Patch Management",
                        "severity": "Informational",
                        "title": "Security Patch is Relatively Current",
                        "evidence": f"Patch date: {patch_date_str}",
                        "remediation": "Continue regular security update cadence."
                    })
            except Exception:
                pass
        else:
            score -= 5
            findings.append({
                "category": "Patch Management",
                "severity": "Medium",
                "title": "Security Patch Property Missing",
                "evidence": "ro.build.version.security_patch not exposed",
                "remediation": "Check device settings manually for patch level."
            })

        # 4. Bootloader Lock Status [HIGH]
        flash_locked = props.get("ro.boot.flash.locked", "")
        verified_boot = props.get("ro.boot.verifiedbootstate", "")
        if flash_locked == "0" or verified_boot.lower() in ["orange", "red"]:
            score -= 15
            findings.append({
                "category": "Boot Integrity",
                "severity": "High",
                "title": "Bootloader is Unlocked or Verification Orange",
                "evidence": f"flash.locked={flash_locked}, verifiedbootstate={verified_boot}",
                "remediation": "Lock the bootloader to enforce cryptographic verification of kernel and boot images."
            })
        elif flash_locked == "1" or verified_boot.lower() == "green":
            findings.append({
                "category": "Boot Integrity",
                "severity": "Informational",
                "title": "Verified Boot / Bootloader Locked",
                "evidence": f"Boot verification state: {verified_boot or 'Locked'}",
                "remediation": "Maintain bootloader lock."
            })

        # 5. Device Encryption Status [HIGH]
        crypto_state = props.get("ro.crypto.state", "").lower()
        if crypto_state == "unencrypted":
            score -= 15
            findings.append({
                "category": "Data Encryption",
                "severity": "High",
                "title": "Device Storage is Unencrypted",
                "evidence": f"ro.crypto.state={crypto_state}",
                "remediation": "Enable Full Disk or File-Based Encryption in Android Security Settings."
            })
        elif crypto_state == "encrypted":
            findings.append({
                "category": "Data Encryption",
                "severity": "Informational",
                "title": "Storage Encryption Active",
                "evidence": f"Encryption status: {crypto_state}",
                "remediation": "None required."
            })

        # 6. USB Debugging & Developer Options [LOW/MEDIUM]
        findings.append({
            "category": "Attack Surface",
            "severity": "Medium",
            "title": "USB Debugging is Currently Enabled",
            "evidence": "Device is communicating over active ADB channel",
            "remediation": "Disable USB Debugging in Developer Options when not conducting authorized forensic analysis."
        })

        if sec_settings.get("install_non_market", "").startswith("Allowed"):
            score -= 10
            findings.append({
                "category": "Application Security",
                "severity": "Medium",
                "title": "Install from Unknown Sources is Allowed",
                "evidence": "Settings flag install_non_market_apps enabled",
                "remediation": "Disable installation from unknown sources to prevent drive-by sideloading attacks."
            })

        # 7. Dangerous App Combinations
        excessive_apps = [a for a in app_inventory if len(a.get("sensitive_permissions", {})) >= 5]
        if excessive_apps:
            deduct = min(15, len(excessive_apps) * 3)
            score -= deduct
            findings.append({
                "category": "Permission Audit",
                "severity": "Medium",
                "title": f"Detected {len(excessive_apps)} Apps with 5+ Sensitive Permissions",
                "evidence": ", ".join([a["package_name"] for a in excessive_apps[:4]]) + ("..." if len(excessive_apps) > 4 else ""),
                "remediation": "Review and revoke unnecessary runtime permissions in Android App Settings."
            })

        # Clamp score
        score = max(0, min(100, score))

        # Assign Grade
        if score >= 90: grade = "A (Very Good)"
        elif score >= 80: grade = "B (Good)"
        elif score >= 70: grade = "C (Fair)"
        elif score >= 55: grade = "D (Poor / At Risk)"
        else: grade = "F (Critical Vulnerabilities)"

        return {
            "score": score,
            "grade": grade,
            "findings": findings
        }

# ==============================================================================
# MALWARE & VIRUS INDICATOR SCANNER
# ==============================================================================
class MalwareScannerEngine:
    """
    Rule-based heuristic detection module identifying suspicious apps,
    banking trojan patterns, covert stalkerware behaviors, and malicious naming.
    """
    @staticmethod
    def inspect_package(pkg_data: dict) -> dict:
        """Evaluate a single package against forensic threat rules."""
        pkg_name = pkg_data.get("package_name", "").lower()
        is_system = pkg_data.get("is_system", False)
        sens_perms = pkg_data.get("sensitive_permissions", {})
        req_perms = pkg_data.get("requested_permissions", [])
        installer = pkg_data.get("installer", "Unknown")

        has_overlay = pkg_data.get("has_overlay", False)
        has_accessibility = pkg_data.get("has_accessibility", False)
        has_dev_admin = pkg_data.get("has_device_admin", False)
        has_install = pkg_data.get("has_install_packages", False)

        has_sms = "SMS" in sens_perms
        has_location = "LOCATION" in sens_perms
        has_mic = "MICROPHONE" in sens_perms
        has_cam = "CAMERA" in sens_perms
        has_calls = "CALL_PHONE" in sens_perms
        has_boot = "android.permission.RECEIVE_BOOT_COMPLETED" in req_perms

        indicators = []
        max_severity = "Clean"
        confidence = 0

        # Don't aggressively flag official system apps unless root compromised
        if is_system:
            return {"is_suspicious": False, "severity": "Clean", "confidence": 0, "indicators": []}

        # RULE 1: Banking Trojan / Overlay Harvester
        if has_accessibility and has_overlay:
            indicators.append({
                "rule": "M1_BANKING_TROJAN_PATTERN",
                "severity": "Critical",
                "reason": "App requests BOTH Accessibility Service and System Overlay privileges. Known technique used by mobile banking trojans to log keystrokes and display fake login prompts over legitimate banking apps.",
                "confidence": 85
            })
            max_severity = "Critical"
            confidence = max(confidence, 85)

        # RULE 2: SMS Stealer & Dropper Pattern
        if has_sms and has_install and has_boot:
            indicators.append({
                "rule": "M2_SMS_STEALER_DROPPER",
                "severity": "High",
                "reason": "Non-system app holding SMS interception rights, boot auto-start, and APK drop/install privileges. Common indicator of 2FA-stealing malware or payload droppers.",
                "confidence": 80
            })
            if max_severity != "Critical": max_severity = "High"
            confidence = max(confidence, 80)

        # RULE 3: Stalkerware / Covert Surveillance Indicator
        surveillance_count = sum([has_location, has_mic, has_cam, has_calls])
        if surveillance_count >= 3 and has_boot:
            indicators.append({
                "rule": "M3_COVERT_SURVEILLANCE_PATTERN",
                "severity": "High",
                "reason": "Application aggregates multiple covert surveillance permissions (Microphone, Camera, Location, Calls) with background persistence. Indicator of commercial stalkerware or spyware.",
                "confidence": 75
            })
            if max_severity != "Critical": max_severity = "High"
            confidence = max(confidence, 75)

        # RULE 4: Masquerading / Fake System Package
        fake_prefixes = ["com.android.", "com.google.android.system", "com.qualcomm.", "android.system."]
        for pfx in fake_prefixes:
            if pkg_name.startswith(pfx) and not is_system:
                indicators.append({
                    "rule": "M4_SPOOFED_SYSTEM_NAMESPACE",
                    "severity": "Critical",
                    "reason": f"Third-party user application masquerading under system namespace '{pfx}'. Often utilized to evade user visual scrutiny.",
                    "confidence": 90
                })
                max_severity = "Critical"
                confidence = max(confidence, 90)
                break

        # RULE 5: Suspicious Device Administrator
        if has_dev_admin and (has_overlay or has_install):
            indicators.append({
                "rule": "M5_AGGRESSIVE_DEVICE_ADMIN",
                "severity": "Medium",
                "reason": "Third-party application holds Device Administrator rights combined with overlays or package installation. Can prevent uninstallation and lock out device users.",
                "confidence": 70
            })
            if max_severity not in ["Critical", "High"]: max_severity = "Medium"
            confidence = max(confidence, 70)

        # RULE 6: Known Suspicious Package Keywords
        for kw in SUSPICIOUS_PACKAGE_KEYWORDS:
            if kw in pkg_name:
                indicators.append({
                    "rule": "M6_SUSPICIOUS_KEYWORD_MATCH",
                    "severity": "High",
                    "reason": f"Package name contains suspicious threat/monitoring keyword: '{kw}'",
                    "confidence": 75
                })
                if max_severity != "Critical": max_severity = "High"
                confidence = max(confidence, 75)
                break

        # RULE 7: Excessive Permissions on Sideloaded App
        if len(sens_perms) >= 5 and (installer in ["null", "Unknown", None]):
            indicators.append({
                "rule": "M7_SIDELOADED_EXCESSIVE_PERMS",
                "severity": "Medium",
                "reason": "Sideloaded application (not from official Google Play Store) requesting 5+ sensitive permission clusters.",
                "confidence": 65
            })
            if max_severity not in ["Critical", "High"]: max_severity = "Medium"
            confidence = max(confidence, 65)

        is_suspicious = len(indicators) > 0
        return {
            "package_name": pkg_name,
            "is_suspicious": is_suspicious,
            "severity": max_severity if is_suspicious else "Clean",
            "confidence": confidence,
            "indicators": indicators
        }

# ==============================================================================
# REPORT GENERATION ENGINE
# ==============================================================================
class ReportGenerator:
    """Generates comprehensive forensic dossiers in TXT, JSON, CSV, and interactive HTML formats."""
    @staticmethod
    def get_default_report_path() -> str:
        """Return a safe writable path for the HTML report next to the EXE or in a user folder."""
        candidates = []
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidates.append(os.path.join(exe_dir, "SCITBOSS_Forensic_Report.html"))
        if '__file__' in globals():
            candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "SCITBOSS_Forensic_Report.html"))
        candidates.append(os.path.join(os.getcwd(), "SCITBOSS_Forensic_Report.html"))
        candidates.append(os.path.join(os.path.expanduser("~"), "Desktop", "SCITBOSS_Forensic_Report.html"))
        candidates.append(os.path.join(os.path.expanduser("~"), "SCITBOSS_Forensic_Report.html"))

        for p in candidates:
            try:
                d = os.path.dirname(p)
                if os.path.isdir(d) and os.access(d, os.W_OK):
                    return p
            except Exception:
                continue
        return os.path.join(os.getcwd(), "SCITBOSS_Forensic_Report.html")

    @staticmethod
    def generate_txt(device_info: dict, audit_data: dict, malware_data: dict, app_inventory: list, storage_files: list) -> str:
        lines = []
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        lines.append("=" * 80)
        lines.append("       SCITBOSS ANDROID FORENSIC & SECURITY ANALYZER PRO")
        lines.append("                 DIGITAL FORENSIC & SECURITY DOSSIER")
        lines.append("=" * 80)
        lines.append(f"Investigation Timestamp : {now_str}")
        lines.append(f"Tool Version            : {APP_VERSION}")
        lines.append(f"Developer               : {AUTHOR_NAME}")
        lines.append(f"GitHub Repository       : {GITHUB_URL}")
        lines.append("=" * 80)
        lines.append("")

        lines.append("--- [1] DEVICE HARDWARE & OPERATING SYSTEM ---")
        props = device_info.get("properties", {})
        battery = device_info.get("battery", {})
        display = device_info.get("display", {})
        memory = device_info.get("memory", {})
        storage = device_info.get("storage", {})

        lines.append(f"Manufacturer         : {props.get('ro.product.manufacturer', 'N/A')}")
        lines.append(f"Model                : {props.get('ro.product.model', 'N/A')}")
        lines.append(f"Device Codename      : {props.get('ro.product.device', 'N/A')}")
        lines.append(f"Android OS Version   : {props.get('ro.build.version.release', 'N/A')} (API {props.get('ro.build.version.sdk', 'N/A')})")
        lines.append(f"Security Patch Level : {props.get('ro.build.version.security_patch', 'N/A')}")
        lines.append(f"Build ID             : {props.get('ro.build.display.id', 'N/A')}")
        lines.append(f"Kernel Version       : {device_info.get('kernel', 'N/A')}")
        lines.append(f"CPU Architecture     : {props.get('ro.product.cpu.abi', 'N/A')}")
        lines.append(f"Screen Resolution    : {display.get('resolution', 'N/A')} ({display.get('density', 'N/A')})")
        lines.append(f"RAM Information      : Total: {memory.get('total', 'N/A')}, Free: {memory.get('free', 'N/A')}")
        lines.append(f"Internal Storage     : Total: {storage.get('data_total', 'N/A')}, Free: {storage.get('data_free', 'N/A')} ({storage.get('percent', 'N/A')} used)")
        lines.append(f"Battery Telemetry    : Level {battery.get('level', 'N/A')}, Status: {battery.get('status', 'N/A')}, Health: {battery.get('health', 'N/A')}, Temp: {battery.get('temperature', 'N/A')}")
        lines.append(f"SELinux Enforcement  : {device_info.get('selinux', 'N/A')}")
        lines.append(f"System Uptime        : {device_info.get('uptime', 'N/A')}")
        lines.append("")

        lines.append("--- [2] SECURITY AUDIT & POSTURE ASSESSMENT ---")
        lines.append(f"Overall Security Score : {audit_data.get('score', 0)} / 100 (Grade: {audit_data.get('grade', 'N/A')})")
        lines.append("Detailed Findings:")
        for idx, f in enumerate(audit_data.get("findings", []), 1):
            lines.append(f"  [{idx}] [{f.get('severity', 'Info').upper()}] {f.get('title')}")
            lines.append(f"      Evidence    : {f.get('evidence')}")
            lines.append(f"      Remediation : {f.get('remediation')}")
        lines.append("")

        lines.append("--- [3] MALWARE INDICATOR SCAN RESULTS ---")
        suspicious_list = [r for r in malware_data.get("results", []) if r.get("is_suspicious")]
        lines.append(f"Total Applications Scanned : {len(malware_data.get('results', []))}")
        lines.append(f"Suspicious Indicators Found: {len(suspicious_list)}")
        lines.append(f"High / Critical Indicators : {len([s for s in suspicious_list if s.get('severity') in ['Critical', 'High']])}")
        lines.append("")

        if suspicious_list:
            lines.append("Flagged Suspicious Applications:")
            for s in suspicious_list:
                lines.append(f"  * Package   : {s.get('package_name')}")
                lines.append(f"    Risk Level: {s.get('severity')} (Confidence: {s.get('confidence')}%)")
                for ind in s.get("indicators", []):
                    lines.append(f"    Rule      : {ind.get('rule')}")
                    lines.append(f"    Reason    : {ind.get('reason')}")
                lines.append("")
        else:
            lines.append("No active rule-based malware indicators triggered.")
        lines.append("")

        lines.append("--- [4] ACCESSIBLE STORAGE & FILE ARTIFACTS ---")
        lines.append(f"Files Enumerated in Public Storage: {len(storage_files)}")
        suspicious_files = [f for f in storage_files if f.get("is_suspicious")]
        lines.append(f"Suspicious Executable/Hidden Artifacts: {len(suspicious_files)}")
        for sf in suspicious_files:
            lines.append(f"  ! {sf.get('path')} (Size: {sf.get('size')}, Date: {sf.get('date')})")
        lines.append("")

        lines.append("--- [5] APPLICATION INVENTORY (SAMPLE) ---")
        lines.append(f"Total Installed Packages: {len(app_inventory)}")
        for app in app_inventory[:25]:
            lines.append(f"  - {app.get('package_name')} [{app.get('type')}] (Ver: {app.get('version_name', 'N/A')})")
        if len(app_inventory) > 25:
            lines.append(f"  ... and {len(app_inventory) - 25} more packages (see attached JSON/CSV).")
        lines.append("")

        lines.append("=" * 80)
        lines.append("LEGAL & FORENSIC DISCLAIMER:")
        lines.append("This digital forensic report was generated by SCITBOSS ANDROID FORENSIC & SECURITY")
        lines.append("ANALYZER PRO. All data collected originates solely from accessible Android interfaces")
        lines.append("via authorized ADB protocol. No device security controls were bypassed, screen locks")
        lines.append("circumvented, or encrypted partitions broken. This report constitutes a technical audit")
        lines.append("and forensic assessment based on accessible indicators at the time of examination.")
        lines.append("=" * 80)
        lines.append("PROJECT CREDIT: DEVELOP BY SCITBOSS | GITHUB: https://github.com/scitboss")
        lines.append("=" * 80)

        return "\n".join(lines)

    @staticmethod
    def generate_html(device_info: dict, audit_data: dict, malware_data: dict, app_inventory: list, storage_files: list) -> str:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        props = device_info.get("properties", {})
        battery = device_info.get("battery", {})
        display = device_info.get("display", {})
        memory = device_info.get("memory", {})
        storage = device_info.get("storage", {})
        root_info = device_info.get("root_info", {})
        selinux = device_info.get("selinux", "Unknown")

        model = props.get("ro.product.model", "Android Device")
        manufacturer = props.get("ro.product.manufacturer", "OEM")
        android_ver = props.get("ro.build.version.release", "N/A")
        sdk_ver = props.get("ro.build.version.sdk", "N/A")
        patch_date = props.get("ro.build.version.security_patch", "N/A")
        fingerprint = props.get("ro.build.fingerprint", "N/A")
        kernel = device_info.get("kernel", "N/A")
        uptime = device_info.get("uptime", "N/A")

        score = audit_data.get("score", 0)
        grade = audit_data.get("grade", "N/A")
        score_color = "#00ff66" if score >= 80 else ("#f59e0b" if score >= 60 else "#ef4444")

        suspicious_list = [r for r in malware_data.get("results", []) if r.get("is_suspicious")]
        crit_high = [s for s in suspicious_list if s.get("severity") in ["Critical", "High"]]

        findings_html = []
        for idx, f in enumerate(audit_data.get("findings", []), 1):
            sev = f.get("severity", "Info").upper()
            sev_class = "badge-crit" if sev == "CRITICAL" else ("badge-high" if sev == "HIGH" else ("badge-med" if sev == "MEDIUM" else "badge-low"))
            findings_html.append(f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge {sev_class}">[{sev}]</span>
                    <span class="finding-title">{f.get('title')}</span>
                    <span class="finding-domain">Domain: {f.get('category')}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Technical Evidence:</strong> <code>{f.get('evidence')}</code></p>
                    <p><strong>Remediation Countermeasure:</strong> {f.get('remediation')}</p>
                </div>
            </div>
            """)

        threats_html = []
        if suspicious_list:
            for s in suspicious_list:
                sev = s.get("severity", "Medium").upper()
                sev_class = "badge-crit" if sev == "CRITICAL" else "badge-high"
                reasons = "<br>".join([f"• <strong>{ind.get('rule')}:</strong> {ind.get('reason')}" for ind in s.get("indicators", [])])
                threats_html.append(f"""
                <tr class="threat-row">
                    <td><code>{s.get('package_name')}</code></td>
                    <td><span class="badge {sev_class}">{sev}</span></td>
                    <td><strong>{s.get('confidence')}%</strong></td>
                    <td>{reasons}</td>
                    <td><code>adb uninstall {s.get('package_name')}</code></td>
                </tr>
                """)
        else:
            threats_html.append("<tr><td colspan='5' style='text-align:center;color:#00ff66;padding:18px;'>✓ No active rule-based malware or spyware indicators triggered.</td></tr>")

        apps_rows = []
        for app in app_inventory:
            is_sys = app.get("is_system", False)
            type_class = "badge-sys" if is_sys else "badge-user"
            type_text = "System" if is_sys else "User"
            sens_pills = " ".join([f"<span class='pill pill-sens'>{cat}</span>" for cat in app.get("sensitive_permissions", {}).keys()]) or "<span class='pill'>None</span>"
            apps_rows.append(f"""
            <tr>
                <td><code>{app.get('package_name')}</code></td>
                <td><span class="badge {type_class}">{type_text}</span></td>
                <td>{app.get('version_name', 'N/A')}</td>
                <td>{app.get('installer', 'N/A')}</td>
                <td>{sens_pills}</td>
            </tr>
            """)

        storage_rows = []
        for sf in storage_files:
            is_susp = sf.get("is_suspicious", False)
            flag_pill = "<span class='badge badge-crit'>SUSPICIOUS</span>" if is_susp else "<span class='badge badge-low'>Normal</span>"
            storage_rows.append(f"""
            <tr>
                <td><code>{sf.get('path')}</code></td>
                <td>{sf.get('size')}</td>
                <td>{sf.get('date')}</td>
                <td>{flag_pill}</td>
            </tr>
            """)

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SCITBOSS Forensic Dossier - {model}</title>
<style>
    :root {{
        --bg-main: #080b11;
        --bg-card: #111726;
        --bg-card-alt: #161f33;
        --border: #1e293b;
        --accent-green: #00ff66;
        --accent-cyan: #00e5ff;
        --accent-blue: #3b82f6;
        --accent-amber: #f59e0b;
        --accent-red: #ef4444;
        --text-primary: #f8fafc;
        --text-secondary: #94a3b8;
        --text-dim: #64748b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        background-color: var(--bg-main);
        color: var(--text-primary);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        line-height: 1.6;
        padding: 30px;
    }}
    .container {{ max-width: 1300px; margin: 0 auto; }}
    .header-banner {{
        background: linear-gradient(135deg, #0d1322 0%, #17243c 100%);
        border: 1px solid var(--border);
        border-left: 5px solid var(--accent-green);
        border-radius: 8px;
        padding: 24px 30px;
        margin-bottom: 25px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 15px;
    }}
    .brand-title {{ font-size: 24px; font-weight: 800; color: var(--accent-green); letter-spacing: 0.5px; }}
    .brand-sub {{ font-size: 13px; color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 1.5px; font-weight: 600; margin-top: 4px; }}
    .meta-pills {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }}
    .meta-pill {{ background: #0b0f19; border: 1px solid var(--border); padding: 4px 10px; border-radius: 4px; font-size: 11px; color: var(--text-secondary); }}
    .btn-print {{
        background: var(--accent-green);
        color: #000;
        font-weight: 700;
        padding: 10px 18px;
        border: none;
        border-radius: 6px;
        cursor: pointer;
        text-decoration: none;
        font-size: 13px;
        transition: 0.2s;
    }}
    .btn-print:hover {{ background: #05df72; }}
    .grid-summary {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 15px;
        margin-bottom: 25px;
    }}
    .stat-card {{
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 18px;
    }}
    .stat-label {{ font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700; letter-spacing: 0.5px; }}
    .stat-val {{ font-size: 26px; font-weight: 800; margin-top: 6px; }}
    .section-card {{
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 22px;
        margin-bottom: 25px;
    }}
    .section-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid var(--border);
        padding-bottom: 12px;
        margin-bottom: 18px;
    }}
    .section-title {{ font-size: 16px; font-weight: 700; color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 1px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }}
    th {{ background: var(--bg-card-alt); color: var(--text-secondary); font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
    tr:hover {{ background: rgba(255,255,255,0.02); }}
    code {{ font-family: "Consolas", "Courier New", monospace; color: var(--accent-green); background: #090d16; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
    .badge {{
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    .badge-crit {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}
    .badge-high {{ background: rgba(245, 158, 11, 0.2); color: var(--accent-amber); border: 1px solid var(--accent-amber); }}
    .badge-med {{ background: rgba(59, 130, 246, 0.2); color: var(--accent-blue); border: 1px solid var(--accent-blue); }}
    .badge-low {{ background: rgba(148, 163, 184, 0.2); color: var(--text-secondary); border: 1px solid var(--border); }}
    .badge-sys {{ background: #17243c; color: var(--accent-cyan); border: 1px solid #1e3a5f; }}
    .badge-user {{ background: #13281f; color: var(--accent-green); border: 1px solid #165b38; }}
    .pill {{ display: inline-block; font-size: 10px; padding: 2px 6px; border-radius: 3px; background: #0b0f19; color: var(--text-dim); margin: 1px; border: 1px solid var(--border); }}
    .pill-sens {{ color: var(--accent-amber); border-color: rgba(245, 158, 11, 0.4); }}
    .finding-card {{
        background: #0d121e;
        border: 1px solid var(--border);
        border-left: 4px solid var(--accent-cyan);
        border-radius: 6px;
        padding: 14px 18px;
        margin-bottom: 12px;
    }}
    .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }}
    .finding-title {{ font-weight: 700; font-size: 14px; color: var(--text-primary); }}
    .finding-domain {{ font-size: 11px; color: var(--text-dim); margin-left: auto; }}
    .finding-body p {{ font-size: 12px; color: var(--text-secondary); margin-top: 4px; }}
    .search-box {{
        background: #0b0f19;
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 8px 14px;
        color: var(--text-primary);
        font-size: 13px;
        width: 280px;
    }}
    .disclaimer-box {{
        background: #090c14;
        border: 1px dashed var(--border);
        border-radius: 8px;
        padding: 16px 20px;
        font-size: 11px;
        color: var(--text-dim);
        line-height: 1.7;
        margin-top: 25px;
    }}
    .footer {{
        text-align: center;
        padding: 25px 0 10px 0;
        font-size: 11px;
        color: var(--text-dim);
    }}
    .footer a {{ color: var(--accent-green); text-decoration: none; font-weight: 700; }}
    @media print {{
        body {{ background: #fff !important; color: #000 !important; padding: 10px !important; }}
        .header-banner, .section-card, .stat-card {{ border: 1px solid #ccc !important; background: #fff !important; color: #000 !important; }}
        .btn-print, .search-box {{ display: none !important; }}
        code {{ background: #eee !important; color: #000 !important; }}
    }}
</style>
</head>
<body>
<div class="container">
    <!-- Header Banner -->
    <div class="header-banner">
        <div>
            <div class="brand-sub">⚡ SCITBOSS FORENSIC INTELLIGENCE DOSSIER</div>
            <div class="brand-title">SCITBOSS ANDROID FORENSIC & SECURITY ANALYZER PRO</div>
            <div class="meta-pills">
                <span class="meta-pill">📅 Examination: {now_str}</span>
                <span class="meta-pill">📱 Target: {manufacturer} {model} (Android {android_ver})</span>
                <span class="meta-pill">🛡️ Engine: v{APP_VERSION}</span>
                <span class="meta-pill">👨‍💻 Examiner: {AUTHOR_NAME}</span>
            </div>
        </div>
        <div>
            <button onclick="window.print()" class="btn-print">🖨️ Print / Save PDF</button>
        </div>
    </div>

    <!-- Summary KPI Cards -->
    <div class="grid-summary">
        <div class="stat-card">
            <div class="stat-label">Security Posture Score</div>
            <div class="stat-val" style="color: {score_color};">{score} / 100</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Grade: {grade}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Malware & Threat Indicators</div>
            <div class="stat-val" style="color: {'#ef4444' if suspicious_list else '#00ff66'};">{len(suspicious_list)} Flagged</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">{len(crit_high)} High / Critical Risk</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Device Integrity State</div>
            <div class="stat-val" style="font-size: 18px; color: var(--accent-cyan);">{selinux}</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Root: {'DETECTED' if root_info.get('is_rooted') else 'Unrooted / Clean'}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Application Inventory</div>
            <div class="stat-val" style="color: var(--text-primary);">{len(app_inventory)} Packages</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">{len([a for a in app_inventory if not a.get('is_system')])} User-Installed Apps</div>
        </div>
    </div>

    <!-- Section 1: Device Telemetry -->
    <div class="section-card">
        <div class="section-header">
            <div class="section-title">📱 Device Hardware & Operating System Specifications</div>
        </div>
        <table>
            <thead><tr><th>Metric Property</th><th>Observed Value</th><th>Forensic & Security Meaning</th></tr></thead>
            <tbody>
                <tr><td><strong>Manufacturer</strong></td><td><code>{manufacturer}</code></td><td>Hardware OEM assembly vendor</td></tr>
                <tr><td><strong>Commercial Model</strong></td><td><code>{model}</code></td><td>Marketing model identifier</td></tr>
                <tr><td><strong>Hardware Codename</strong></td><td><code>{props.get('ro.product.device', 'N/A')}</code></td><td>Engineering board codename</td></tr>
                <tr><td><strong>Android OS Version</strong></td><td><code>{android_ver} (API {sdk_ver})</code></td><td>OS generation and API level</td></tr>
                <tr><td><strong>Security Patch Level</strong></td><td><code>{patch_date}</code></td><td>OS vulnerability bulletin date</td></tr>
                <tr><td><strong>Cryptographic Fingerprint</strong></td><td><code>{fingerprint}</code></td><td>ROM cryptographic signature</td></tr>
                <tr><td><strong>Linux Kernel Version</strong></td><td><code>{kernel}</code></td><td>Kernel release and compiler build</td></tr>
                <tr><td><strong>CPU Architecture (ABI)</strong></td><td><code>{props.get('ro.product.cpu.abi', 'N/A')}</code></td><td>Primary instruction set architecture</td></tr>
                <tr><td><strong>System Uptime</strong></td><td><code>{uptime}</code></td><td>Continuous execution duration</td></tr>
                <tr><td><strong>Display Geometry</strong></td><td><code>{display.get('resolution', 'N/A')} @ {display.get('density', 'N/A')}</code></td><td>Frame buffer resolution and DPI</td></tr>
                <tr><td><strong>RAM Memory</strong></td><td><code>{memory.get('total', 'N/A')} (Free: {memory.get('free', 'N/A')})</code></td><td>Volatile memory status</td></tr>
                <tr><td><strong>Internal Storage (/data)</strong></td><td><code>{storage.get('data_total', 'N/A')} (Free: {storage.get('data_free', 'N/A')} - {storage.get('percent', 'N/A')} used)</code></td><td>User partition storage capacity</td></tr>
                <tr><td><strong>Battery Telemetry</strong></td><td><code>{battery.get('level', 'N/A')} - {battery.get('status', 'N/A')} (Health: {battery.get('health', 'N/A')}, Temp: {battery.get('temperature', 'N/A')})</code></td><td>Electrochemical cell metrics</td></tr>
            </tbody>
        </table>
    </div>

    <!-- Section 2: Security Audit Findings -->
    <div class="section-card">
        <div class="section-header">
            <div class="section-title">🛡️ Security Posture & Vulnerability Findings</div>
            <div>Score: <strong style="color:{score_color}; font-size:16px;">{score}/100</strong></div>
        </div>
        {''.join(findings_html)}
    </div>

    <!-- Section 3: Malware Threat Indicators -->
    <div class="section-card">
        <div class="section-header">
            <div class="section-title">☣️ Malware & Suspicious Behavior Indicator Scanner</div>
            <div><span class="badge {'badge-crit' if suspicious_list else 'badge-low'}">{len(suspicious_list)} Suspicious Items</span></div>
        </div>
        <table>
            <thead><tr><th>Target Package</th><th>Risk Level</th><th>Confidence</th><th>Forensic Rule Triggers & Reasoning</th><th>Recommended Action</th></tr></thead>
            <tbody>
                {''.join(threats_html)}
            </tbody>
        </table>
    </div>

    <!-- Section 4: Application Inventory -->
    <div class="section-card">
        <div class="section-header">
            <div class="section-title">📦 Installed Applications & Permissions Catalog</div>
            <input type="text" id="appFilter" class="search-box" placeholder="🔍 Search package name..." onkeyup="filterApps()">
        </div>
        <table id="appsTable">
            <thead><tr><th>Package Identifier</th><th>Partition</th><th>Version</th><th>Installer</th><th>Sensitive Permissions</th></tr></thead>
            <tbody>
                {''.join(apps_rows[:300])}
            </tbody>
        </table>
    </div>

    <!-- Section 5: Accessible Storage Artifacts -->
    <div class="section-card">
        <div class="section-header">
            <div class="section-title">📁 Storage Forensics Artifacts & Downloads</div>
            <div><span>{len(storage_files)} Files Enumerated</span></div>
        </div>
        <table>
            <thead><tr><th>File System Path</th><th>Size (Bytes)</th><th>Modified Timestamp</th><th>Forensic Flag</th></tr></thead>
            <tbody>
                {''.join(storage_rows)}
            </tbody>
        </table>
    </div>

    <!-- Disclaimer Box -->
    <div class="disclaimer-box">
        <strong>LEGAL & FORENSIC CHAIN OF CUSTODY NOTICE:</strong><br>
        This digital forensic report was generated by <strong>SCITBOSS ANDROID FORENSIC & SECURITY ANALYZER PRO</strong>.
        All telemetry, package information, and audit indicators were acquired non-intrusively through authorized Android Debug Bridge (ADB) protocols.
        No hardware screen locks, cryptographic passcodes, or secure enclave partitions were bypassed. This report serves as a technical audit dossier
        for authorized cybersecurity research and digital investigation.
    </div>

    <!-- Footer -->
    <div class="footer">
        PROJECT CREDIT | DEVELOP BY SCITBOSS | GITHUB: <a href="{GITHUB_URL}" target="_blank">{GITHUB_URL}</a>
    </div>
</div>

<script>
function filterApps() {{
    var input = document.getElementById("appFilter");
    var filter = input.value.toLowerCase();
    var table = document.getElementById("appsTable");
    var tr = table.getElementsByTagName("tr");
    for (var i = 1; i < tr.length; i++) {{
        var td = tr[i].getElementsByTagName("td")[0];
        if (td) {{
            var txt = td.textContent || td.innerText;
            tr[i].style.display = txt.toLowerCase().indexOf(filter) > -1 ? "" : "none";
        }}
    }}
}}
</script>
</body>
</html>
"""
        return html_doc

    @staticmethod
    def generate_json(device_info: dict, audit_data: dict, malware_data: dict, app_inventory: list, storage_files: list) -> str:
        data = {
            "metadata": {
                "application": APP_NAME,
                "version": APP_VERSION,
                "author": AUTHOR_NAME,
                "github": GITHUB_URL,
                "generated_at": datetime.datetime.now().isoformat(),
                "disclaimer": "This report contains only information accessible through authorized device inspection."
            },
            "device_information": device_info,
            "security_audit": audit_data,
            "malware_scan": malware_data,
            "application_inventory": app_inventory,
            "storage_artifacts": storage_files
        }
        return json.dumps(data, indent=2, default=str)

    @staticmethod
    def export_csv_apps(app_inventory: list, filepath: str):
        fieldnames = ["package_name", "type", "version_name", "version_code", "first_install", "last_update", "installer", "sensitive_perms_count", "has_accessibility", "has_device_admin", "has_overlay"]
        with open(filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for app in app_inventory:
                writer.writerow({
                    "package_name": app.get("package_name", ""),
                    "type": app.get("type", ""),
                    "version_name": app.get("version_name", ""),
                    "version_code": app.get("version_code", ""),
                    "first_install": app.get("first_install", ""),
                    "last_update": app.get("last_update", ""),
                    "installer": app.get("installer", ""),
                    "sensitive_perms_count": len(app.get("sensitive_permissions", {})),
                    "has_accessibility": app.get("has_accessibility", False),
                    "has_device_admin": app.get("has_device_admin", False),
                    "has_overlay": app.get("has_overlay", False)
                })

# ==============================================================================
# GUI PAGES & VIEWS
# ==============================================================================
class BaseView(ttk.Frame):
    """Base frame helper with consistent styling."""
    def __init__(self, parent, controller):
        super().__init__(parent, style="Dark.TFrame")
        self.controller = controller

    def create_header(self, title: str, subtitle: str):
        header_frame = tk.Frame(self, bg=THEME["bg_card"], padx=18, pady=14, relief="flat", highlightbackground=THEME["border"], highlightthickness=1)
        header_frame.pack(fill="x", padx=15, pady=(15, 10))

        title_lbl = tk.Label(header_frame, text=title, font=(FONT_FAMILY, 15, "bold"), fg=THEME["accent_green"], bg=THEME["bg_card"])
        title_lbl.pack(anchor="w")

        sub_lbl = tk.Label(header_frame, text=subtitle, font=(FONT_FAMILY, 9), fg=THEME["text_secondary"], bg=THEME["bg_card"])
        sub_lbl.pack(anchor="w", pady=(2, 0))
        return header_frame

# ------------------------------------------------------------------------------
# 1. DASHBOARD VIEW
# ------------------------------------------------------------------------------
class DashboardView(BaseView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.create_header("CYBERSECURITY DASHBOARD & THREAT TELEMETRY", "Live overview of connected Android device, security audit score, and threat indicators.")

        # Top Statistics Cards Grid
        cards_container = tk.Frame(self, bg=THEME["bg_root"])
        cards_container.pack(fill="x", padx=15, pady=5)
        cards_container.columnconfigure((0, 1, 2, 3), weight=1, uniform="cards")

        self.card_device = self._create_stat_card(cards_container, 0, "DEVICE STATUS", "NO DEVICE", THEME["status_disconnected"], "⚡")
        self.card_model = self._create_stat_card(cards_container, 1, "MODEL & ANDROID", "Disconnected", THEME["text_primary"], "📱")
        self.card_audit = self._create_stat_card(cards_container, 2, "SECURITY SCORE", "-- / 100", THEME["accent_cyan"], "🛡️")
        self.card_threats = self._create_stat_card(cards_container, 3, "SUSPICIOUS APPS", "0 Flagged", THEME["accent_green"], "☣️")

        # Second Row: Storage & App Inventory Summary
        cards_container2 = tk.Frame(self, bg=THEME["bg_root"])
        cards_container2.pack(fill="x", padx=15, pady=5)
        cards_container2.columnconfigure((0, 1, 2, 3), weight=1, uniform="cards2")

        self.card_apps = self._create_stat_card(cards_container2, 0, "INSTALLED PACKAGES", "0 Total", THEME["text_primary"], "📦")
        self.card_selinux = self._create_stat_card(cards_container2, 1, "SELINUX MODE", "Unknown", THEME["text_primary"], "🔒")
        self.card_storage = self._create_stat_card(cards_container2, 2, "INTERNAL STORAGE", "N/A Free", THEME["text_primary"], "💾")
        self.card_battery = self._create_stat_card(cards_container2, 3, "BATTERY STATUS", "N/A", THEME["text_primary"], "🔋")

        # Main Central Action & Telemetry Area
        main_split = tk.Frame(self, bg=THEME["bg_root"])
        main_split.pack(fill="both", expand=True, padx=15, pady=10)
        main_split.columnconfigure(0, weight=3)
        main_split.columnconfigure(1, weight=2)
        main_split.rowconfigure(0, weight=1)

        # Left Column: Quick Action Panel & Live Findings Feed
        left_frame = tk.Frame(main_split, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        lf_title = tk.Label(left_frame, text="⚡ FORENSIC WORKFLOW & RAPID AUDIT", font=(FONT_FAMILY, 11, "bold"), fg=THEME["accent_cyan"], bg=THEME["bg_card"], padx=15, pady=10)
        lf_title.pack(anchor="w")

        btn_row = tk.Frame(left_frame, bg=THEME["bg_card"], padx=15, pady=5)
        btn_row.pack(fill="x")

        self.btn_full_scan = tk.Button(btn_row, text="🔬 Run Full Forensic Scan", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_green"], fg="#000000", activebackground="#05df72", activeforeground="#000000", relief="flat", padx=14, pady=8, cursor="hand2", command=self.controller.start_full_scan)
        self.btn_full_scan.pack(side="left", padx=(0, 10))

        self.btn_quick_scan = tk.Button(btn_row, text="⚡ Quick Audit", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_blue"], fg="#ffffff", activebackground="#2563eb", activeforeground="#ffffff", relief="flat", padx=14, pady=8, cursor="hand2", command=self.controller.start_quick_audit)
        self.btn_quick_scan.pack(side="left", padx=(0, 10))

        self.btn_html = tk.Button(btn_row, text="🌐 View HTML Report", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_cyan"], fg="#000000", activebackground="#00b4d8", activeforeground="#000000", relief="flat", padx=12, pady=8, cursor="hand2", command=self.controller.open_html_report)
        self.btn_html.pack(side="left", padx=(0, 10))

        self.btn_gen_rep = tk.Button(btn_row, text="📑 Export Dossier", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["text_primary"], relief="flat", padx=12, pady=8, cursor="hand2", command=lambda: self.controller.show_page("report"))
        self.btn_gen_rep.pack(side="left")

        # Scan progress bar on dashboard
        prog_frame = tk.Frame(left_frame, bg=THEME["bg_card"], padx=15, pady=10)
        prog_frame.pack(fill="x")
        self.prog_lbl = tk.Label(prog_frame, text="Scan Progress: Ready", font=(FONT_FAMILY, 9), fg=THEME["text_secondary"], bg=THEME["bg_card"])
        self.prog_lbl.pack(anchor="w", pady=(0, 4))
        self.progress_bar = ttk.Progressbar(prog_frame, style="Neon.Horizontal.TProgressbar", mode="determinate")
        self.progress_bar.pack(fill="x")

        # Live Findings Preview
        flist_lbl = tk.Label(left_frame, text="CRITICAL FINDINGS & ANOMALIES", font=(FONT_FAMILY, 10, "bold"), fg=THEME["text_primary"], bg=THEME["bg_card"], padx=15, pady=8)
        flist_lbl.pack(anchor="w", pady=(4, 0))

        self.findings_box = tk.Text(left_frame, bg=THEME["bg_input"], fg=THEME["text_primary"], font=(FONT_MONO, 9), relief="flat", bd=0, padx=10, pady=10, highlightthickness=1, highlightbackground=THEME["border"])
        self.findings_box.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.findings_box.insert("1.0", "[*] No active scan results. Connect an authorized Android device and initiate 'Run Full Forensic Scan'...")
        self.findings_box.config(state="disabled")

        # Right Column: Device Connection Guide & Instructions
        right_frame = tk.Frame(main_split, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        rf_title = tk.Label(right_frame, text="🔌 DEVICE CONNECTION GUIDE", font=(FONT_FAMILY, 11, "bold"), fg=THEME["accent_green"], bg=THEME["bg_card"], padx=15, pady=10)
        rf_title.pack(anchor="w")

        guide_text = (
            "HOW TO CONNECT YOUR ANDROID DEVICE:\n\n"
            "1. ENABLE DEVELOPER OPTIONS:\n"
            "   Settings -> About Phone -> Tap 'Build Number' 7 times\n"
            "   until developer mode is unlocked.\n\n"
            "2. ENABLE USB DEBUGGING:\n"
            "   Settings -> System / Developer Options -> Toggle 'USB Debugging' ON.\n\n"
            "3. CONNECT VIA USB CABLE:\n"
            "   Connect phone to Windows PC using a high-quality data cable.\n"
            "   Ensure USB mode is 'File Transfer (MTP)', not 'Charging only'.\n\n"
            "4. AUTHORIZE PC RSA KEY:\n"
            "   Unlock your phone screen. A popup dialog will appear:\n"
            "   'Allow USB debugging from this computer?'\n"
            "   Check 'Always allow from this computer' and tap 'ALLOW'.\n\n"
            "5. ACTIVE USB AUTO-DETECTION & AUTO-CONNECT:\n"
            "   The software automatically detects Android USB connections in real time!\n"
            "   As soon as you plug in your phone, it auto-detects, auto-connects,\n"
            "   and loads hardware specifications & telemetry immediately.\n"
            "   (You can also click 'Refresh Device' at any time).\n\n"
            "--------------------------------------------------\n"
            "SECURITY NOTICE:\n"
            "This software operates strictly through non-intrusive,\n"
            "authorized ADB protocols. It does NOT bypass lock screens,\n"
            "passwords, or cryptographic hardware keys."
        )

        guide_box = tk.Text(right_frame, bg=THEME["bg_input"], fg=THEME["text_secondary"], font=(FONT_FAMILY, 9), relief="flat", bd=0, padx=12, pady=12, wrap="word", highlightthickness=1, highlightbackground=THEME["border"])
        guide_box.pack(fill="both", expand=True, padx=15, pady=(0, 10))
        guide_box.insert("1.0", guide_text)
        guide_box.config(state="disabled")

        fix_bar = tk.Frame(right_frame, bg=THEME["bg_card"], padx=15, pady=8)
        fix_bar.pack(fill="x", pady=(0, 10))

        btn_fix_drv = tk.Button(fix_bar, text="🔧 Auto-Install Drivers", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_green"], fg="#000000", activebackground="#05df72", activeforeground="#000000", relief="flat", padx=8, pady=6, cursor="hand2", command=self.controller.run_driver_installer_gui)
        btn_fix_drv.pack(side="left", fill="x", expand=True, padx=(0, 4))

        btn_wifi = tk.Button(fix_bar, text="📶 Wi-Fi Connect", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["accent_cyan"], relief="flat", padx=8, pady=6, cursor="hand2", command=self.controller.connect_wireless_gui)
        btn_wifi.pack(side="left", padx=(0, 4))

        btn_diag = tk.Button(fix_bar, text="🩺 Diagnostic", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["text_primary"], relief="flat", padx=8, pady=6, cursor="hand2", command=self.controller.run_hardware_diagnostic_gui)
        btn_diag.pack(side="right")

    def _create_stat_card(self, parent, col, title, value, val_color, icon):
        card = tk.Frame(parent, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1, padx=14, pady=10)
        card.grid(row=0, column=col, sticky="nsew", padx=4, pady=4)

        top_row = tk.Frame(card, bg=THEME["bg_card"])
        top_row.pack(fill="x")

        t_lbl = tk.Label(top_row, text=title, font=(FONT_FAMILY, 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_card"])
        t_lbl.pack(side="left")

        i_lbl = tk.Label(top_row, text=icon, font=(FONT_FAMILY, 10), fg=THEME["accent_green"], bg=THEME["bg_card"])
        i_lbl.pack(side="right")

        v_lbl = tk.Label(card, text=value, font=(FONT_FAMILY, 13, "bold"), fg=val_color, bg=THEME["bg_card"])
        v_lbl.pack(anchor="w", pady=(4, 0))
        return {"frame": card, "val_lbl": v_lbl}

    def update_stats(self, dev_info: dict, audit_data: dict, malware_data: dict, packages: list):
        props = dev_info.get("properties", {})
        battery = dev_info.get("battery", {})
        storage = dev_info.get("storage", {})
        selinux = dev_info.get("selinux", "Unknown")

        # Connection status
        device_status = self.controller.device_status
        if device_status == "device":
            self.card_device["val_lbl"].config(text="AUTHORIZED", fg=THEME["status_connected"])
        elif device_status == "unauthorized":
            self.card_device["val_lbl"].config(text="UNAUTHORIZED", fg=THEME["status_unauthorized"])
        elif device_status == "offline":
            self.card_device["val_lbl"].config(text="OFFLINE", fg=THEME["status_unauthorized"])
        else:
            self.card_device["val_lbl"].config(text="DISCONNECTED", fg=THEME["status_disconnected"])

        # Model & OS
        model = props.get("ro.product.model", "N/A")
        os_ver = props.get("ro.build.version.release", "")
        if model != "N/A":
            self.card_model["val_lbl"].config(text=f"{model} (Android {os_ver})", fg=THEME["text_primary"])
        else:
            self.card_model["val_lbl"].config(text="Disconnected", fg=THEME["text_dim"])

        # Audit score
        if audit_data:
            score = audit_data.get("score", 0)
            score_color = THEME["accent_green"] if score >= 80 else (THEME["accent_amber"] if score >= 60 else THEME["accent_red"])
            self.card_audit["val_lbl"].config(text=f"{score} / 100", fg=score_color)
        else:
            self.card_audit["val_lbl"].config(text="-- / 100", fg=THEME["accent_cyan"])

        # Threats
        if malware_data:
            susp = [r for r in malware_data.get("results", []) if r.get("is_suspicious")]
            threat_color = THEME["accent_red"] if susp else THEME["accent_green"]
            self.card_threats["val_lbl"].config(text=f"{len(susp)} Flagged", fg=threat_color)
        else:
            self.card_threats["val_lbl"].config(text="0 Flagged", fg=THEME["accent_green"])

        # Packages
        self.card_apps["val_lbl"].config(text=f"{len(packages)} Installed")

        # SELinux
        selinux_color = THEME["accent_green"] if selinux.lower() == "enforcing" else THEME["accent_red"]
        self.card_selinux["val_lbl"].config(text=selinux, fg=selinux_color)

        # Storage
        free_st = storage.get("data_free", "N/A")
        self.card_storage["val_lbl"].config(text=f"{free_st} Free")

        # Battery
        bat_lvl = battery.get("level", "N/A")
        bat_stat = battery.get("status", "")
        self.card_battery["val_lbl"].config(text=f"{bat_lvl} ({bat_stat})")

        # Update findings text box
        self.findings_box.config(state="normal")
        self.findings_box.delete("1.0", "end")
        if audit_data and audit_data.get("findings"):
            for f in audit_data.get("findings", []):
                sev = f.get("severity", "Info").upper()
                self.findings_box.insert("end", f"[{sev}] {f.get('title')}\n")
                self.findings_box.insert("end", f"   -> {f.get('evidence')}\n\n")
        else:
            self.findings_box.insert("1.0", "[*] System idle. Ready for diagnostic scan.")
        self.findings_box.config(state="disabled")

# ------------------------------------------------------------------------------
# 2. DEVICE INFORMATION VIEW
# ------------------------------------------------------------------------------
class DeviceInfoView(BaseView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.create_header("COMPLETE ANDROID HARDWARE & SYSTEM DOSSIER", "Deep inspection of accessible hardware specifications, kernel version, build tags, and battery metrics.")

        # Scrollable Notebook / Tabs for Organized Categories
        tab_control = ttk.Notebook(self)
        tab_control.pack(fill="both", expand=True, padx=15, pady=10)

        self.tab_general = ttk.Frame(tab_control, style="Dark.TFrame")
        self.tab_hardware = ttk.Frame(tab_control, style="Dark.TFrame")
        self.tab_security_status = ttk.Frame(tab_control, style="Dark.TFrame")
        self.tab_raw_props = ttk.Frame(tab_control, style="Dark.TFrame")

        tab_control.add(self.tab_general, text="  📱 General & OS  ")
        tab_control.add(self.tab_hardware, text="  ⚙️ Hardware & Battery  ")
        tab_control.add(self.tab_security_status, text="  🔒 Root & SELinux  ")
        tab_control.add(self.tab_raw_props, text="  📋 Raw Properties  ")

        # Populate Tabs
        self.tree_general = self._create_key_value_tree(self.tab_general)
        self.tree_hardware = self._create_key_value_tree(self.tab_hardware)
        self.tree_security = self._create_key_value_tree(self.tab_security_status)

        # Raw Properties Tab
        raw_frame = tk.Frame(self.tab_raw_props, bg=THEME["bg_card"])
        raw_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.raw_text = tk.Text(raw_frame, bg=THEME["bg_input"], fg=THEME["accent_green"], font=(FONT_MONO, 9), relief="flat")
        raw_scroll = ttk.Scrollbar(raw_frame, orient="vertical", command=self.raw_text.yview)
        self.raw_text.configure(yscrollcommand=raw_scroll.set)
        self.raw_text.pack(side="left", fill="both", expand=True)
        raw_scroll.pack(side="right", fill="y")

    def _create_key_value_tree(self, parent):
        frame = tk.Frame(parent, bg=THEME["bg_card"], padx=10, pady=10)
        frame.pack(fill="both", expand=True)

        columns = ("Property", "Value", "Forensic Implication")
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        tree.heading("Property", text="System Metric / Property")
        tree.heading("Value", text="Observed Value")
        tree.heading("Forensic Implication", text="Forensic & Security Meaning")

        tree.column("Property", width=240, anchor="w")
        tree.column("Value", width=350, anchor="w")
        tree.column("Forensic Implication", width=380, anchor="w")

        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return tree

    def update_view(self, dev_info: dict):
        props = dev_info.get("properties", {})
        battery = dev_info.get("battery", {})
        display = dev_info.get("display", {})
        memory = dev_info.get("memory", {})
        storage = dev_info.get("storage", {})
        root_info = dev_info.get("root_info", {})
        sec_settings = dev_info.get("security_settings", {})
        uptime = dev_info.get("uptime", "N/A")
        kernel = dev_info.get("kernel", "N/A")
        selinux = dev_info.get("selinux", "N/A")

        # 1. General & OS
        self.tree_general.delete(*self.tree_general.get_children())
        general_rows = [
            ("Manufacturer", props.get("ro.product.manufacturer", "N/A"), "OEM Vendor responsible for hardware assembly"),
            ("Device Model", props.get("ro.product.model", "N/A"), "Commercial marketing model identification"),
            ("Device Codename", props.get("ro.product.device", "N/A"), "Hardware engineering platform identifier"),
            ("Android Version", f"{props.get('ro.build.version.release', 'N/A')} (API {props.get('ro.build.version.sdk', 'N/A')})", "OS major generation and API capability level"),
            ("Security Patch Level", props.get("ro.build.version.security_patch", "N/A"), "Critical indicator of platform patch age"),
            ("Build Fingerprint", props.get("ro.build.fingerprint", "N/A"), "Cryptographic ROM release and signature identifier"),
            ("Build ID / Display", props.get("ro.build.display.id", "N/A"), "Firmware compilation identifier"),
            ("Kernel Version", kernel, "Linux kernel base version, compiler, and build date"),
            ("System Uptime", uptime, "Duration device has remained continuously powered on"),
            ("Screen Resolution", f"{display.get('resolution', 'N/A')} @ {display.get('density', 'N/A')}", "Physical frame buffer geometry"),
        ]
        for row in general_rows:
            self.tree_general.insert("", "end", values=row)

        # 2. Hardware & Battery
        self.tree_hardware.delete(*self.tree_hardware.get_children())
        hardware_rows = [
            ("CPU Architecture (ABI)", props.get("ro.product.cpu.abi", "N/A"), "Primary native instruction set (e.g. arm64-v8a)"),
            ("CPU ABI List", props.get("ro.product.cpu.abilist", "N/A"), "Supported secondary instruction sets"),
            ("Chipset / Hardware", props.get("ro.hardware", props.get("ro.board.platform", "N/A")), "System-on-Chip (SoC) processor platform"),
            ("RAM Total", memory.get("total", "N/A"), "Physical volatile memory allocated to Android"),
            ("RAM Available", memory.get("available", "N/A"), "Available memory before OOM killer triggers"),
            ("Internal Storage Total", storage.get("data_total", "N/A"), "Total formatted capacity of /data user partition"),
            ("Internal Storage Free", f"{storage.get('data_free', 'N/A')} ({storage.get('percent', 'N/A')} used)", "Free space remaining for user and app data"),
            ("Battery Level", battery.get("level", "N/A"), "Current state of charge"),
            ("Battery Status", battery.get("status", "N/A"), "Charging, discharging, or full status"),
            ("Battery Health", battery.get("health", "N/A"), "Electrochemical cell condition"),
            ("Battery Temperature", battery.get("temperature", "N/A"), "Thermal telemetry reading"),
            ("Battery Voltage", battery.get("voltage", "N/A"), "Operational terminal voltage"),
            ("Battery Technology", battery.get("technology", "N/A"), "Cell chemistry (e.g. Li-ion, Li-poly)"),
        ]
        for row in hardware_rows:
            self.tree_hardware.insert("", "end", values=row)

        # 3. Security & Root
        self.tree_security.delete(*self.tree_security.get_children())
        sec_rows = [
            ("Root Status", "ROOT DETECTED" if root_info.get("is_rooted") else "Unrooted / Clean", "SU binaries or superuser packages presence"),
            ("Root Details", "; ".join(root_info.get("indicators", ["No indicators"])), "Specific binaries or packages detected"),
            ("SELinux Mode", selinux, "Enforcing protects sandboxes; Permissive allows bypass"),
            ("Bootloader Lock", "Locked" if props.get("ro.boot.flash.locked") == "1" else "Unlocked / Insecure", "Guarantees cryptographic verification of boot partitions"),
            ("Verified Boot State", props.get("ro.boot.verifiedbootstate", "N/A"), "Green = Verified; Orange = Custom/Unlocked; Red = Corrupted"),
            ("Device Encryption", props.get("ro.crypto.state", "N/A"), "FBE (File-Based) or FDE (Full-Disk) encryption state"),
            ("Build Tags", props.get("ro.build.tags", "N/A"), "release-keys indicates official OEM; test-keys indicates custom build"),
            ("USB Debugging Status", sec_settings.get("adb_enabled", "N/A"), "Exposed ADB interface"),
            ("Developer Options", sec_settings.get("dev_settings", "N/A"), "Developer settings menu activation"),
            ("Unknown Sources Install", sec_settings.get("install_non_market", "N/A"), "Sideloading policy for non-market APK files"),
            ("Google Play Protect", sec_settings.get("verify_apps", "N/A"), "Package verification service status"),
        ]
        for row in sec_rows:
            self.tree_security.insert("", "end", values=row)

        # 4. Raw Properties
        self.raw_text.config(state="normal")
        self.raw_text.delete("1.0", "end")
        for k, v in sorted(props.items()):
            self.raw_text.insert("end", f"[{k}]: [{v}]\n")
        self.raw_text.config(state="disabled")

# ------------------------------------------------------------------------------
# 3. INSTALLED APPLICATIONS VIEW
# ------------------------------------------------------------------------------
class ApplicationsView(BaseView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.create_header("APPLICATION INVENTORY & PERMISSION FORENSICS", "Forensic catalog of installed applications, system vs user partitions, and high-risk sensitive permissions.")

        # Filter & Search Toolbar
        toolbar = tk.Frame(self, bg=THEME["bg_card"], padx=15, pady=10, highlightbackground=THEME["border"], highlightthickness=1)
        toolbar.pack(fill="x", padx=15, pady=5)

        tk.Label(toolbar, text="Filter:", font=(FONT_FAMILY, 9, "bold"), fg=THEME["text_primary"], bg=THEME["bg_card"]).pack(side="left", padx=(0, 5))

        self.filter_var = tk.StringVar(value="All")
        for mode in ["All", "User Apps", "System Apps", "Sensitive Privileges"]:
            rb = tk.Radiobutton(toolbar, text=mode, variable=self.filter_var, value=mode, font=(FONT_FAMILY, 9), fg=THEME["text_secondary"], selectcolor=THEME["bg_card"], bg=THEME["bg_card"], activebackground=THEME["bg_card"], activeforeground=THEME["accent_green"], command=self.apply_filter)
            rb.pack(side="left", padx=6)

        tk.Label(toolbar, text="Search:", font=(FONT_FAMILY, 9, "bold"), fg=THEME["text_primary"], bg=THEME["bg_card"]).pack(side="left", padx=(15, 5))
        self.search_entry = tk.Entry(toolbar, bg=THEME["bg_input"], fg=THEME["text_primary"], font=(FONT_FAMILY, 9), relief="flat", highlightbackground=THEME["border"], highlightthickness=1, width=25)
        self.search_entry.pack(side="left", padx=5)
        self.search_entry.bind("<KeyRelease>", lambda e: self.apply_filter())

        self.btn_export_apps = tk.Button(toolbar, text="💾 Export Inventory (CSV)", font=(FONT_FAMILY, 9), bg=THEME["accent_blue"], fg="#ffffff", relief="flat", padx=10, pady=4, cursor="hand2", command=self.export_csv)
        self.btn_export_apps.pack(side="right", padx=5)

        # Split Layout: Applications Table (Left) + Detail & Permissions Card (Right)
        split_frame = tk.Frame(self, bg=THEME["bg_root"])
        split_frame.pack(fill="both", expand=True, padx=15, pady=10)
        split_frame.columnconfigure(0, weight=3)
        split_frame.columnconfigure(1, weight=2)
        split_frame.rowconfigure(0, weight=1)

        # Table
        table_frame = tk.Frame(split_frame, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1)
        table_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        columns = ("Package Name", "Type", "Version", "Permissions")
        self.tree_apps = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.tree_apps.heading("Package Name", text="Package Identifier")
        self.tree_apps.heading("Type", text="Partition")
        self.tree_apps.heading("Version", text="Version")
        self.tree_apps.heading("Permissions", text="Sensitive Groups")

        self.tree_apps.column("Package Name", width=260, anchor="w")
        self.tree_apps.column("Type", width=100, anchor="center")
        self.tree_apps.column("Version", width=90, anchor="center")
        self.tree_apps.column("Permissions", width=140, anchor="w")

        app_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_apps.yview)
        self.tree_apps.configure(yscrollcommand=app_scroll.set)
        self.tree_apps.pack(side="left", fill="both", expand=True)
        app_scroll.pack(side="right", fill="y")
        self.tree_apps.bind("<<TreeviewSelect>>", self.on_app_selected)

        # Detail Panel
        detail_frame = tk.Frame(split_frame, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1)
        detail_frame.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        tk.Label(detail_frame, text="APPLICATION FORENSIC PROFILE", font=(FONT_FAMILY, 10, "bold"), fg=THEME["accent_cyan"], bg=THEME["bg_card"], padx=12, pady=10).pack(anchor="w")

        self.detail_text = tk.Text(detail_frame, bg=THEME["bg_input"], fg=THEME["text_primary"], font=(FONT_FAMILY, 9), relief="flat", padx=10, pady=10)
        self.detail_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.detail_text.insert("1.0", "Select an installed application from the table to inspect detailed permissions, installation origins, and forensic risk indicators.")
        self.detail_text.config(state="disabled")

        self.all_packages = []

    def update_packages(self, packages: list):
        self.all_packages = packages
        self.apply_filter()

    def apply_filter(self):
        self.tree_apps.delete(*self.tree_apps.get_children())
        filter_mode = self.filter_var.get()
        search_kw = self.search_entry.get().strip().lower()

        for pkg in self.all_packages:
            name = pkg.get("package_name", "").lower()
            is_sys = pkg.get("is_system", False)
            sens_count = len(pkg.get("sensitive_permissions", {}))

            if search_kw and search_kw not in name:
                continue

            if filter_mode == "User Apps" and is_sys:
                continue
            if filter_mode == "System Apps" and not is_sys:
                continue
            if filter_mode == "Sensitive Privileges" and sens_count == 0:
                continue

            sens_cats = ", ".join(pkg.get("sensitive_permissions", {}).keys()) or "None"
            values = (
                pkg.get("package_name"),
                pkg.get("type"),
                pkg.get("version_name", "N/A"),
                sens_cats
            )
            self.tree_apps.insert("", "end", values=values)

    def on_app_selected(self, event):
        selected = self.tree_apps.selection()
        if not selected:
            return
        item = self.tree_apps.item(selected[0])
        pkg_name = item["values"][0]

        pkg = next((p for p in self.all_packages if p.get("package_name") == pkg_name), None)
        if not pkg:
            return

        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")

        lines = [
            f"Package Name   : {pkg.get('package_name')}",
            f"Partition Type : {pkg.get('type')}",
            f"APK Location   : {pkg.get('apk_path')}",
            f"Version Name   : {pkg.get('version_name', 'N/A')}",
            f"Version Code   : {pkg.get('version_code', 'N/A')}",
            f"Installer      : {pkg.get('installer', 'N/A')}",
            f"First Install  : {pkg.get('first_install', 'N/A')}",
            f"Last Update    : {pkg.get('last_update', 'N/A')}",
            "",
            "SPECIAL PRIVILEGES:",
            f"  * Accessibility Service : {'YES [HIGH RISK]' if pkg.get('has_accessibility') else 'No'}",
            f"  * Device Administrator  : {'YES [HIGH RISK]' if pkg.get('has_device_admin') else 'No'}",
            f"  * System Overlay Window : {'YES [HIGH RISK]' if pkg.get('has_overlay') else 'No'}",
            f"  * Install Other Packages: {'YES [DROPPER RISK]' if pkg.get('has_install_packages') else 'No'}",
            "",
            "SENSITIVE PERMISSION GROUPS:"
        ]
        sens = pkg.get("sensitive_permissions", {})
        if sens:
            for cat, perms in sens.items():
                lines.append(f"  [{cat}]")
                for p in perms:
                    lines.append(f"    - {p}")
        else:
            lines.append("  No dangerous or sensitive permission clusters identified.")

        lines.append("")
        lines.append(f"TOTAL REQUESTED PERMISSIONS: {len(pkg.get('requested_permissions', []))}")
        for p in pkg.get("requested_permissions", []):
            lines.append(f"  - {p}")

        self.detail_text.insert("1.0", "\n".join(lines))
        self.detail_text.config(state="disabled")

    def export_csv(self):
        if not self.all_packages:
            messagebox.showwarning("Export Warning", "No applications inventory available to export.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Spreadsheet", "*.csv")], title="Export Application Inventory")
        if filename:
            try:
                ReportGenerator.export_csv_apps(self.all_packages, filename)
                messagebox.showinfo("Export Successful", f"Application inventory exported successfully to:\n{filename}")
                GLOBAL_LOGGER.success(f"Exported application inventory to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export CSV: {str(e)}")

# ------------------------------------------------------------------------------
# 4. SECURITY AUDIT VIEW
# ------------------------------------------------------------------------------
class SecurityAuditView(BaseView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.create_header("ANDROID SECURITY AUDIT & VULNERABILITY ASSESSMENT", "Transparent rule-based scoring evaluating OS patch age, root privileges, encryption, and system policies.")

        # Top Score Badge Banner
        score_banner = tk.Frame(self, bg=THEME["bg_card"], padx=20, pady=15, highlightbackground=THEME["border"], highlightthickness=1)
        score_banner.pack(fill="x", padx=15, pady=10)

        left_score = tk.Frame(score_banner, bg=THEME["bg_card"])
        left_score.pack(side="left")

        self.lbl_score_num = tk.Label(left_score, text="--", font=(FONT_FAMILY, 32, "bold"), fg=THEME["accent_green"], bg=THEME["bg_card"])
        self.lbl_score_num.pack(side="left")

        score_desc_frame = tk.Frame(left_score, bg=THEME["bg_card"], padx=15)
        score_desc_frame.pack(side="left")

        self.lbl_grade = tk.Label(score_desc_frame, text="Security Posture: Pending Scan", font=(FONT_FAMILY, 13, "bold"), fg=THEME["text_primary"], bg=THEME["bg_card"])
        self.lbl_grade.pack(anchor="w")

        self.lbl_audit_meta = tk.Label(score_desc_frame, text="Auditing 10 core Android security dimensions using transparent rule heuristics.", font=(FONT_FAMILY, 9), fg=THEME["text_secondary"], bg=THEME["bg_card"])
        self.lbl_audit_meta.pack(anchor="w")

        # Findings Tree
        findings_frame = tk.Frame(self, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1)
        findings_frame.pack(fill="both", expand=True, padx=15, pady=10)

        tk.Label(findings_frame, text="AUDIT FINDINGS & REMEDIATION MATRIX", font=(FONT_FAMILY, 10, "bold"), fg=THEME["accent_cyan"], bg=THEME["bg_card"], padx=12, pady=8).pack(anchor="w")

        columns = ("Severity", "Category", "Finding / Vulnerability", "Observed Evidence", "Remediation Advice")
        self.tree_audit = ttk.Treeview(findings_frame, columns=columns, show="headings", selectmode="browse")
        self.tree_audit.heading("Severity", text="Severity")
        self.tree_audit.heading("Category", text="Domain")
        self.tree_audit.heading("Finding / Vulnerability", text="Finding Title")
        self.tree_audit.heading("Observed Evidence", text="Technical Evidence")
        self.tree_audit.heading("Remediation Advice", text="Recommended Countermeasure")

        self.tree_audit.column("Severity", width=90, anchor="center")
        self.tree_audit.column("Category", width=130, anchor="w")
        self.tree_audit.column("Finding / Vulnerability", width=250, anchor="w")
        self.tree_audit.column("Observed Evidence", width=250, anchor="w")
        self.tree_audit.column("Remediation Advice", width=320, anchor="w")

        audit_scroll = ttk.Scrollbar(findings_frame, orient="vertical", command=self.tree_audit.yview)
        self.tree_audit.configure(yscrollcommand=audit_scroll.set)
        self.tree_audit.pack(side="left", fill="both", expand=True)
        audit_scroll.pack(side="right", fill="y")

    def update_audit(self, audit_data: dict):
        self.tree_audit.delete(*self.tree_audit.get_children())
        if not audit_data:
            return

        score = audit_data.get("score", 0)
        grade = audit_data.get("grade", "N/A")
        score_color = THEME["accent_green"] if score >= 80 else (THEME["accent_amber"] if score >= 60 else THEME["accent_red"])

        self.lbl_score_num.config(text=str(score), fg=score_color)
        self.lbl_grade.config(text=f"Security Posture: Grade {grade}")

        for f in audit_data.get("findings", []):
            sev = f.get("severity", "Informational")
            values = (
                sev.upper(),
                f.get("category"),
                f.get("title"),
                f.get("evidence"),
                f.get("remediation")
            )
            self.tree_audit.insert("", "end", values=values)

# ------------------------------------------------------------------------------
# 5. MALWARE & VIRUS INDICATOR SCANNER VIEW
# ------------------------------------------------------------------------------
class MalwareScannerView(BaseView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.create_header("MALWARE & SUSPICIOUS BEHAVIOR INDICATOR SCANNER", "Rule-based heuristic engine detecting banking trojan patterns, stalkerware, and spoofed system packages.")

        # Summary Counters
        summary_bar = tk.Frame(self, bg=THEME["bg_card"], padx=15, pady=10, highlightbackground=THEME["border"], highlightthickness=1)
        summary_bar.pack(fill="x", padx=15, pady=5)
        summary_bar.columnconfigure((0, 1, 2, 3), weight=1)

        self.lbl_total_scanned = self._create_summary_box(summary_bar, 0, "APPS SCANNED", "0", THEME["text_primary"])
        self.lbl_suspicious = self._create_summary_box(summary_bar, 1, "SUSPICIOUS DETECTED", "0", THEME["accent_red"])
        self.lbl_high_risk = self._create_summary_box(summary_bar, 2, "HIGH / CRITICAL RISK", "0", THEME["accent_amber"])
        self.lbl_clean = self._create_summary_box(summary_bar, 3, "CLEAN / BENIGN", "0", THEME["accent_green"])

        # Threats Split View
        threat_split = tk.Frame(self, bg=THEME["bg_root"])
        threat_split.pack(fill="both", expand=True, padx=15, pady=10)
        threat_split.columnconfigure(0, weight=3)
        threat_split.columnconfigure(1, weight=2)
        threat_split.rowconfigure(0, weight=1)

        # Left Table of Flagged Apps
        table_frame = tk.Frame(threat_split, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1)
        table_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        columns = ("Package Name", "Risk Level", "Confidence", "Triggered Rule")
        self.tree_threats = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.tree_threats.heading("Package Name", text="Flagged Package Identifier")
        self.tree_threats.heading("Risk Level", text="Risk Level")
        self.tree_threats.heading("Confidence", text="Confidence")
        self.tree_threats.heading("Triggered Rule", text="Primary Heuristic Rule")

        self.tree_threats.column("Package Name", width=250, anchor="w")
        self.tree_threats.column("Risk Level", width=90, anchor="center")
        self.tree_threats.column("Confidence", width=80, anchor="center")
        self.tree_threats.column("Triggered Rule", width=220, anchor="w")

        threat_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_threats.yview)
        self.tree_threats.configure(yscrollcommand=threat_scroll.set)
        self.tree_threats.pack(side="left", fill="both", expand=True)
        threat_scroll.pack(side="right", fill="y")
        self.tree_threats.bind("<<TreeviewSelect>>", self.on_threat_selected)

        # Right Detail Panel
        detail_frame = tk.Frame(threat_split, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1)
        detail_frame.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        tk.Label(detail_frame, text="THREAT ANALYSIS & ACTIONABLE REMEDIATION", font=(FONT_FAMILY, 10, "bold"), fg=THEME["accent_red"], bg=THEME["bg_card"], padx=12, pady=10).pack(anchor="w")

        self.threat_text = tk.Text(detail_frame, bg=THEME["bg_input"], fg=THEME["text_primary"], font=(FONT_FAMILY, 9), relief="flat", padx=10, pady=10)
        self.threat_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.threat_text.insert("1.0", "Select a flagged package from the threat list to review detailed behavioral reasons, triggered rules, and forensic recommendations.")
        self.threat_text.config(state="disabled")

        self.scanned_results = []

    def _create_summary_box(self, parent, col, title, val, color):
        box = tk.Frame(parent, bg=THEME["bg_card"], padx=10, pady=5)
        box.grid(row=0, column=col, sticky="nsew")
        tk.Label(box, text=title, font=(FONT_FAMILY, 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_card"]).pack(anchor="w")
        lbl = tk.Label(box, text=val, font=(FONT_FAMILY, 15, "bold"), fg=color, bg=THEME["bg_card"])
        lbl.pack(anchor="w")
        return lbl

    def update_scan(self, malware_data: dict):
        self.tree_threats.delete(*self.tree_threats.get_children())
        if not malware_data:
            return

        results = malware_data.get("results", [])
        self.scanned_results = results

        suspicious = [r for r in results if r.get("is_suspicious")]
        high_crit = [r for r in suspicious if r.get("severity") in ["Critical", "High"]]
        clean = len(results) - len(suspicious)

        self.lbl_total_scanned.config(text=str(len(results)))
        self.lbl_suspicious.config(text=str(len(suspicious)))
        self.lbl_high_risk.config(text=str(len(high_crit)))
        self.lbl_clean.config(text=str(clean))

        for item in suspicious:
            primary_rule = item.get("indicators", [{}])[0].get("rule", "Unknown") if item.get("indicators") else "General Anomaly"
            values = (
                item.get("package_name"),
                item.get("severity"),
                f"{item.get('confidence')}%",
                primary_rule
            )
            self.tree_threats.insert("", "end", values=values)

    def on_threat_selected(self, event):
        selected = self.tree_threats.selection()
        if not selected:
            return
        pkg_name = self.tree_threats.item(selected[0])["values"][0]
        item = next((r for r in self.scanned_results if r.get("package_name") == pkg_name), None)
        if not item:
            return

        self.threat_text.config(state="normal")
        self.threat_text.delete("1.0", "end")

        lines = [
            f"TARGET PACKAGE : {item.get('package_name')}",
            f"RISK LEVEL     : {item.get('severity').upper()}",
            f"CONFIDENCE     : {item.get('confidence')}% (Heuristic rule match)",
            "--------------------------------------------------",
            "FORENSIC DETECTION EVIDENCE & TRIGGERS:",
            ""
        ]
        for ind in item.get("indicators", []):
            lines.append(f"RULE: {ind.get('rule')}")
            lines.append(f"REASON: {ind.get('reason')}")
            lines.append("")

        lines.extend([
            "--------------------------------------------------",
            "RECOMMENDED FORENSIC ACTIONS:",
            "1. Quarantine or uninstall the package using:",
            f"   adb uninstall {item.get('package_name')}",
            "2. If package holds Device Admin, revoke admin first in:",
            "   Settings -> Security -> Device Admin Apps.",
            "3. Extract APK file for sandbox malware analysis:",
            f"   adb pull <apk_path> ./evidence_{item.get('package_name')}.apk"
        ])

        self.threat_text.insert("1.0", "\n".join(lines))
        self.threat_text.config(state="disabled")

# ------------------------------------------------------------------------------
# 6. FILE & STORAGE FORENSICS VIEW
# ------------------------------------------------------------------------------
class FileForensicsView(BaseView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.create_header("FILE ARTIFACTS & STORAGE FORENSIC ANALYSIS", "Enumeration of accessible storage partitions, sideloaded APK drops, and suspicious script files.")

        # Directory Selector Toolbar
        toolbar = tk.Frame(self, bg=THEME["bg_card"], padx=15, pady=10, highlightbackground=THEME["border"], highlightthickness=1)
        toolbar.pack(fill="x", padx=15, pady=5)

        tk.Label(toolbar, text="Target Partition:", font=(FONT_FAMILY, 9, "bold"), fg=THEME["text_primary"], bg=THEME["bg_card"]).pack(side="left", padx=(0, 8))

        self.dir_entry = tk.Entry(toolbar, bg=THEME["bg_input"], fg=THEME["text_primary"], font=(FONT_MONO, 9), relief="flat", highlightbackground=THEME["border"], highlightthickness=1, width=35)
        self.dir_entry.insert(0, "/sdcard/Download")
        self.dir_entry.pack(side="left", padx=(0, 10))

        self.btn_browse = tk.Button(toolbar, text="🔍 Inspect Directory", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_green"], fg="#000000", relief="flat", padx=12, pady=4, cursor="hand2", command=self.inspect_custom_dir)
        self.btn_browse.pack(side="left", padx=4)

        for quick_path in ["/sdcard/Download", "/sdcard/Documents", "/sdcard/DCIM"]:
            btn_quick = tk.Button(toolbar, text=os.path.basename(quick_path), font=(FONT_FAMILY, 8), bg=THEME["bg_card_alt"], fg=THEME["text_secondary"], relief="flat", padx=8, pady=4, cursor="hand2", command=lambda p=quick_path: self.set_and_inspect(p))
            btn_quick.pack(side="left", padx=4)

        # File List Tree
        tree_frame = tk.Frame(self, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1)
        tree_frame.pack(fill="both", expand=True, padx=15, pady=10)

        columns = ("Name", "Type", "Size", "Date Modified", "Suspicious Status", "Full Path")
        self.tree_files = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        self.tree_files.heading("Name", text="File / Folder Name")
        self.tree_files.heading("Type", text="Type")
        self.tree_files.heading("Size", text="Size (Bytes)")
        self.tree_files.heading("Date Modified", text="Timestamp")
        self.tree_files.heading("Suspicious Status", text="Forensic Flag")
        self.tree_files.heading("Full Path", text="Full Path")

        self.tree_files.column("Name", width=240, anchor="w")
        self.tree_files.column("Type", width=70, anchor="center")
        self.tree_files.column("Size", width=90, anchor="e")
        self.tree_files.column("Date Modified", width=110, anchor="center")
        self.tree_files.column("Suspicious Status", width=140, anchor="center")
        self.tree_files.column("Full Path", width=350, anchor="w")

        file_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_files.yview)
        self.tree_files.configure(yscrollcommand=file_scroll.set)
        self.tree_files.pack(side="left", fill="both", expand=True)
        file_scroll.pack(side="right", fill="y")

    def inspect_custom_dir(self):
        target = self.dir_entry.get().strip()
        if target:
            self.controller.run_storage_scan(target)

    def set_and_inspect(self, path: str):
        self.dir_entry.delete(0, "end")
        self.dir_entry.insert(0, path)
        self.inspect_custom_dir()

    def update_files(self, files: list):
        self.tree_files.delete(*self.tree_files.get_children())
        for f in files:
            is_susp = f.get("is_suspicious", False)
            flag_text = "SUSPICIOUS ARTIFACT" if is_susp else "Normal"
            values = (
                f.get("name"),
                "DIR" if f.get("is_dir") else "FILE",
                f.get("size"),
                f.get("date"),
                flag_text,
                f.get("path")
            )
            self.tree_files.insert("", "end", values=values)

# ------------------------------------------------------------------------------
# 7. LIVE LOG CONSOLE VIEW
# ------------------------------------------------------------------------------
class LiveLogsView(BaseView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.create_header("REAL-TIME FORENSIC LOG CONSOLE & ADB TERMINAL", "Streaming event logs, ADB subshell responses, and execution activity telemetry.")

        # Log Toolbar
        log_tools = tk.Frame(self, bg=THEME["bg_card"], padx=15, pady=8, highlightbackground=THEME["border"], highlightthickness=1)
        log_tools.pack(fill="x", padx=15, pady=5)

        self.btn_clear = tk.Button(log_tools, text="🗑️ Clear Console", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["text_primary"], relief="flat", padx=10, pady=4, cursor="hand2", command=self.clear_logs)
        self.btn_clear.pack(side="left", padx=4)

        self.btn_copy = tk.Button(log_tools, text="📋 Copy All Logs", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["text_primary"], relief="flat", padx=10, pady=4, cursor="hand2", command=self.copy_logs)
        self.btn_copy.pack(side="left", padx=4)

        self.btn_save = tk.Button(log_tools, text="💾 Save Log to File", font=(FONT_FAMILY, 9), bg=THEME["accent_blue"], fg="#ffffff", relief="flat", padx=10, pady=4, cursor="hand2", command=self.save_logs)
        self.btn_save.pack(side="left", padx=4)

        self.auto_scroll_var = tk.BooleanVar(value=True)
        cb = tk.Checkbutton(log_tools, text="Auto-Scroll", variable=self.auto_scroll_var, font=(FONT_FAMILY, 9), fg=THEME["text_secondary"], bg=THEME["bg_card"], selectcolor=THEME["bg_card"], activebackground=THEME["bg_card"])
        cb.pack(side="right", padx=10)

        # Log Text Box
        console_frame = tk.Frame(self, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1)
        console_frame.pack(fill="both", expand=True, padx=15, pady=5)

        self.console = tk.Text(console_frame, bg=THEME["bg_input"], fg=THEME["text_primary"], font=(FONT_MONO, 9), relief="flat", bd=0, padx=10, pady=10)
        scroll = ttk.Scrollbar(console_frame, orient="vertical", command=self.console.yview)
        self.console.configure(yscrollcommand=scroll.set)
        self.console.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # Color Tags
        self.console.tag_config("INFO", foreground=THEME["accent_cyan"])
        self.console.tag_config("SUCCESS", foreground=THEME["accent_green"])
        self.console.tag_config("WARN", foreground=THEME["accent_amber"])
        self.console.tag_config("ERROR", foreground=THEME["accent_red"])
        self.console.tag_config("AUDIT", foreground=THEME["accent_purple"])
        self.console.tag_config("TIME", foreground=THEME["text_dim"])

        # Interactive Shell Input Area (Safe Read-Only Queries)
        cmd_frame = tk.Frame(self, bg=THEME["bg_card"], padx=15, pady=8, highlightbackground=THEME["border"], highlightthickness=1)
        cmd_frame.pack(fill="x", padx=15, pady=(5, 10))

        tk.Label(cmd_frame, text="ADB Shell Query:", font=(FONT_FAMILY, 9, "bold"), fg=THEME["accent_green"], bg=THEME["bg_card"]).pack(side="left", padx=(0, 8))

        self.cmd_entry = tk.Entry(cmd_frame, bg=THEME["bg_input"], fg=THEME["accent_green"], font=(FONT_MONO, 9), relief="flat", highlightbackground=THEME["border"], highlightthickness=1)
        self.cmd_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.cmd_entry.bind("<Return>", lambda e: self.send_custom_cmd())

        btn_run = tk.Button(cmd_frame, text="⚡ Send Command", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_green"], fg="#000000", relief="flat", padx=12, pady=4, cursor="hand2", command=self.send_custom_cmd)
        btn_run.pack(side="right")

    def append_log(self, level: str, timestamp: str, message: str):
        self.console.insert("end", f"[{timestamp}] ", "TIME")
        self.console.insert("end", f"[{level:<7}] ", level)
        self.console.insert("end", f"{message}\n")
        if self.auto_scroll_var.get():
            self.console.see("end")

    def clear_logs(self):
        self.console.delete("1.0", "end")

    def copy_logs(self):
        self.controller.clipboard_clear()
        self.controller.clipboard_append(self.console.get("1.0", "end"))
        messagebox.showinfo("Copied", "Console logs copied to system clipboard.")

    def save_logs(self):
        filename = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt")], title="Save Execution Logs")
        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(self.console.get("1.0", "end"))
                messagebox.showinfo("Saved", f"Log successfully written to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {str(e)}")

    def send_custom_cmd(self):
        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return
        self.cmd_entry.delete(0, "end")
        GLOBAL_LOGGER.info(f"Executing manual query: adb shell {cmd}")
        threading.Thread(target=self._run_cmd_thread, args=(cmd,), daemon=True).start()

    def _run_cmd_thread(self, cmd: str):
        success, stdout, stderr = self.controller.adb.run_shell(cmd, timeout=12)
        if success:
            GLOBAL_LOGGER.success(f"Result of '{cmd}':\n{stdout}")
        else:
            GLOBAL_LOGGER.error(f"Command '{cmd}' failed: {stderr}")

# ------------------------------------------------------------------------------
# 8. FORENSIC REPORT GENERATOR VIEW
# ------------------------------------------------------------------------------
class ReportGeneratorView(BaseView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.create_header("FORENSIC DOSSIER & COMPREHENSIVE REPORT GENERATOR", "Export court-admissible technical investigation dossiers in structured TXT, JSON, and CSV formats.")

        # Export Controls Frame
        ctrl_frame = tk.Frame(self, bg=THEME["bg_card"], padx=20, pady=15, highlightbackground=THEME["border"], highlightthickness=1)
        ctrl_frame.pack(fill="x", padx=15, pady=10)

        tk.Label(ctrl_frame, text="SELECT EXPORT FORMAT & DESTINATION", font=(FONT_FAMILY, 11, "bold"), fg=THEME["accent_cyan"], bg=THEME["bg_card"]).pack(anchor="w", pady=(0, 10))

        btn_row = tk.Frame(ctrl_frame, bg=THEME["bg_card"])
        btn_row.pack(fill="x")

        self.btn_open_html = tk.Button(btn_row, text="🌐 View HTML Report in Browser", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_green"], fg="#000000", activebackground="#05df72", activeforeground="#000000", relief="flat", padx=14, pady=8, cursor="hand2", command=self.open_html_browser)
        self.btn_open_html.pack(side="left", padx=(0, 8))

        self.btn_export_html = tk.Button(btn_row, text="💾 Save HTML Dossier", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_cyan"], fg="#000000", activebackground="#00b4d8", activeforeground="#000000", relief="flat", padx=14, pady=8, cursor="hand2", command=self.export_html)
        self.btn_export_html.pack(side="left", padx=(0, 8))

        self.btn_export_txt = tk.Button(btn_row, text="📄 Export TXT", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["text_primary"], relief="flat", padx=12, pady=8, cursor="hand2", command=self.export_txt)
        self.btn_export_txt.pack(side="left", padx=(0, 8))

        self.btn_export_json = tk.Button(btn_row, text="📦 Export JSON", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["text_primary"], relief="flat", padx=12, pady=8, cursor="hand2", command=self.export_json)
        self.btn_export_json.pack(side="left", padx=(0, 8))

        self.btn_export_csv = tk.Button(btn_row, text="📊 Export Apps CSV", font=(FONT_FAMILY, 9), bg=THEME["accent_blue"], fg="#ffffff", relief="flat", padx=12, pady=8, cursor="hand2", command=self.export_csv)
        self.btn_export_csv.pack(side="left")

        # Report Preview Text
        preview_frame = tk.Frame(self, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1)
        preview_frame.pack(fill="both", expand=True, padx=15, pady=(5, 15))

        tk.Label(preview_frame, text="DOSSIER PREVIEW", font=(FONT_FAMILY, 10, "bold"), fg=THEME["text_primary"], bg=THEME["bg_card"], padx=15, pady=8).pack(anchor="w")

        self.preview_text = tk.Text(preview_frame, bg=THEME["bg_input"], fg=THEME["text_primary"], font=(FONT_MONO, 9), relief="flat", bd=0, padx=12, pady=12)
        scroll = ttk.Scrollbar(preview_frame, orient="vertical", command=self.preview_text.yview)
        self.preview_text.configure(yscrollcommand=scroll.set)
        self.preview_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.preview_text.insert("1.0", "[*] Run a diagnostic scan to generate the forensic report dossier preview.")
        self.preview_text.config(state="disabled")

    def update_preview(self):
        txt_content = ReportGenerator.generate_txt(
            self.controller.device_data,
            self.controller.audit_data,
            self.controller.malware_data,
            self.controller.app_inventory,
            self.controller.storage_files
        )
        self.preview_text.config(state="normal")
        self.preview_text.delete("1.0", "end")
        self.preview_text.insert("1.0", txt_content)
        self.preview_text.config(state="disabled")

    def open_html_browser(self):
        try:
            html_content = ReportGenerator.generate_html(
                self.controller.device_data,
                self.controller.audit_data,
                self.controller.malware_data,
                self.controller.app_inventory,
                self.controller.storage_files
            )
            out_file = ReportGenerator.get_default_report_path()
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            GLOBAL_LOGGER.success(f"Generated HTML report: {out_file}")
            webbrowser.open_new_tab(f"file:///{os.path.abspath(out_file).replace(os.sep, '/')}")
        except Exception as e:
            messagebox.showerror("HTML Report Error", f"Failed to generate HTML report: {str(e)}")

    def export_html(self):
        filename = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML Dossier", "*.html"), ("All Files", "*.*")], title="Save HTML Forensic Dossier")
        if filename:
            try:
                content = ReportGenerator.generate_html(
                    self.controller.device_data,
                    self.controller.audit_data,
                    self.controller.malware_data,
                    self.controller.app_inventory,
                    self.controller.storage_files
                )
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Export Successful", f"HTML forensic dossier saved successfully to:\n{filename}")
                GLOBAL_LOGGER.success(f"Forensic HTML dossier saved: {filename}")
                webbrowser.open_new_tab(f"file:///{os.path.abspath(filename).replace(os.sep, '/')}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save HTML report: {str(e)}")

    def export_txt(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Report", "*.txt")], title="Export Forensic Dossier")
        if filename:
            try:
                content = ReportGenerator.generate_txt(
                    self.controller.device_data,
                    self.controller.audit_data,
                    self.controller.malware_data,
                    self.controller.app_inventory,
                    self.controller.storage_files
                )
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Export Successful", f"Forensic dossier successfully exported to:\n{filename}")
                GLOBAL_LOGGER.success(f"Forensic TXT dossier saved: {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save TXT report: {str(e)}")

    def export_json(self):
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON File", "*.json")], title="Export JSON Evidence")
        if filename:
            try:
                content = ReportGenerator.generate_json(
                    self.controller.device_data,
                    self.controller.audit_data,
                    self.controller.malware_data,
                    self.controller.app_inventory,
                    self.controller.storage_files
                )
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Export Successful", f"Structured JSON evidence successfully saved to:\n{filename}")
                GLOBAL_LOGGER.success(f"Evidence JSON saved: {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save JSON: {str(e)}")

    def export_csv(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Spreadsheet", "*.csv")], title="Export Apps CSV")
        if filename:
            try:
                ReportGenerator.export_csv_apps(self.controller.app_inventory, filename)
                messagebox.showinfo("Export Successful", f"Application inventory CSV saved to:\n{filename}")
                GLOBAL_LOGGER.success(f"Apps CSV saved: {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save CSV: {str(e)}")

# ------------------------------------------------------------------------------
# 9. SETTINGS & ADB CONFIGURATION VIEW
# ------------------------------------------------------------------------------
class SettingsView(BaseView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.create_header("ADB INTEGRATION & FORENSIC ENVIRONMENT SETTINGS", "Configure custom ADB binary paths, verify environment dependencies, and test bridge connectivity.")

        card = tk.Frame(self, bg=THEME["bg_card"], padx=20, pady=20, highlightbackground=THEME["border"], highlightthickness=1)
        card.pack(fill="x", padx=15, pady=10)

        tk.Label(card, text="ADB BINARY CONFIGURATION", font=(FONT_FAMILY, 11, "bold"), fg=THEME["accent_green"], bg=THEME["bg_card"]).pack(anchor="w", pady=(0, 10))

        path_row = tk.Frame(card, bg=THEME["bg_card"])
        path_row.pack(fill="x", pady=5)

        tk.Label(path_row, text="Active ADB Path:", font=(FONT_FAMILY, 9, "bold"), fg=THEME["text_primary"], bg=THEME["bg_card"]).pack(side="left", padx=(0, 10))

        self.adb_path_entry = tk.Entry(path_row, bg=THEME["bg_input"], fg=THEME["accent_cyan"], font=(FONT_MONO, 9), relief="flat", highlightbackground=THEME["border"], highlightthickness=1)
        self.adb_path_entry.insert(0, self.controller.adb.adb_path or "adb")
        self.adb_path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_browse = tk.Button(path_row, text="📁 Browse...", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["text_primary"], relief="flat", padx=10, pady=4, cursor="hand2", command=self.browse_adb)
        btn_browse.pack(side="left", padx=4)

        btn_apply = tk.Button(path_row, text="Apply Path", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_green"], fg="#000000", relief="flat", padx=12, pady=4, cursor="hand2", command=self.apply_custom_adb)
        btn_apply.pack(side="left", padx=4)

        # Status & Diagnostic Test
        diag_row = tk.Frame(card, bg=THEME["bg_card"], pady=12)
        diag_row.pack(fill="x")

        btn_test = tk.Button(diag_row, text="⚡ Test ADB Connectivity", font=(FONT_FAMILY, 9), bg=THEME["accent_blue"], fg="#ffffff", relief="flat", padx=12, pady=6, cursor="hand2", command=self.test_adb)
        btn_test.pack(side="left", padx=(0, 10))

        self.lbl_adb_diag = tk.Label(diag_row, text="Status: Not tested", font=(FONT_FAMILY, 9), fg=THEME["text_secondary"], bg=THEME["bg_card"])
        self.lbl_adb_diag.pack(side="left")

        # USB Driver Repair & Auto-Installer Card
        driver_card = tk.Frame(self, bg=THEME["bg_card"], padx=20, pady=16, highlightbackground=THEME["border"], highlightthickness=1)
        driver_card.pack(fill="x", padx=15, pady=8)

        tk.Label(driver_card, text="🔧 ANDROID USB DRIVER & CONNECTION REPAIR", font=(FONT_FAMILY, 11, "bold"), fg=THEME["accent_cyan"], bg=THEME["bg_card"]).pack(anchor="w", pady=(0, 6))

        tk.Label(driver_card, text="If your phone is plugged in but not connecting, use these 1-click tools to install Windows ADB drivers and fix connectivity:", font=(FONT_FAMILY, 9), fg=THEME["text_secondary"], bg=THEME["bg_card"]).pack(anchor="w", pady=(0, 10))

        btn_bar = tk.Frame(driver_card, bg=THEME["bg_card"])
        btn_bar.pack(fill="x")

        btn_install_driver = tk.Button(btn_bar, text="⚡ 1-Click Auto-Install Android USB Driver", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_green"], fg="#000000", activebackground="#05df72", activeforeground="#000000", relief="flat", padx=14, pady=6, cursor="hand2", command=self.controller.run_driver_installer_gui)
        btn_install_driver.pack(side="left", padx=(0, 8))

        btn_restart_adb = tk.Button(btn_bar, text="🔄 Restart ADB Server Daemon", font=(FONT_FAMILY, 9), bg=THEME["accent_blue"], fg="#ffffff", activebackground="#2563eb", activeforeground="#ffffff", relief="flat", padx=12, pady=6, cursor="hand2", command=self.controller.run_restart_adb_gui)
        btn_restart_adb.pack(side="left", padx=(0, 8))

        btn_diag_hw = tk.Button(btn_bar, text="🩺 Scan Physical USB Ports", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["text_primary"], relief="flat", padx=12, pady=6, cursor="hand2", command=self.controller.run_hardware_diagnostic_gui)
        btn_diag_hw.pack(side="left")

        # PyInstaller & Standalone EXE Build Documentation
        exe_card = tk.Frame(self, bg=THEME["bg_card"], padx=20, pady=20, highlightbackground=THEME["border"], highlightthickness=1)
        exe_card.pack(fill="both", expand=True, padx=15, pady=(5, 15))

        tk.Label(exe_card, text="WINDOWS STANDALONE EXE BUILD SPECIFICATION", font=(FONT_FAMILY, 11, "bold"), fg=THEME["accent_cyan"], bg=THEME["bg_card"]).pack(anchor="w", pady=(0, 10))

        build_instructions = (
            "HOW TO BUILD A STANDALONE WINDOWS EXECUTABLE (.EXE):\n\n"
            "This software is engineered to be 100% convertible into a standalone Windows executable\n"
            "without requiring end-users to install Python or external packages.\n\n"
            "1. Install PyInstaller in your Python environment:\n"
            "   pip install pyinstaller\n\n"
            "2. Execute the single-file build command:\n"
            "   pyinstaller --onefile --windowed --name SCITBOSS_ANDROID_FORENSIC_PRO scitboss_android_forensic_pro.py\n\n"
            "3. (Optional) Bundle ADB platform-tools folder adjacent to the executable or embed platform-tools/adb.exe.\n"
            "   The application automatically detects adjacent platform-tools/ folders upon startup.\n\n"
            "Output Executable Location:\n"
            "   ./dist/SCITBOSS_ANDROID_FORENSIC_PRO.exe"
        )

        build_box = tk.Text(exe_card, bg=THEME["bg_input"], fg=THEME["text_secondary"], font=(FONT_MONO, 9), relief="flat", bd=0, padx=12, pady=12, wrap="word")
        build_box.pack(fill="both", expand=True)
        build_box.insert("1.0", build_instructions)
        build_box.config(state="disabled")

    def browse_adb(self):
        filename = filedialog.askopenfilename(title="Select adb.exe", filetypes=[("Executable Files", "adb.exe;adb"), ("All Files", "*.*")])
        if filename:
            self.adb_path_entry.delete(0, "end")
            self.adb_path_entry.insert(0, filename)

    def apply_custom_adb(self):
        custom = self.adb_path_entry.get().strip()
        if custom:
            self.controller.adb.adb_path = custom
            GLOBAL_LOGGER.info(f"Custom ADB path set to: {custom}")
            self.test_adb()

    def test_adb(self):
        success, version_str = self.controller.adb.check_adb_version()
        if success:
            self.lbl_adb_diag.config(text=f"CONNECTED: {version_str}", fg=THEME["accent_green"])
            GLOBAL_LOGGER.success(f"ADB bridge operational: {version_str}")
            self.controller.refresh_devices()
        else:
            self.lbl_adb_diag.config(text=f"FAILED: {version_str}", fg=THEME["accent_red"])
            GLOBAL_LOGGER.error(f"ADB bridge failed: {version_str}")

# ------------------------------------------------------------------------------
# 10. ABOUT VIEW
# ------------------------------------------------------------------------------
class AboutView(BaseView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.create_header("ABOUT SCITBOSS ANDROID FORENSIC & SECURITY ANALYZER PRO", "Software metadata, project credit, development team, and licensing information.")

        card = tk.Frame(self, bg=THEME["bg_card"], padx=30, pady=25, highlightbackground=THEME["border"], highlightthickness=1)
        card.pack(fill="both", expand=True, padx=15, pady=15)

        title_lbl = tk.Label(card, text="SCITBOSS ANDROID FORENSIC & SECURITY ANALYZER PRO", font=(FONT_FAMILY, 15, "bold"), fg=THEME["accent_green"], bg=THEME["bg_card"])
        title_lbl.pack(anchor="w", pady=(0, 4))

        sub_lbl = tk.Label(card, text="Professional Android Security Analysis & Digital Forensics Tool", font=(FONT_FAMILY, 11), fg=THEME["accent_cyan"], bg=THEME["bg_card"])
        sub_lbl.pack(anchor="w", pady=(0, 15))

        about_desc = (
            "DESIGN & PURPOSE:\n"
            "Designed for authorized Android device inspection, cybersecurity research, security auditing,\n"
            "ethical hacking, and digital forensic information collection.\n\n"
            "KEY CAPABILITIES:\n"
            "• Deep hardware, kernel, and firmware telemetry extraction.\n"
            "• Application inventory forensic audit with sensitive permission cluster tracking.\n"
            "• Advanced rule-based security scoring (0-100%) evaluating 10 key OS dimensions.\n"
            "• Malware indicator analysis: banking trojan overlays, SMS stealers, covert stalkerware.\n"
            "• Storage artifact auditing (sideloaded APKs, suspicious scripts in Download).\n"
            "• Comprehensive dossier generation in TXT, JSON, and CSV formats.\n"
            "• Real-time colorized log terminal with safe interactive ADB query runner.\n"
            "• 100% lightweight pure-Python Tkinter desktop architecture with PyInstaller EXE support.\n\n"
            "SPECIFICATIONS:\n"
            f"• Software Version : {APP_VERSION}\n"
            f"• Lead Developer   : {AUTHOR_NAME}\n"
            "• Target Platform  : Windows 10 & Windows 11 (64-bit)\n"
            "• Interface        : USB Debugging via Android Debug Bridge (ADB)\n\n"
            "ETHICAL & SECURITY NOTICE:\n"
            "This software is intended strictly for authorized security assessments, digital forensic research,\n"
            "and auditing devices where explicit permission has been obtained. The application operates in strict\n"
            "adherence to Android security boundaries and does not circumvent screen locks, passcodes, or encryption."
        )

        txt = tk.Text(card, bg=THEME["bg_input"], fg=THEME["text_primary"], font=(FONT_FAMILY, 9), relief="flat", bd=0, padx=14, pady=14, wrap="word")
        txt.pack(fill="both", expand=True, pady=(0, 15))
        txt.insert("1.0", about_desc)
        txt.config(state="disabled")

        credit_frame = tk.Frame(card, bg=THEME["bg_card_alt"], padx=15, pady=12, highlightbackground=THEME["border"], highlightthickness=1)
        credit_frame.pack(fill="x")

        credit_txt = tk.Label(credit_frame, text="PROJECT CREDIT: DEVELOP BY SCITBOSS", font=(FONT_FAMILY, 10, "bold"), fg=THEME["accent_green"], bg=THEME["bg_card_alt"])
        credit_txt.pack(side="left")

        btn_gh = tk.Button(credit_frame, text="🌐 Visit GitHub: https://github.com/scitboss", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_cyan"], fg="#000000", relief="flat", padx=12, pady=5, cursor="hand2", command=lambda: webbrowser.open_new_tab(GITHUB_URL))
        btn_gh.pack(side="right")

# ==============================================================================
# MAIN APPLICATION CONTROLLER
# ==============================================================================
class ScitbossApp(tk.Tk):
    """
    Main application window and coordinator orchestrating background scan
    threads, navigation views, ADB telemetry, and status updates.
    """
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} [v{APP_VERSION}]")
        self.geometry("1240x820")
        self.minsize(1080, 720)
        self.configure(bg=THEME["bg_root"])

        # Try to apply dark titlebar on Windows 10/11
        if sys.platform.startswith("win"):
            try:
                import ctypes
                hwnd = self.winfo_id()
                # 20 = DWMWA_USE_IMMERSIVE_DARK_MODE on Win11/Win10 modern builds
                ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(1)), 4)
            except Exception:
                pass

        # Data Models & State
        self.adb = AdbEngine(GLOBAL_LOGGER)
        self.device_status = "disconnected"
        self.device_data = {}
        self.app_inventory = []
        self.audit_data = {}
        self.malware_data = {}
        self.storage_files = []
        self.is_scanning = False

        # Auto-detection state
        self.auto_detect_enabled = True
        self._last_device_signature = None
        self._running = True

        self._configure_ttk_styles()
        self._build_main_layout()

        # Window closing handler for clean shutdown
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Start background timer for log consumption
        self.after(100, self._process_log_queue)

        # Start persistent auto-detection worker for instant USB connection
        self.auto_detect_thread = threading.Thread(target=self._auto_detect_worker, daemon=True)
        self.auto_detect_thread.start()

    def _configure_ttk_styles(self):
        """Configure sleek dark theme styles for standard ttk widgets."""
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("Dark.TFrame", background=THEME["bg_root"])
        style.configure("Card.TFrame", background=THEME["bg_card"])

        # Treeview Styling
        style.configure(
            "Treeview",
            background=THEME["bg_card"],
            foreground=THEME["text_primary"],
            fieldbackground=THEME["bg_card"],
            rowheight=26,
            font=(FONT_FAMILY, 9),
            borderwidth=0
        )
        style.map("Treeview", background=[("selected", THEME["bg_card_alt"])], foreground=[("selected", THEME["accent_green"])])

        style.configure(
            "Treeview.Heading",
            background=THEME["bg_sidebar"],
            foreground=THEME["text_primary"],
            font=(FONT_FAMILY, 9, "bold"),
            relief="flat",
            padding=5
        )
        style.map("Treeview.Heading", background=[("active", THEME["bg_card_alt"])])

        # Scrollbar Styling
        style.configure("Vertical.TScrollbar", background=THEME["bg_sidebar"], troughcolor=THEME["bg_root"], borderwidth=0, arrowcolor=THEME["text_dim"])

        # Progressbar Styling
        style.configure("Neon.Horizontal.TProgressbar", background=THEME["accent_green"], troughcolor=THEME["bg_input"], bordercolor=THEME["border"], lightcolor=THEME["accent_green"], darkcolor=THEME["accent_green"])

        # Notebook Tabs
        style.configure("TNotebook", background=THEME["bg_root"], borderwidth=0)
        style.configure("TNotebook.Tab", background=THEME["bg_sidebar"], foreground=THEME["text_secondary"], font=(FONT_FAMILY, 9, "bold"), padding=[14, 6], borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", THEME["bg_card"])], foreground=[("selected", THEME["accent_green"])])

    def _build_main_layout(self):
        # 1. Main Header Bar
        self.header_frame = tk.Frame(self, bg=THEME["bg_sidebar"], height=58, highlightbackground=THEME["border"], highlightthickness=1)
        self.header_frame.pack(side="top", fill="x")

        # Header Title & Icon
        brand_frame = tk.Frame(self.header_frame, bg=THEME["bg_sidebar"], padx=15, pady=8)
        brand_frame.pack(side="left")

        logo_lbl = tk.Label(brand_frame, text="⚡", font=(FONT_FAMILY, 15, "bold"), fg=THEME["accent_green"], bg=THEME["bg_sidebar"])
        logo_lbl.pack(side="left", padx=(0, 8))

        app_title_lbl = tk.Label(brand_frame, text=APP_NAME, font=(FONT_FAMILY, 11, "bold"), fg=THEME["text_primary"], bg=THEME["bg_sidebar"])
        app_title_lbl.pack(side="left")

        # Header Right: Auto-Detect Toggle, Fix Drivers, Refresh Device, Status Badge
        header_right = tk.Frame(self.header_frame, bg=THEME["bg_sidebar"], padx=15, pady=8)
        header_right.pack(side="right")

        self.btn_auto_detect = tk.Button(header_right, text="⚡ Auto-Detect: ON", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_green"], fg="#000000", activebackground="#05df72", activeforeground="#000000", relief="flat", padx=10, pady=5, cursor="hand2", command=self.toggle_auto_detect)
        self.btn_auto_detect.pack(side="left", padx=(0, 6))

        self.btn_driver_fix = tk.Button(header_right, text="🔧 Auto-Install Drivers", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_cyan"], fg="#000000", activebackground="#00b4d8", activeforeground="#000000", relief="flat", padx=10, pady=5, cursor="hand2", command=self.run_driver_installer_gui)
        self.btn_driver_fix.pack(side="left", padx=(0, 6))

        self.btn_wifi = tk.Button(header_right, text="📶 Wi-Fi", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["accent_cyan"], relief="flat", padx=8, pady=5, cursor="hand2", command=self.connect_wireless_gui)
        self.btn_wifi.pack(side="left", padx=(0, 6))

        self.btn_refresh = tk.Button(header_right, text="🔄 Refresh", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["text_primary"], relief="flat", padx=10, pady=5, cursor="hand2", command=self.refresh_devices)
        self.btn_refresh.pack(side="left", padx=(0, 8))

        self.lbl_status_badge = tk.Label(header_right, text="DISCONNECTED", font=(FONT_FAMILY, 9, "bold"), fg="#ffffff", bg=THEME["status_disconnected"], padx=10, pady=4)
        self.lbl_status_badge.pack(side="left")

        # 2. Permanent Footer Bar
        self.footer_frame = tk.Frame(self, bg=THEME["bg_sidebar"], height=32, highlightbackground=THEME["border"], highlightthickness=1)
        self.footer_frame.pack(side="bottom", fill="x")

        footer_left = tk.Label(self.footer_frame, text="PROJECT CREDIT  |  DEVELOP BY SCITBOSS  |  ANDROID FORENSIC PRO", font=(FONT_FAMILY, 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_sidebar"], padx=15, pady=6)
        footer_left.pack(side="left")

        btn_footer_gh = tk.Button(self.footer_frame, text="GITHUB: https://github.com/scitboss", font=(FONT_FAMILY, 8, "bold"), fg=THEME["accent_green"], bg=THEME["bg_sidebar"], relief="flat", bd=0, cursor="hand2", command=lambda: webbrowser.open_new_tab(GITHUB_URL))
        btn_footer_gh.pack(side="right", padx=15, pady=6)

        # 3. Main Center Area (Sidebar + Content Pages)
        center_body = tk.Frame(self, bg=THEME["bg_root"])
        center_body.pack(fill="both", expand=True)

        # Left Sidebar
        self.sidebar_frame = tk.Frame(center_body, bg=THEME["bg_sidebar"], width=230, highlightbackground=THEME["border"], highlightthickness=1)
        self.sidebar_frame.pack(side="left", fill="y")
        self.sidebar_frame.pack_propagate(False)

        # Navigation Menu Items
        nav_title = tk.Label(self.sidebar_frame, text="INVESTIGATION MODULES", font=(FONT_FAMILY, 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_sidebar"], padx=15, pady=12)
        nav_title.pack(anchor="w")

        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "📊 Dashboard"),
            ("device_info", "📱 Device Info"),
            ("applications", "📦 Installed Apps"),
            ("security_audit", "🛡️ Security Audit"),
            ("malware_scanner", "☣️ Malware Scanner"),
            ("file_forensics", "📁 File Forensics"),
            ("live_logs", "📜 Live Logs"),
            ("report", "📑 Report Dossier"),
            ("settings", "⚙️ ADB Settings"),
            ("about", "ℹ️ About & Credits"),
        ]

        for page_id, label in nav_items:
            btn = tk.Button(
                self.sidebar_frame,
                text=f"  {label}",
                font=(FONT_FAMILY, 9),
                fg=THEME["text_secondary"],
                bg=THEME["bg_sidebar"],
                activebackground=THEME["bg_card"],
                activeforeground=THEME["accent_green"],
                relief="flat",
                anchor="w",
                padx=15,
                pady=9,
                cursor="hand2",
                command=lambda pid=page_id: self.show_page(pid)
            )
            btn.pack(fill="x")
            self.nav_buttons[page_id] = btn

        # Sidebar Bottom Info
        sb_bottom = tk.Frame(self.sidebar_frame, bg=THEME["bg_sidebar"], padx=15, pady=15)
        sb_bottom.pack(side="bottom", fill="x")

        sb_badge = tk.Label(sb_bottom, text="SCITBOSS FORENSICS", font=(FONT_FAMILY, 8, "bold"), fg=THEME["accent_cyan"], bg=THEME["bg_sidebar"])
        sb_badge.pack(anchor="w")
        sb_ver = tk.Label(sb_bottom, text=f"Engine v{APP_VERSION}", font=(FONT_FAMILY, 8), fg=THEME["text_dim"], bg=THEME["bg_sidebar"])
        sb_ver.pack(anchor="w")

        # Right Content View Area
        self.content_area = tk.Frame(center_body, bg=THEME["bg_root"])
        self.content_area.pack(side="left", fill="both", expand=True)

        # Instantiate View Pages
        self.pages = {}
        self.pages["dashboard"] = DashboardView(self.content_area, self)
        self.pages["device_info"] = DeviceInfoView(self.content_area, self)
        self.pages["applications"] = ApplicationsView(self.content_area, self)
        self.pages["security_audit"] = SecurityAuditView(self.content_area, self)
        self.pages["malware_scanner"] = MalwareScannerView(self.content_area, self)
        self.pages["file_forensics"] = FileForensicsView(self.content_area, self)
        self.pages["live_logs"] = LiveLogsView(self.content_area, self)
        self.pages["report"] = ReportGeneratorView(self.content_area, self)
        self.pages["settings"] = SettingsView(self.content_area, self)
        self.pages["about"] = AboutView(self.content_area, self)

        for p in self.pages.values():
            p.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.show_page("dashboard")

    def show_page(self, page_id: str):
        """Bring target view page to front and highlight active navigation button."""
        if page_id in self.pages:
            self.pages[page_id].tkraise()
            for pid, btn in self.nav_buttons.items():
                if pid == page_id:
                    btn.config(bg=THEME["bg_card"], fg=THEME["accent_green"], font=(FONT_FAMILY, 9, "bold"))
                else:
                    btn.config(bg=THEME["bg_sidebar"], fg=THEME["text_secondary"], font=(FONT_FAMILY, 9))

    def _process_log_queue(self):
        """Drain thread-safe logger queue and push entries into LiveLogsView."""
        try:
            while not GLOBAL_LOGGER.queue.empty():
                level, timestamp, message = GLOBAL_LOGGER.queue.get_nowait()
                if "live_logs" in self.pages:
                    self.pages["live_logs"].append_log(level, timestamp, message)
        except Exception:
            pass
        self.after(100, self._process_log_queue)

    # --------------------------------------------------------------------------
    # USB HOTPLUG AUTO-DETECTION & DEVICE DISCOVERY
    # --------------------------------------------------------------------------
    def toggle_auto_detect(self):
        """Toggle active background USB hotplug auto-detection."""
        self.auto_detect_enabled = not self.auto_detect_enabled
        if self.auto_detect_enabled:
            self.btn_auto_detect.config(text="⚡ Auto-Detect: ON", bg=THEME["accent_green"], fg="#000000")
            GLOBAL_LOGGER.success("⚡ Auto-Detect is ACTIVE. When an Android phone is connected via USB, it will connect automatically.")
            self._last_device_signature = None
            self.refresh_devices()
        else:
            self.btn_auto_detect.config(text="⚡ Auto-Detect: OFF", bg=THEME["bg_card_alt"], fg=THEME["text_dim"])
            GLOBAL_LOGGER.info("Auto-Detect paused. Click 'Refresh Device' to connect manually.")

    def refresh_devices(self):
        """Manual refresh forcing an immediate ADB device scan."""
        self._last_device_signature = None  # Force re-evaluation
        threading.Thread(target=self._manual_refresh_thread, daemon=True).start()

    def _manual_refresh_thread(self):
        GLOBAL_LOGGER.info("Scanning for connected Android devices via ADB...")
        self._check_device_change(is_manual=True)

    def _auto_detect_worker(self):
        """Continuous background monitor detecting USB plug/unplug events & auto-connecting."""
        time.sleep(0.5)
        retry_locate_counter = 0
        while self._running:
            try:
                # If ADB was not located on initial launch, retry locating it
                if not self.adb.adb_path or self.adb.adb_path == "adb":
                    retry_locate_counter += 1
                    if retry_locate_counter >= 3:
                        retry_locate_counter = 0
                        self.adb.locate_adb()

                if self.auto_detect_enabled and not self.is_scanning:
                    self._check_device_change(is_manual=False)
            except Exception:
                pass
            time.sleep(1.8)

    def _check_device_change(self, is_manual: bool = False):
        """Query ADB devices and fire events upon connection, disconnection, or state transition."""
        devices = self.adb.scan_devices(silent=not is_manual)
        current_sig = tuple((d["serial"], d["status"]) for d in devices)

        if is_manual or current_sig != self._last_device_signature:
            self._last_device_signature = current_sig
            self._on_device_state_changed(devices, is_manual=is_manual)

    def _on_device_state_changed(self, devices: list, is_manual: bool = False):
        """Handle device connect, disconnect, or authorization transitions."""
        if not devices:
            was_connected = (self.device_status in ["device", "unauthorized", "offline"])
            self.device_status = "disconnected"
            self.adb.selected_device = None
            self.update_status_badge("DISCONNECTED", THEME["status_disconnected"])
            if was_connected or is_manual:
                if was_connected:
                    GLOBAL_LOGGER.warning("🔌 [AUTO-DETECT] Android device unplugged / disconnected.")
                else:
                    # Check if device is physically detected by Windows USB layer
                    hw = self.adb.check_physical_usb_hardware()
                    if hw.get("android_match"):
                        GLOBAL_LOGGER.warning(f"📱 [HARDWARE DETECTED] {hw['vendor_name']} device is physically plugged into USB!")
                        GLOBAL_LOGGER.warning("⚠️ ADB cannot establish connection yet. Possible causes:")
                        GLOBAL_LOGGER.warning("   1. Phone USB mode is set to 'Charging only'. (Swipe down phone notifications -> tap USB notification -> switch to 'File Transfer' / MTP).")
                        GLOBAL_LOGGER.warning("   2. USB Debugging is not enabled on phone (Settings -> Developer Options -> Turn ON USB Debugging).")
                        GLOBAL_LOGGER.warning("   3. Android USB driver missing (Click 'Auto-Install Drivers' button above).")
                    else:
                        GLOBAL_LOGGER.warning("No Android device detected on USB. Check USB cable (use a Data Cable, not charge-only cable) and phone port.")
            self.device_data = {}
            self.after(0, lambda: self.pages["device_info"].update_view({}))
            self.after(0, lambda: self.pages["dashboard"].update_stats({}, self.audit_data, self.malware_data, self.app_inventory))
        else:
            first = devices[0]
            status = first.get("status")
            serial = first.get("serial")
            model = first.get("model", "Device")
            self.adb.selected_device = serial

            if status == "device":
                prev_status = self.device_status
                self.device_status = "device"
                self.update_status_badge(f"CONNECTED: {model}", THEME["status_connected"])

                if prev_status != "device" or is_manual:
                    GLOBAL_LOGGER.success(f"🔌 [AUTO-DETECT] Android device connected via USB: {model} [{serial}]")
                    GLOBAL_LOGGER.info("⚡ [AUTO-CONNECT] Automatically reading hardware, battery & OS forensics...")
                    try:
                        self.bell()  # subtle system alert sound
                    except Exception:
                        pass

                # Automatically collect initial hardware telemetry on connect!
                self._collect_device_data()

            elif status == "unauthorized":
                self.device_status = "unauthorized"
                self.update_status_badge("UNAUTHORIZED", THEME["status_unauthorized"])
                GLOBAL_LOGGER.warning(f"⚠️ [AUTO-DETECT] Phone [{serial}] detected via USB, but UNAUTHORIZED! Please unlock screen and tap 'ALLOW USB DEBUGGING'.")
                self.after(0, lambda: self.pages["dashboard"].update_stats(self.device_data, self.audit_data, self.malware_data, self.app_inventory))

            elif status == "offline":
                self.device_status = "offline"
                self.update_status_badge("OFFLINE", THEME["status_unauthorized"])
                GLOBAL_LOGGER.warning(f"⚠️ [AUTO-DETECT] Device [{serial}] is OFFLINE. Reconnect USB cable or check connection.")
                self.after(0, lambda: self.pages["dashboard"].update_stats(self.device_data, self.audit_data, self.malware_data, self.app_inventory))

            else:
                self.device_status = status
                self.update_status_badge(status.upper(), THEME["text_dim"])

    def run_driver_installer_gui(self):
        """Interactive 1-Click driver installer with background progress and notification."""
        def _worker():
            GLOBAL_LOGGER.info("Starting 1-Click Android USB Driver Installation...")
            success, msg = self.adb.auto_install_usb_driver()
            if success:
                messagebox.showinfo(
                    "Driver Installation Complete",
                    "✅ Android USB Drivers installed successfully!\n\n"
                    "Now please:\n"
                    "1. Unplug and replug your phone USB cable.\n"
                    "2. Ensure phone is in 'File Transfer' (MTP) mode.\n"
                    "3. Make sure 'USB Debugging' is enabled on phone.\n"
                    "4. Tap 'Allow' on your phone screen."
                )
                self.refresh_devices()
            else:
                messagebox.showerror("Driver Installation", f"Driver installation encountered an issue:\n{msg}")

        threading.Thread(target=_worker, daemon=True).start()

    def run_restart_adb_gui(self):
        """Restart ADB daemon server and refresh connections."""
        def _worker():
            self.adb.restart_adb_server()
            self.refresh_devices()
        threading.Thread(target=_worker, daemon=True).start()

    def run_hardware_diagnostic_gui(self):
        """Diagnose physical USB and ADB state."""
        def _worker():
            GLOBAL_LOGGER.info("Running Hardware USB & ADB Diagnostic Scan...")
            hw = self.adb.check_physical_usb_hardware()
            adb_ok, adb_ver = self.adb.check_adb_version()
            
            lines = [
                "=== HARDWARE & USB DIAGNOSTIC RESULTS ===",
                f"ADB Binary Status : {'OPERATIONAL (' + adb_ver + ')' if adb_ok else 'FAILED / MISSING'}",
                f"Active ADB Path   : {self.adb.adb_path}",
                f"USB Ports Active  : {'YES' if hw['has_usb_device'] else 'NO'}",
                f"Android Vendor HW : {'DETECTED: ' + hw['vendor_name'] if hw['android_match'] else 'NO ANDROID USB MATCH'}"
            ]
            if hw["devices"]:
                for d in hw["devices"]:
                    lines.append(f"  * {d['vendor']} (VID: {d['vid']}, PID: {d['pid']})")

            lines.extend([
                "=========================================",
                "DIAGNOSTIC RECOMMENDATION:",
            ])
            if hw["android_match"] and not self.adb.devices:
                lines.append("• Phone IS physically connected to PC, but ADB cannot see it.")
                lines.append("• Pull down notification on phone -> select 'File Transfer (MTP)'.")
                lines.append("• Enable 'USB Debugging' in Settings -> Developer Options.")
                lines.append("• Click 'Auto-Install Drivers' above if driver was never installed.")
            elif not hw["has_usb_device"]:
                lines.append("• No USB devices detected. Verify USB data cable connection.")
            else:
                lines.append("• If phone is plugged in, verify USB cable has data transfer pins.")

            full_msg = "\n".join(lines)
            GLOBAL_LOGGER.info(full_msg)
            messagebox.showinfo("USB Hardware Diagnostic", full_msg)

        threading.Thread(target=_worker, daemon=True).start()

    def update_status_badge(self, text: str, color: str):
        self.after(0, lambda: self.lbl_status_badge.config(text=text, bg=color))

    def _on_close(self):
        """Clean shutdown of background threads and window."""
        self._running = False
        self.destroy()

    def open_html_report(self):
        """Generate and launch live HTML report dossier in default browser."""
        try:
            html_content = ReportGenerator.generate_html(
                self.device_data,
                self.audit_data,
                self.malware_data,
                self.app_inventory,
                self.storage_files
            )
            out_file = ReportGenerator.get_default_report_path()
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            GLOBAL_LOGGER.success(f"Generated Live HTML Dossier: {out_file}")
            webbrowser.open_new_tab(f"file:///{os.path.abspath(out_file).replace(os.sep, '/')}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate HTML report: {str(e)}")

    def connect_wireless_gui(self):
        """Open dialog for connecting to device over Wi-Fi / IP (Wireless ADB)."""
        win = tk.Toplevel(self)
        win.title("📶 Wireless ADB Connect")
        win.geometry("450x230")
        win.configure(bg=THEME["bg_card"])
        win.resizable(False, False)

        tk.Label(win, text="CONNECT OVER WI-FI (WIRELESS ADB)", font=(FONT_FAMILY, 11, "bold"), fg=THEME["accent_green"], bg=THEME["bg_card"]).pack(anchor="w", padx=20, pady=(18, 4))
        tk.Label(win, text="Connect any Android phone (Android 11-15 Wireless Debugging or port 5555) without a USB cable:", font=(FONT_FAMILY, 9), fg=THEME["text_secondary"], bg=THEME["bg_card"], wraplength=410, justify="left").pack(anchor="w", padx=20, pady=(0, 12))

        entry_frame = tk.Frame(win, bg=THEME["bg_card"])
        entry_frame.pack(fill="x", padx=20, pady=4)

        tk.Label(entry_frame, text="IP:Port :", font=(FONT_FAMILY, 9, "bold"), fg=THEME["text_primary"], bg=THEME["bg_card"]).pack(side="left", padx=(0, 10))
        ip_entry = tk.Entry(entry_frame, bg=THEME["bg_input"], fg=THEME["accent_cyan"], font=(FONT_MONO, 10), relief="flat", highlightbackground=THEME["border"], highlightthickness=1)
        ip_entry.insert(0, "192.168.1.100:5555")
        ip_entry.pack(side="left", fill="x", expand=True)

        status_lbl = tk.Label(win, text="Ensure phone and PC are connected to the same Wi-Fi network.", font=(FONT_FAMILY, 8), fg=THEME["text_dim"], bg=THEME["bg_card"])
        status_lbl.pack(anchor="w", padx=20, pady=4)

        def _do_connect():
            ip_val = ip_entry.get().strip()
            status_lbl.config(text=f"Connecting to {ip_val}...", fg=THEME["accent_cyan"])
            def _th():
                success, msg = self.adb.connect_wireless(ip_val)
                if success:
                    self.after(0, lambda: status_lbl.config(text="CONNECTED SUCCESSFULLY!", fg=THEME["accent_green"]))
                    self.after(0, self.refresh_devices)
                    self.after(600, win.destroy)
                else:
                    self.after(0, lambda: status_lbl.config(text=f"Failed: {msg[:45]}", fg=THEME["accent_red"]))
            threading.Thread(target=_th, daemon=True).start()

        btn_row = tk.Frame(win, bg=THEME["bg_card"])
        btn_row.pack(fill="x", padx=20, pady=12)

        tk.Button(btn_row, text="⚡ Connect Now", font=(FONT_FAMILY, 9, "bold"), bg=THEME["accent_green"], fg="#000000", relief="flat", padx=14, pady=5, cursor="hand2", command=_do_connect).pack(side="left", padx=(0, 10))
        tk.Button(btn_row, text="Cancel", font=(FONT_FAMILY, 9), bg=THEME["bg_card_alt"], fg=THEME["text_secondary"], relief="flat", padx=10, pady=5, cursor="hand2", command=win.destroy).pack(side="left")

    def _collect_device_data(self):
        """Collect core hardware properties and telemetry non-intrusively."""
        props = self.adb.get_system_properties()
        battery = self.adb.get_battery_info()
        display = self.adb.get_display_info()
        memory = self.adb.get_memory_info()
        storage = self.adb.get_storage_info()
        uptime = self.adb.get_uptime()
        kernel = self.adb.get_kernel_version()
        root_info = self.adb.check_root_indicators(props)
        selinux = self.adb.get_selinux_mode()
        sec_settings = self.adb.get_security_settings()

        self.device_data = {
            "properties": props,
            "battery": battery,
            "display": display,
            "memory": memory,
            "storage": storage,
            "uptime": uptime,
            "kernel": kernel,
            "root_info": root_info,
            "selinux": selinux,
            "security_settings": sec_settings
        }

        self.after(0, lambda: self.pages["device_info"].update_view(self.device_data))
        self.after(0, lambda: self.pages["dashboard"].update_stats(self.device_data, self.audit_data, self.malware_data, self.app_inventory))

    # --------------------------------------------------------------------------
    # FORENSIC SCAN ORCHESTRATION
    # --------------------------------------------------------------------------
    def start_full_scan(self):
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "A forensic scan is already actively running.")
            return
        if self.device_status != "device":
            messagebox.showwarning("Device Not Ready", "Please connect an authorized Android device before initiating a scan.")
            return

        self.is_scanning = True
        threading.Thread(target=self._full_scan_worker, daemon=True).start()

    def start_quick_audit(self):
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "A diagnostic scan is already actively running.")
            return
        if self.device_status != "device":
            messagebox.showwarning("Device Not Ready", "Please connect an authorized Android device before initiating an audit.")
            return

        self.is_scanning = True
        threading.Thread(target=self._quick_audit_worker, daemon=True).start()

    def _set_progress(self, percent: int, text: str):
        self.after(0, lambda: self.pages["dashboard"].progress_bar.config(value=percent))
        self.after(0, lambda: self.pages["dashboard"].prog_lbl.config(text=f"Scan Progress: {text} ({percent}%)"))

    def _full_scan_worker(self):
        try:
            GLOBAL_LOGGER.info("Starting Full Forensic & Security Scan...")
            self._set_progress(5, "Acquiring Device Properties")
            self._collect_device_data()

            self._set_progress(20, "Cataloging Installed Applications")
            raw_packages = self.adb.list_installed_packages()
            GLOBAL_LOGGER.info(f"Discovered {len(raw_packages)} installed packages on device.")

            # Inspect deep details for user applications & sampling of system apps
            self._set_progress(40, "Auditing Application Permissions")
            detailed_apps = []
            user_apps = [p for p in raw_packages if not p["is_system"]]
            sys_apps = [p for p in raw_packages if p["is_system"]][:30] # Sample first 30 system apps for efficiency
            target_list = user_apps + sys_apps

            total_targets = len(target_list)
            for idx, p in enumerate(target_list):
                deep = self.adb.get_package_deep_info(p["package_name"])
                deep["is_system"] = p["is_system"]
                deep["type"] = p["type"]
                deep["apk_path"] = p["apk_path"]
                detailed_apps.append(deep)

                if idx % 10 == 0 and total_targets > 0:
                    pct = 40 + int((idx / total_targets) * 25)
                    self._set_progress(pct, f"Inspecting Apps ({idx}/{total_targets})")

            self.app_inventory = detailed_apps
            self.after(0, lambda: self.pages["applications"].update_packages(self.app_inventory))

            # Run Security Audit
            self._set_progress(70, "Executing Security Audit Engine")
            self.audit_data = SecurityAuditEngine.audit(self.device_data, self.app_inventory)
            self.after(0, lambda: self.pages["security_audit"].update_audit(self.audit_data))
            GLOBAL_LOGGER.audit(f"Security Audit Complete: Score {self.audit_data.get('score')}/100, Grade {self.audit_data.get('grade')}")

            # Run Malware Indicator Scanner
            self._set_progress(85, "Evaluating Malware Threat Indicators")
            malware_results = []
            for app in self.app_inventory:
                threat = MalwareScannerEngine.inspect_package(app)
                malware_results.append(threat)

            self.malware_data = {"results": malware_results}
            self.after(0, lambda: self.pages["malware_scanner"].update_scan(self.malware_data))

            # Scan Public Storage Artifacts
            self._set_progress(95, "Inspecting Accessible Storage Artifacts")
            self.storage_files = self.adb.scan_storage_directory("/sdcard/Download")
            self.after(0, lambda: self.pages["file_forensics"].update_files(self.storage_files))

            # Update Report & Dashboard
            self._set_progress(100, "Scan Complete")
            self.after(0, lambda: self.pages["dashboard"].update_stats(self.device_data, self.audit_data, self.malware_data, self.app_inventory))
            self.after(0, lambda: self.pages["report"].update_preview())
            
            # Auto-generate Live HTML Forensic Report
            try:
                html_report = ReportGenerator.generate_html(self.device_data, self.audit_data, self.malware_data, self.app_inventory, self.storage_files)
                report_path = ReportGenerator.get_default_report_path()
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(html_report)
                GLOBAL_LOGGER.success(f"🌐 Branded HTML Forensic Dossier auto-saved to {report_path}")
            except Exception:
                pass

            GLOBAL_LOGGER.success("Full Forensic Scan successfully concluded.")

        except Exception as e:
            GLOBAL_LOGGER.error(f"Error during forensic scan: {str(e)}")
        finally:
            self.is_scanning = False

    def _quick_audit_worker(self):
        try:
            GLOBAL_LOGGER.info("Starting Quick Security Audit...")
            self._set_progress(10, "Acquiring System Metrics")
            self._collect_device_data()

            self._set_progress(40, "Scanning User Applications")
            raw_packages = self.adb.list_installed_packages()
            user_apps = [p for p in raw_packages if not p["is_system"]][:30]

            detailed_apps = []
            for p in user_apps:
                deep = self.adb.get_package_deep_info(p["package_name"])
                deep["is_system"] = p["is_system"]
                deep["type"] = p["type"]
                deep["apk_path"] = p["apk_path"]
                detailed_apps.append(deep)

            self.app_inventory = detailed_apps
            self.after(0, lambda: self.pages["applications"].update_packages(self.app_inventory))

            self._set_progress(75, "Scoring Security Posture")
            self.audit_data = SecurityAuditEngine.audit(self.device_data, self.app_inventory)
            self.after(0, lambda: self.pages["security_audit"].update_audit(self.audit_data))

            self._set_progress(90, "Evaluating Threat Heuristics")
            malware_results = [MalwareScannerEngine.inspect_package(app) for app in self.app_inventory]
            self.malware_data = {"results": malware_results}
            self.after(0, lambda: self.pages["malware_scanner"].update_scan(self.malware_data))

            self._set_progress(100, "Audit Complete")
            self.after(0, lambda: self.pages["dashboard"].update_stats(self.device_data, self.audit_data, self.malware_data, self.app_inventory))
            self.after(0, lambda: self.pages["report"].update_preview())

            # Auto-generate Live HTML Forensic Report
            try:
                html_report = ReportGenerator.generate_html(self.device_data, self.audit_data, self.malware_data, self.app_inventory, self.storage_files)
                report_path = ReportGenerator.get_default_report_path()
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(html_report)
                GLOBAL_LOGGER.success(f"🌐 Branded HTML Forensic Dossier auto-saved to {report_path}")
            except Exception:
                pass

            GLOBAL_LOGGER.success("Quick Security Audit completed.")

        except Exception as e:
            GLOBAL_LOGGER.error(f"Error during quick audit: {str(e)}")
        finally:
            self.is_scanning = False

    def run_storage_scan(self, path: str):
        if self.device_status != "device":
            messagebox.showwarning("Device Disconnected", "Please connect an authorized device to inspect storage.")
            return
        threading.Thread(target=self._storage_scan_worker, args=(path,), daemon=True).start()

    def _storage_scan_worker(self, path: str):
        GLOBAL_LOGGER.info(f"Inspecting storage directory: {path}")
        files = self.adb.scan_storage_directory(path)
        self.storage_files = files
        self.after(0, lambda: self.pages["file_forensics"].update_files(files))
        GLOBAL_LOGGER.success(f"Enumerated {len(files)} files in {path}")

# ==============================================================================
# APPLICATION ENTRY POINT
# ==============================================================================
def main():
    app = ScitbossApp()
    app.mainloop()

if __name__ == "__main__":
    main()
