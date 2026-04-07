"""
USBGuard Core Engine
====================
HID-Injection Detection & USB Whitelisting System
Für SOC/Pentest-Umgebungen - erkennt BadUSB/Rubber Ducky Angriffe

Architektur:
  - DeviceMonitor: pyudev-basiertes Hot-Plug Monitoring
  - HIDWatcher:    evdev-basiertes Keystroke-Recording pro Gerät
  - WhitelistDB:   JSON-basierte Persistenz mit Hash-Fingerprinting
  - EventBus:      Thread-safe Callback-System für GUI-Updates
"""

import os
import json
import time
import hashlib
import threading
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Optional, Callable
from enum import Enum

try:
    import pyudev
    PYUDEV_OK = True
except ImportError:
    PYUDEV_OK = False

try:
    import evdev
    from evdev import InputDevice, categorize, ecodes
    EVDEV_OK = True
except ImportError:
    EVDEV_OK = False

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_DIR = Path.home() / ".usbguard"
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "usbguard.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("USBGuard")

# ── Datenstrukturen ───────────────────────────────────────────────────────────
class DeviceStatus(Enum):
    PENDING    = "PENDING"
    WHITELISTED = "WHITELISTED"
    BLOCKED    = "BLOCKED"
    SCANNING   = "SCANNING"

class RiskLevel(Enum):
    SAFE     = "SAFE"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class KeystrokeEvent:
    timestamp: str
    device_id: str
    device_name: str
    key: str
    key_code: int
    event_type: str  # KEY_DOWN / KEY_UP
    wpm_estimate: float = 0.0
    raw: str = ""

    def to_dict(self):
        return asdict(self)

@dataclass
class USBDevice:
    device_id: str          # VID:PID
    vid: str
    pid: str
    manufacturer: str
    product: str
    serial: str
    bus_path: str
    first_seen: str
    last_seen: str
    status: DeviceStatus = DeviceStatus.PENDING
    risk_level: RiskLevel = RiskLevel.SAFE
    is_hid: bool = False
    is_mass_storage: bool = False
    hid_device_path: Optional[str] = None
    fingerprint: str = ""
    keystroke_count: int = 0
    flags: list = field(default_factory=list)  # BadUSB-Indikatoren

    def to_dict(self):
        d = asdict(self)
        d["status"] = self.status.value
        d["risk_level"] = self.risk_level.value
        return d

    @classmethod
    def from_dict(cls, d):
        d["status"] = DeviceStatus(d.get("status", "PENDING"))
        d["risk_level"] = RiskLevel(d.get("risk_level", "SAFE"))
        return cls(**d)

# ── Whitelist-Datenbank ───────────────────────────────────────────────────────
class WhitelistDB:
    DB_PATH = LOG_DIR / "whitelist.json"
    KEYSTROKE_LOG = LOG_DIR / "keystroke_events.jsonl"
    DEVICE_LOG    = LOG_DIR / "device_history.jsonl"

    def __init__(self):
        self._lock = threading.Lock()
        self._db: dict[str, dict] = {}
        self._load()

    def _load(self):
        if self.DB_PATH.exists():
            try:
                with open(self.DB_PATH) as f:
                    self._db = json.load(f)
                log.info(f"Whitelist geladen: {len(self._db)} Einträge")
            except Exception as e:
                log.error(f"Whitelist-Ladefehler: {e}")
                self._db = {}

    def _save(self):
        try:
            with open(self.DB_PATH, "w") as f:
                json.dump(self._db, f, indent=2, ensure_ascii=False)
        except Exception as e:
            log.error(f"Whitelist-Speicherfehler: {e}")

    def get_device(self, fingerprint: str) -> Optional[USBDevice]:
        with self._lock:
            data = self._db.get(fingerprint)
            if data:
                return USBDevice.from_dict(data.copy())
        return None

    def set_status(self, fingerprint: str, status: DeviceStatus, device: Optional[USBDevice] = None):
        with self._lock:
            if device and fingerprint not in self._db:
                self._db[fingerprint] = device.to_dict()
            if fingerprint in self._db:
                self._db[fingerprint]["status"] = status.value
                self._db[fingerprint]["last_seen"] = datetime.now().isoformat()
                self._save()

    def get_all(self) -> list[USBDevice]:
        with self._lock:
            return [USBDevice.from_dict(v.copy()) for v in self._db.values()]

    def delete(self, fingerprint: str):
        with self._lock:
            self._db.pop(fingerprint, None)
            self._save()

    def log_keystroke(self, event: KeystrokeEvent):
        try:
            with open(self.KEYSTROKE_LOG, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as e:
            log.error(f"Keystroke-Log-Fehler: {e}")

    def get_keystrokes(self, device_id: Optional[str] = None, limit: int = 500) -> list[dict]:
        events = []
        if not self.KEYSTROKE_LOG.exists():
            return events
        try:
            with open(self.KEYSTROKE_LOG) as f:
                lines = f.readlines()
            for line in reversed(lines[-limit*2:]):
                try:
                    ev = json.loads(line.strip())
                    if device_id is None or ev.get("device_id") == device_id:
                        events.append(ev)
                        if len(events) >= limit:
                            break
                except Exception:
                    pass
        except Exception as e:
            log.error(f"Keystroke-Read-Fehler: {e}")
        return list(reversed(events))

    def log_device_event(self, action: str, device: USBDevice):
        try:
            entry = {"action": action, "timestamp": datetime.now().isoformat(), **device.to_dict()}
            with open(self.DEVICE_LOG, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            log.error(f"Device-Log-Fehler: {e}")

# ── Fingerprinting ────────────────────────────────────────────────────────────
def make_fingerprint(vid: str, pid: str, serial: str, manufacturer: str, product: str) -> str:
    raw = f"{vid}:{pid}:{serial}:{manufacturer}:{product}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

# ── Risiko-Analyse ────────────────────────────────────────────────────────────
KNOWN_BADUSB_VIDS = {
    "1b4f": "SparkFun (häufig für BadUSB-Prototypen)",
    "16c0": "VOTI / Rubber Ducky Klon",
    "1781": "Multiple HID-Exploit-Geräte",
    "04d8": "Microchip (oft für HID-Angriffe missbraucht)",
    "f1d0": "USB Ninja / O.MG Cable VID",
    "1209": "Generic / pid.codes (oft DIY-BadUSB)",
}

KNOWN_SAFE_VIDS = {
    "045e": "Microsoft",
    "046d": "Logitech",
    "05ac": "Apple",
    "0461": "Primax (Dell/HP Keyboards)",
    "413c": "Dell",
    "03f0": "HP",
    "17ef": "Lenovo",
    "0bda": "Realtek (USB-Hubs)",
    "058f": "Alcor Micro (Card Reader)",
    "0781": "SanDisk",
    "090c": "Silicon Motion (USB-Sticks)",
    "1307": "Transcend",
}

def analyze_risk(device: USBDevice) -> tuple[RiskLevel, list[str]]:
    """Heuristik-basierte Risikoanalyse für HID-Injection."""
    flags = []
    score = 0

    # Bekannte BadUSB-VIDs
    if device.vid.lower() in KNOWN_BADUSB_VIDS:
        flags.append(f"⚠ Bekannte BadUSB-VID: {KNOWN_BADUSB_VIDS[device.vid.lower()]}")
        score += 40

    # Unbekannte VID + HID-Gerät
    if device.is_hid and device.vid.lower() not in KNOWN_SAFE_VIDS:
        flags.append("⚠ HID-Gerät mit unbekannter VID")
        score += 20

    # HID + Mass-Storage Kombination (klassisches BadUSB-Muster)
    if device.is_hid and device.is_mass_storage:
        flags.append("🔴 KRITISCH: HID + Mass-Storage Kombination (BadUSB-Muster!)")
        score += 50

    # Kein Hersteller/Produkt-String
    if not device.manufacturer and not device.product:
        flags.append("⚠ Keine Herstellerinfo (häufig bei gefälschten Geräten)")
        score += 15

    # Generische / leere Strings
    if device.manufacturer.lower() in ("", "unknown", "generic", "usb device"):
        flags.append("⚠ Generischer Herstellername")
        score += 10

    # Kein Serial bei HID
    if device.is_hid and not device.serial:
        flags.append("ℹ Kein Serial Number bei HID-Gerät")
        score += 5

    # Bekannter sicherer Hersteller
    if device.vid.lower() in KNOWN_SAFE_VIDS:
        flags.append(f"✓ Bekannter Hersteller: {KNOWN_SAFE_VIDS[device.vid.lower()]}")
        score = max(0, score - 20)

    if score >= 60:
        return RiskLevel.CRITICAL, flags
    elif score >= 40:
        return RiskLevel.HIGH, flags
    elif score >= 20:
        return RiskLevel.MEDIUM, flags
    elif score >= 5:
        return RiskLevel.LOW, flags
    else:
        return RiskLevel.SAFE, flags

# ── HID Keystroke Watcher ─────────────────────────────────────────────────────
class HIDWatcher(threading.Thread):
    """Überwacht ein evdev HID-Gerät und zeichnet alle Tastendrücke auf."""

    KEYMAP = {
        # Basis-Mapping für Visualisierung
        "KEY_A": "a", "KEY_B": "b", "KEY_C": "c", "KEY_D": "d",
        "KEY_E": "e", "KEY_F": "f", "KEY_G": "g", "KEY_H": "h",
        "KEY_I": "i", "KEY_J": "j", "KEY_K": "k", "KEY_L": "l",
        "KEY_M": "m", "KEY_N": "n", "KEY_O": "o", "KEY_P": "p",
        "KEY_Q": "q", "KEY_R": "r", "KEY_S": "s", "KEY_T": "t",
        "KEY_U": "u", "KEY_V": "v", "KEY_W": "w", "KEY_X": "x",
        "KEY_Y": "y", "KEY_Z": "z",
        "KEY_1": "1", "KEY_2": "2", "KEY_3": "3", "KEY_4": "4",
        "KEY_5": "5", "KEY_6": "6", "KEY_7": "7", "KEY_8": "8",
        "KEY_9": "9", "KEY_0": "0",
        "KEY_SPACE": "[SPACE]", "KEY_ENTER": "[ENTER]",
        "KEY_BACKSPACE": "[BS]", "KEY_TAB": "[TAB]",
        "KEY_LEFTSHIFT": "[LSHIFT]", "KEY_RIGHTSHIFT": "[RSHIFT]",
        "KEY_LEFTCTRL": "[LCTRL]", "KEY_RIGHTCTRL": "[RCTRL]",
        "KEY_LEFTALT": "[LALT]", "KEY_RIGHTALT": "[RALT]",
        "KEY_LEFTMETA": "[WIN]", "KEY_RIGHTMETA": "[WIN]",
        "KEY_ESC": "[ESC]", "KEY_DELETE": "[DEL]",
        "KEY_UP": "[↑]", "KEY_DOWN": "[↓]", "KEY_LEFT": "[←]", "KEY_RIGHT": "[→]",
        "KEY_F1": "[F1]", "KEY_F2": "[F2]", "KEY_F3": "[F3]", "KEY_F4": "[F4]",
        "KEY_F5": "[F5]", "KEY_F6": "[F6]", "KEY_F7": "[F7]", "KEY_F8": "[F8]",
        "KEY_F9": "[F9]", "KEY_F10": "[F10]", "KEY_F11": "[F11]", "KEY_F12": "[F12]",
        "KEY_MINUS": "-", "KEY_EQUAL": "=", "KEY_SLASH": "/",
        "KEY_DOT": ".", "KEY_COMMA": ",", "KEY_SEMICOLON": ";",
    }

    def __init__(self, device: USBDevice, db: WhitelistDB, on_keystroke: Callable, on_alert: Callable):
        super().__init__(daemon=True)
        self.device = device
        self.db = db
        self.on_keystroke = on_keystroke
        self.on_alert = on_alert
        self._stop_event = threading.Event()
        self._key_times: list[float] = []
        self.name = f"HIDWatcher-{device.device_id}"

    def stop(self):
        self._stop_event.set()

    def _estimate_wpm(self) -> float:
        now = time.time()
        self._key_times = [t for t in self._key_times if now - t < 10]
        self._key_times.append(now)
        if len(self._key_times) < 2:
            return 0.0
        duration = self._key_times[-1] - self._key_times[0]
        if duration < 0.1:
            return 0.0
        return (len(self._key_times) / 5) / (duration / 60)

    def run(self):
        if not EVDEV_OK or not self.device.hid_device_path:
            log.warning(f"HIDWatcher: evdev nicht verfügbar oder kein Pfad für {self.device.device_id}")
            return

        log.info(f"HIDWatcher gestartet: {self.device.hid_device_path}")
        try:
            dev = InputDevice(self.device.hid_device_path)
            for event in dev.read_loop():
                if self._stop_event.is_set():
                    break
                if event.type == ecodes.EV_KEY:
                    key_event = categorize(event)
                    key_name = ecodes.KEY.get(event.code, f"KEY_{event.code}")
                    if isinstance(key_name, list):
                        key_name = key_name[0]

                    event_type = {0: "KEY_UP", 1: "KEY_DOWN", 2: "KEY_HOLD"}.get(event.value, "UNKNOWN")
                    if event.value != 1:  # Nur Key-Down für WPM/Log
                        continue

                    wpm = self._estimate_wpm()
                    display_key = self.KEYMAP.get(key_name, f"[{key_name}]")

                    ks = KeystrokeEvent(
                        timestamp=datetime.now().isoformat(),
                        device_id=self.device.device_id,
                        device_name=self.device.product or self.device.device_id,
                        key=display_key,
                        key_code=event.code,
                        event_type=event_type,
                        wpm_estimate=round(wpm, 1),
                        raw=key_name,
                    )

                    # Hochgeschwindigkeits-Eingabe = BadUSB-Indikator
                    if wpm > 800:
                        self.on_alert(
                            self.device,
                            f"🔴 EXTREM HOHE EINGABEGESCHWINDIGKEIT: {wpm:.0f} WPM — mögliche HID-Injection!"
                        )

                    self.db.log_keystroke(ks)
                    self.on_keystroke(ks)
                    self.device.keystroke_count += 1

        except PermissionError:
            log.error(f"Kein Zugriff auf {self.device.hid_device_path} — Root/udev-Regel erforderlich")
            self.on_alert(self.device, f"⚠ Kein Zugriff auf HID-Device — Root-Rechte oder udev-Regel nötig")
        except Exception as e:
            if not self._stop_event.is_set():
                log.error(f"HIDWatcher-Fehler: {e}")

# ── USB Scanner ───────────────────────────────────────────────────────────────
class USBScanner:
    """Statische Scan-Methoden für USB-Geräte."""

    @staticmethod
    def scan_lsusb(device: USBDevice) -> dict:
        """Detaillierte lsusb-Ausgabe parsen."""
        result = {"raw": "", "interfaces": [], "class_info": []}
        try:
            out = subprocess.check_output(
                ["lsusb", "-v", "-d", f"{device.vid}:{device.pid}"],
                stderr=subprocess.DEVNULL, timeout=10
            ).decode(errors="replace")
            result["raw"] = out[:4000]

            # Interface-Klassen extrahieren
            for line in out.splitlines():
                line = line.strip()
                if "bInterfaceClass" in line:
                    result["interfaces"].append(line)
                if "bDeviceClass" in line or "bInterfaceProtocol" in line:
                    result["class_info"].append(line)
        except Exception as e:
            result["raw"] = f"lsusb nicht verfügbar oder Fehler: {e}"
        return result

    @staticmethod
    def scan_sysfs(device: USBDevice) -> dict:
        """sysfs-Informationen auslesen."""
        result = {}
        try:
            sysfs_base = Path(f"/sys/bus/usb/devices/")
            for dev_path in sysfs_base.iterdir():
                vid_f = dev_path / "idVendor"
                pid_f = dev_path / "idProduct"
                if vid_f.exists() and pid_f.exists():
                    vid = vid_f.read_text().strip()
                    pid = pid_f.read_text().strip()
                    if vid.lower() == device.vid.lower() and pid.lower() == device.pid.lower():
                        for attr in ["speed", "bMaxPower", "bNumInterfaces", "manufacturer",
                                     "product", "serial", "bcdUSB", "bDeviceClass"]:
                            attr_f = dev_path / attr
                            if attr_f.exists():
                                result[attr] = attr_f.read_text().strip()
                        break
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def scan_hid_interfaces(device: USBDevice) -> list[str]:
        """Prüft ob und welche HID-Interfaces registriert sind."""
        hid_devs = []
        if not EVDEV_OK:
            return ["evdev nicht installiert"]
        try:
            for d in evdev.list_devices():
                try:
                    dev = InputDevice(d)
                    # Vergleich über Name/Phys
                    if device.product and device.product.lower() in dev.name.lower():
                        caps = dev.capabilities(verbose=True)
                        cap_summary = []
                        for ev_type, events in caps.items():
                            cap_summary.append(f"{ev_type[0]}: {[e[0] for e in events[:5]]}")
                        hid_devs.append(f"{d} | {dev.name} | Caps: {'; '.join(cap_summary[:3])}")
                except Exception:
                    pass
        except Exception as e:
            hid_devs.append(f"Fehler: {e}")
        return hid_devs or ["Keine HID-Interfaces gefunden"]

    @staticmethod
    def check_usbguard_available() -> bool:
        try:
            subprocess.check_output(["which", "usbguard"], stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

# ── Device Monitor ────────────────────────────────────────────────────────────
class DeviceMonitor:
    """
    Hauptklasse: Überwacht USB-Events via pyudev.
    Meldet neue Geräte → Whitelist-Check → HIDWatcher starten.
    """

    def __init__(self):
        self.db = WhitelistDB()
        self._watchers: dict[str, HIDWatcher] = {}
        self._devices: dict[str, USBDevice] = {}
        self._lock = threading.Lock()
        self._running = False

        # Callbacks (werden von GUI gesetzt)
        self.on_device_added: Optional[Callable] = None
        self.on_device_removed: Optional[Callable] = None
        self.on_whitelist_request: Optional[Callable] = None
        self.on_keystroke: Optional[Callable] = None
        self.on_alert: Optional[Callable] = None
        self.on_status_change: Optional[Callable] = None

        self._monitor_thread: Optional[threading.Thread] = None

    def start(self):
        self._running = True
        self._load_existing_devices()
        if PYUDEV_OK:
            self._monitor_thread = threading.Thread(target=self._udev_loop, daemon=True)
            self._monitor_thread.start()
            log.info("USB-Monitor gestartet (pyudev)")
        else:
            log.warning("pyudev nicht verfügbar — nur manuelle Scans möglich")

    def stop(self):
        self._running = False
        for w in self._watchers.values():
            w.stop()

    def _load_existing_devices(self):
        """Bereits angeschlossene USB-Geräte beim Start inventarisieren."""
        if not PYUDEV_OK:
            return
        try:
            ctx = pyudev.Context()
            for udev_dev in ctx.list_devices(subsystem="usb", DEVTYPE="usb_device"):
                device = self._parse_udev_device(udev_dev)
                if device:
                    self._register_device(device, initial=True)
        except Exception as e:
            log.error(f"Initiales Gerätescan-Fehler: {e}")

    def _udev_loop(self):
        try:
            ctx = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(ctx)
            monitor.filter_by(subsystem="usb")
            for action, udev_dev in monitor:
                if not self._running:
                    break
                if udev_dev.device_type != "usb_device":
                    continue
                if action == "add":
                    device = self._parse_udev_device(udev_dev)
                    if device:
                        self._register_device(device)
                elif action == "remove":
                    dev_id = self._make_dev_id_from_udev(udev_dev)
                    self._unregister_device(dev_id)
        except Exception as e:
            log.error(f"udev-Loop-Fehler: {e}")

    def _parse_udev_device(self, udev_dev) -> Optional[USBDevice]:
        try:
            vid = (udev_dev.get("ID_VENDOR_ID") or "").lower().strip()
            pid = (udev_dev.get("ID_MODEL_ID") or "").lower().strip()
            if not vid or not pid:
                return None

            manufacturer = udev_dev.get("ID_VENDOR") or udev_dev.get("ID_VENDOR_FROM_DATABASE") or ""
            product      = udev_dev.get("ID_MODEL")  or udev_dev.get("ID_MODEL_FROM_DATABASE")  or ""
            serial       = udev_dev.get("ID_SERIAL_SHORT") or ""
            bus_path     = udev_dev.sys_path or ""

            # USB-Klassen ermitteln
            is_hid = False
            is_mass_storage = False
            hid_path = None

            try:
                ctx = pyudev.Context()
                for child in pyudev.Device.from_sys_path(ctx, bus_path).children:
                    cls = child.get("DEVTYPE", "")
                    drv = child.get("DRIVER", "")
                    if drv in ("usbhid", "hid"):
                        is_hid = True
                    if "input" in child.sys_path and EVDEV_OK:
                        for ed in evdev.list_devices():
                            try:
                                d = InputDevice(ed)
                                if product and product.lower() in d.name.lower():
                                    hid_path = ed
                            except Exception:
                                pass
                    usb_class = child.get("bInterfaceClass", "")
                    if usb_class == "08":
                        is_mass_storage = True
                    if usb_class == "03":
                        is_hid = True
            except Exception:
                pass

            fingerprint = make_fingerprint(vid, pid, serial, manufacturer, product)
            now = datetime.now().isoformat()

            device = USBDevice(
                device_id=f"{vid}:{pid}",
                vid=vid,
                pid=pid,
                manufacturer=manufacturer.replace("_", " "),
                product=product.replace("_", " "),
                serial=serial,
                bus_path=bus_path,
                first_seen=now,
                last_seen=now,
                is_hid=is_hid,
                is_mass_storage=is_mass_storage,
                hid_device_path=hid_path,
                fingerprint=fingerprint,
            )

            risk, flags = analyze_risk(device)
            device.risk_level = risk
            device.flags = flags
            return device

        except Exception as e:
            log.error(f"Parse-Fehler: {e}")
            return None

    def _make_dev_id_from_udev(self, udev_dev) -> str:
        vid = (udev_dev.get("ID_VENDOR_ID") or "").lower()
        pid = (udev_dev.get("ID_MODEL_ID") or "").lower()
        return f"{vid}:{pid}"

    def _register_device(self, device: USBDevice, initial: bool = False):
        with self._lock:
            # Whitelist prüfen
            existing = self.db.get_device(device.fingerprint)
            if existing:
                device.status = existing.status
                device.first_seen = existing.first_seen
            else:
                device.status = DeviceStatus.PENDING

            self._devices[device.fingerprint] = device
            self.db.log_device_event("connect", device)

        log.info(f"Gerät erkannt: {device.product or device.device_id} [{device.fingerprint}] Status={device.status.value}")

        if self.on_device_added:
            self.on_device_added(device)

        # Whitelist-Dialog anfragen
        if device.status == DeviceStatus.PENDING and not initial:
            if self.on_whitelist_request:
                self.on_whitelist_request(device)
        elif device.status == DeviceStatus.WHITELISTED and device.is_hid:
            self._start_hid_watcher(device)

    def _unregister_device(self, dev_id: str):
        with self._lock:
            # Finde Device per device_id
            found = None
            for fp, dev in self._devices.items():
                if dev.device_id == dev_id:
                    found = fp
                    break
            if found:
                device = self._devices.pop(found)
                self.db.log_device_event("disconnect", device)
                log.info(f"Gerät entfernt: {device.product or dev_id}")
                # HID-Watcher stoppen
                if found in self._watchers:
                    self._watchers[found].stop()
                    del self._watchers[found]
                if self.on_device_removed:
                    self.on_device_removed(device)

    def set_device_status(self, fingerprint: str, status: DeviceStatus):
        with self._lock:
            device = self._devices.get(fingerprint)
            if device:
                device.status = status
                self.db.set_status(fingerprint, status, device)
                log.info(f"Status gesetzt: {device.device_id} → {status.value}")
                if status == DeviceStatus.WHITELISTED and device.is_hid:
                    self._start_hid_watcher(device)
                elif status == DeviceStatus.BLOCKED:
                    if fingerprint in self._watchers:
                        self._watchers[fingerprint].stop()
                        del self._watchers[fingerprint]
                if self.on_status_change:
                    self.on_status_change(device)

    def _start_hid_watcher(self, device: USBDevice):
        if device.fingerprint in self._watchers:
            return
        if not device.hid_device_path:
            log.warning(f"Kein HID-Pfad für {device.device_id}, Watcher nicht gestartet")
            return

        watcher = HIDWatcher(
            device=device,
            db=self.db,
            on_keystroke=lambda ev: self.on_keystroke(ev) if self.on_keystroke else None,
            on_alert=lambda dev, msg: self.on_alert(dev, msg) if self.on_alert else None,
        )
        self._watchers[device.fingerprint] = watcher
        watcher.start()
        log.info(f"HID-Watcher gestartet für {device.product}")

    def get_connected_devices(self) -> list[USBDevice]:
        with self._lock:
            return list(self._devices.values())

    def scan_device(self, fingerprint: str, scan_type: str) -> dict:
        with self._lock:
            device = self._devices.get(fingerprint)
        if not device:
            # Versuche aus DB
            device = self.db.get_device(fingerprint)
        if not device:
            return {"error": "Gerät nicht gefunden"}

        scanner = USBScanner()
        if scan_type == "lsusb":
            return scanner.scan_lsusb(device)
        elif scan_type == "sysfs":
            return scanner.scan_sysfs(device)
        elif scan_type == "hid":
            return {"interfaces": scanner.scan_hid_interfaces(device)}
        elif scan_type == "risk":
            risk, flags = analyze_risk(device)
            return {"risk": risk.value, "flags": flags}
        elif scan_type == "full":
            return {
                "lsusb": scanner.scan_lsusb(device),
                "sysfs": scanner.scan_sysfs(device),
                "hid":   {"interfaces": scanner.scan_hid_interfaces(device)},
                "risk":  {"risk": analyze_risk(device)[0].value, "flags": analyze_risk(device)[1]},
            }
        return {"error": f"Unbekannter Scan-Typ: {scan_type}"}

# Singleton
_monitor: Optional[DeviceMonitor] = None

def get_monitor() -> DeviceMonitor:
    global _monitor
    if _monitor is None:
        _monitor = DeviceMonitor()
    return _monitor
