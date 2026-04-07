# ⚡ USBGuard — HID-Injection Detection & USB Whitelisting

**Schutz gegen BadUSB / Rubber Ducky / O.MG Cable Angriffe**

---

## Architektur

```
usb_guard/
├── usb_guard_core.py   — Backend-Engine (Monitor, Watcher, DB, Scanner)
├── usb_guard_gui.py    — CustomTkinter-Dashboard (Hauptprogramm)
├── run_usbguard.sh     — Start- & Installationsskript
└── README.md
```

### Komponenten

| Klasse | Aufgabe |
|---|---|
| `DeviceMonitor` | pyudev-basiertes Hot-Plug Monitoring, orchestriert alles |
| `HIDWatcher` | evdev-Loop pro Gerät, zeichnet alle Keystrokes auf |
| `WhitelistDB` | JSON-Persistenz + JSONL-Event-Log |
| `USBScanner` | lsusb / sysfs / evdev-Scans |
| `analyze_risk()` | Heuristik: VID-Blacklist, HID+Storage-Combo, fehlende Strings |

---

## Features

### 🔌 Geräteerkennung
- Erkennt alle USB-Geräte beim Einstecken via udev
- Klassifiziert: HID (Tastatur/Maus), Mass Storage, Combo
- Berechnet SHA-256 Fingerprint (VID+PID+Serial+Hersteller+Produkt)

### ⚠ Whitelist-Dialog
- Pop-up bei jedem **unbekannten** Gerät
- Zeigt Risiko-Analyse mit Flags
- Entscheidung: Erlauben / Blockieren / Ignorieren
- Entscheidung wird persistent gespeichert

### ⌨ Keystroke-Monitoring (HID-Watcher)
- Nur für whitelisted Geräte aktiv
- Zeichnet Key-Down-Events mit Zeitstempel auf
- WPM-Schätzung in Echtzeit
- **Automatischer Alert bei >600 WPM** (BadUSB-Indikator: >1000 WPM normal)
- Farbcodierte Darstellung: Buchstaben / Spezial-Keys / Modifier

### 🔍 Scan-Modi
| Scan | Beschreibung |
|---|---|
| `lsusb` | USB-Descriptor Dump (Interfaces, Klassen, Protocol) |
| `sysfs` | Kernel-Attribute: Speed, MaxPower, NumInterfaces, bcdUSB |
| `HID-Interfaces` | Registrierte evdev-Devices + Capabilities |
| `Risiko` | Heuristik: VID-Blacklist, Combo-Muster, String-Analyse |
| `Vollscan` | Alle obigen kombiniert |

### 🚨 Risiko-Heuristik
| Indikator | Score |
|---|---|
| Bekannte BadUSB-VID (Rubber Ducky etc.) | +40 |
| HID + Mass Storage Kombination | +50 |
| HID mit unbekannter VID | +20 |
| Kein Hersteller/Produktstring | +15 |
| Generischer Herstellername | +10 |
| Bekannter Hersteller (Logitech, MS…) | -20 |

Score → SAFE / LOW / MEDIUM / HIGH / CRITICAL

---

## Installation & Start

### Schnellstart (eingeschränkt, kein Root)
```bash
pip install pyudev evdev customtkinter pillow
python3 usb_guard_gui.py
```

### Vollständig (mit HID-Monitoring)
```bash
# udev-Regel installieren (einmalig)
sudo bash run_usbguard.sh --install

# Dann als normaler User:
bash run_usbguard.sh

# Oder mit Root für direkten Zugriff:
sudo python3 usb_guard_gui.py
```

### udev-Regel (manuell)
```
# /etc/udev/rules.d/99-usbguard-input.rules
KERNEL=="event*", SUBSYSTEM=="input", GROUP="input", MODE="0660"
```
```bash
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo usermod -aG input $USER
# Neu anmelden!
```

---

## Log-Dateien

Alle Daten werden unter `~/.usbguard/` gespeichert:

| Datei | Inhalt |
|---|---|
| `whitelist.json` | Geräte-Datenbank mit Status und Fingerprints |
| `keystroke_events.jsonl` | Alle aufgezeichneten Keystrokes (JSONL) |
| `device_history.jsonl` | Connect/Disconnect-Events |
| `usbguard.log` | Debug-Log |

---

## Bekannte Einschränkungen

- **Root oder input-Gruppe** notwendig für `/dev/input/eventX` Zugriff
- `lsusb -v` benötigt Root für vollständige Descriptor-Ausgabe
- HID-Device-Path-Matching über Produktnamen (Heuristik, nicht deterministisch)
- Auf **Windows** muss das Backend durch WMI/pywinusb ersetzt werden

---

## Erweiterungsideen

- [ ] Windows-Backend (WMI + pynput)
- [ ] Netzwerk-Alert (Syslog / Webhook)
- [ ] Automatisches Blockieren bei CRITICAL-Risk
- [ ] Integration mit systemd `usbguard` Daemon
- [ ] Export-Funktion (CSV / PDF-Report)
- [ ] Timing-Analyse: Tastenintervall-Histogram pro Session
