"""
USBGuard GUI
============
CustomTkinter-basiertes Dashboard für USB-Gerätekontrolle und HID-Monitoring.

Tabs:
  1. Dashboard     — Verbundene Geräte + Whitelist-Aktionen
  2. Keystroke Log — Zeitlicher Ablauf aller aufgezeichneten Eingaben
  3. Scanner       — lsusb / sysfs / HID / Risiko-Analyse
  4. Verlauf       — Alle Geräte-Events aus der Datenbank
  5. Einstellungen — Allgemeine Konfiguration
"""

import sys
import threading
import json
import time
from pathlib import Path
from datetime import datetime
from tkinter import messagebox, simpledialog
import tkinter as tk

try:
    import customtkinter as ctk
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
except ImportError:
    print("customtkinter nicht installiert: pip install customtkinter")
    sys.exit(1)

# Core importieren (im selben Verzeichnis)
sys.path.insert(0, str(Path(__file__).parent))
from usb_guard_core import (
    DeviceMonitor, DeviceStatus, RiskLevel, KeystrokeEvent,
    USBDevice, get_monitor, LOG_DIR, EVDEV_OK, PYUDEV_OK
)

# ── Farb-Konstanten ───────────────────────────────────────────────────────────
COLORS = {
    "bg_dark":     "#0d1117",
    "bg_card":     "#161b22",
    "bg_input":    "#21262d",
    "border":      "#30363d",
    "text_primary":"#e6edf3",
    "text_muted":  "#8b949e",
    "accent_blue": "#388bfd",
    "accent_cyan": "#39d353",
    "risk_safe":   "#3fb950",
    "risk_low":    "#d29922",
    "risk_medium": "#db6d28",
    "risk_high":   "#f85149",
    "risk_crit":   "#ff0000",
    "whitelisted": "#3fb950",
    "blocked":     "#f85149",
    "pending":     "#d29922",
    "scanning":    "#388bfd",
}

RISK_COLORS = {
    RiskLevel.SAFE:     COLORS["risk_safe"],
    RiskLevel.LOW:      COLORS["risk_low"],
    RiskLevel.MEDIUM:   COLORS["risk_medium"],
    RiskLevel.HIGH:     COLORS["risk_high"],
    RiskLevel.CRITICAL: COLORS["risk_crit"],
}

STATUS_COLORS = {
    DeviceStatus.PENDING:    COLORS["pending"],
    DeviceStatus.WHITELISTED:COLORS["whitelisted"],
    DeviceStatus.BLOCKED:    COLORS["blocked"],
    DeviceStatus.SCANNING:   COLORS["scanning"],
}

# ── Whitelist-Dialog ──────────────────────────────────────────────────────────
class WhitelistDialog(ctk.CTkToplevel):
    def __init__(self, parent, device: USBDevice, on_decision):
        super().__init__(parent)
        self.device = device
        self.on_decision = on_decision
        self.title("⚠ Neues USB-Gerät erkannt")
        self.geometry("560x480")
        self.configure(fg_color=COLORS["bg_dark"])
        self.resizable(False, False)
        self.grab_set()
        self.lift()
        self._build()

    def _build(self):
        risk_color = RISK_COLORS.get(self.device.risk_level, COLORS["text_muted"])
        d = self.device

        # Header
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="🔌  Neues USB-Gerät eingesteckt",
                     font=("Courier New", 16, "bold"),
                     text_color=COLORS["accent_blue"]).pack(pady=(16, 4))
        ctk.CTkLabel(hdr, text="Soll dieses Gerät mit dem System interagieren dürfen?",
                     font=("Courier New", 11), text_color=COLORS["text_muted"]).pack(pady=(0, 14))

        # Gerätinfo-Grid
        info = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=8, border_width=1,
                             border_color=COLORS["border"])
        info.pack(fill="x", padx=20, pady=10)

        rows = [
            ("Gerät",        f"{d.product or '(unbekannt)'}"),
            ("Hersteller",   f"{d.manufacturer or '(unbekannt)'}"),
            ("VID:PID",      f"{d.vid}:{d.pid}"),
            ("Serial",       d.serial or "(keiner)"),
            ("HID (Tastatur/Maus)", "✓ JA" if d.is_hid else "✗ Nein"),
            ("Mass Storage", "✓ JA" if d.is_mass_storage else "✗ Nein"),
            ("Risiko-Level", d.risk_level.value),
        ]
        for i, (label, value) in enumerate(rows):
            bg = COLORS["bg_card"] if i % 2 == 0 else COLORS["bg_input"]
            row_frame = ctk.CTkFrame(info, fg_color=bg, corner_radius=0)
            row_frame.pack(fill="x")
            ctk.CTkLabel(row_frame, text=f"  {label}:", width=160, anchor="w",
                         font=("Courier New", 11), text_color=COLORS["text_muted"]).pack(side="left", padx=4, pady=4)
            color = risk_color if label == "Risiko-Level" else COLORS["text_primary"]
            ctk.CTkLabel(row_frame, text=value, anchor="w",
                         font=("Courier New", 11, "bold"), text_color=color).pack(side="left", pady=4)

        # Flags / Warnungen
        if d.flags:
            flag_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_input"], corner_radius=8,
                                       border_width=1, border_color=risk_color)
            flag_frame.pack(fill="x", padx=20, pady=6)
            ctk.CTkLabel(flag_frame, text="  Analyse-Flags:", font=("Courier New", 10, "bold"),
                         text_color=risk_color).pack(anchor="w", padx=8, pady=(6, 2))
            for flag in d.flags:
                ctk.CTkLabel(flag_frame, text=f"  {flag}", font=("Courier New", 10),
                             text_color=COLORS["text_muted"]).pack(anchor="w", padx=8)
            ctk.CTkLabel(flag_frame, text="").pack(pady=2)

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=16)

        ctk.CTkButton(btn_frame, text="✓  ERLAUBEN (Whitelist)",
                      fg_color=COLORS["risk_safe"], hover_color="#2ea043",
                      font=("Courier New", 12, "bold"), width=200,
                      command=self._allow).pack(side="left", padx=10)

        ctk.CTkButton(btn_frame, text="✗  BLOCKIEREN",
                      fg_color=COLORS["risk_high"], hover_color="#da3633",
                      font=("Courier New", 12, "bold"), width=140,
                      command=self._block).pack(side="left", padx=10)

        ctk.CTkButton(btn_frame, text="  Ignorieren",
                      fg_color=COLORS["bg_input"], hover_color=COLORS["border"],
                      font=("Courier New", 11), width=100,
                      command=self.destroy).pack(side="left", padx=5)

    def _allow(self):
        self.on_decision(self.device.fingerprint, DeviceStatus.WHITELISTED)
        self.destroy()

    def _block(self):
        self.on_decision(self.device.fingerprint, DeviceStatus.BLOCKED)
        self.destroy()

# ── Alert-Toast ───────────────────────────────────────────────────────────────
class AlertToast(ctk.CTkToplevel):
    def __init__(self, parent, message: str, duration_ms: int = 5000):
        super().__init__(parent)
        self.overrideredirect(True)
        self.configure(fg_color=COLORS["risk_high"])
        self.attributes("-topmost", True)
        self.geometry(f"480x80+{parent.winfo_x() + parent.winfo_width() - 500}+{parent.winfo_y() + 10}")
        ctk.CTkLabel(self, text=f"🚨 ALARM: {message[:80]}",
                     font=("Courier New", 11, "bold"),
                     text_color="white", wraplength=460).pack(expand=True, padx=10, pady=10)
        self.after(duration_ms, self.destroy)

# ── Geräte-Karte ──────────────────────────────────────────────────────────────
class DeviceCard(ctk.CTkFrame):
    def __init__(self, parent, device: USBDevice, monitor: DeviceMonitor, on_scan, on_refresh):
        super().__init__(parent, fg_color=COLORS["bg_card"], corner_radius=10,
                          border_width=1, border_color=COLORS["border"])
        self.device = device
        self.monitor = monitor
        self.on_scan = on_scan
        self.on_refresh = on_refresh
        self._build()

    def _build(self):
        d = self.device
        risk_c  = RISK_COLORS.get(d.risk_level, COLORS["text_muted"])
        stat_c  = STATUS_COLORS.get(d.status, COLORS["text_muted"])

        # Kopfzeile
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x", padx=12, pady=(10, 4))

        icon = "⌨" if d.is_hid else "💾" if d.is_mass_storage else "🔌"
        ctk.CTkLabel(head, text=f"{icon}  {d.product or d.device_id}",
                     font=("Courier New", 13, "bold"),
                     text_color=COLORS["text_primary"]).pack(side="left")

        # Status-Badge
        stat_badge = ctk.CTkLabel(head, text=f"  {d.status.value}  ",
                                   font=("Courier New", 10, "bold"),
                                   fg_color=stat_c, corner_radius=4,
                                   text_color="white" if d.status != DeviceStatus.PENDING else COLORS["bg_dark"])
        stat_badge.pack(side="right")

        # Risk-Badge
        ctk.CTkLabel(head, text=f"  {d.risk_level.value}  ",
                     font=("Courier New", 10, "bold"),
                     fg_color=risk_c, corner_radius=4,
                     text_color="white").pack(side="right", padx=6)

        # Infos
        info = ctk.CTkFrame(self, fg_color="transparent")
        info.pack(fill="x", padx=12)
        details = f"VID:PID {d.vid}:{d.pid}  |  {d.manufacturer or 'Unbekannt'}  |  Serial: {d.serial or '—'}"
        if d.is_hid:   details += "  |  🖮 HID"
        if d.is_mass_storage: details += "  |  💾 Storage"
        ctk.CTkLabel(info, text=details, font=("Courier New", 10),
                     text_color=COLORS["text_muted"]).pack(anchor="w")

        fp_label = f"Fingerprint: {d.fingerprint}  |  Keystrokes: {d.keystroke_count}"
        ctk.CTkLabel(info, text=fp_label, font=("Courier New", 9),
                     text_color=COLORS["text_muted"]).pack(anchor="w")

        # Flags (kompakt)
        if d.flags:
            flags_text = "  ".join(d.flags[:2])
            if len(d.flags) > 2:
                flags_text += f"  (+{len(d.flags)-2} weitere)"
            ctk.CTkLabel(info, text=flags_text, font=("Courier New", 9),
                         text_color=risk_c).pack(anchor="w", pady=(2,0))

        # Aktions-Buttons
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=12, pady=(8, 10))

        if d.status != DeviceStatus.WHITELISTED:
            ctk.CTkButton(btn_row, text="✓ Erlauben", width=100,
                          fg_color=COLORS["risk_safe"], hover_color="#2ea043",
                          font=("Courier New", 10, "bold"), height=28,
                          command=lambda: self._set_status(DeviceStatus.WHITELISTED)).pack(side="left", padx=(0,6))

        if d.status != DeviceStatus.BLOCKED:
            ctk.CTkButton(btn_row, text="✗ Blockieren", width=110,
                          fg_color=COLORS["risk_high"], hover_color="#da3633",
                          font=("Courier New", 10, "bold"), height=28,
                          command=lambda: self._set_status(DeviceStatus.BLOCKED)).pack(side="left", padx=(0,6))

        ctk.CTkButton(btn_row, text="🔍 Scannen", width=100,
                      fg_color=COLORS["bg_input"], hover_color=COLORS["border"],
                      font=("Courier New", 10), height=28,
                      command=lambda: self.on_scan(d)).pack(side="left", padx=(0,6))

        ctk.CTkButton(btn_row, text="🗑 Vergessen", width=100,
                      fg_color=COLORS["bg_input"], hover_color=COLORS["border"],
                      font=("Courier New", 10), height=28,
                      command=self._forget).pack(side="left")

    def _set_status(self, status: DeviceStatus):
        self.monitor.set_device_status(self.device.fingerprint, status)
        self.on_refresh()

    def _forget(self):
        self.monitor.db.delete(self.device.fingerprint)
        self.on_refresh()

# ── Keystroke Log Panel ───────────────────────────────────────────────────────
class KeystrokePanel(ctk.CTkFrame):
    MAX_ENTRIES = 1000

    def __init__(self, parent, db):
        super().__init__(parent, fg_color=COLORS["bg_dark"])
        self.db = db
        self._entries: list[dict] = []
        self._filter_device = None
        self._auto_scroll = True
        self._build()

    def _build(self):
        # Toolbar
        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=0)
        toolbar.pack(fill="x")

        ctk.CTkLabel(toolbar, text="  Keystroke Monitor",
                     font=("Courier New", 13, "bold"),
                     text_color=COLORS["accent_blue"]).pack(side="left", padx=8, pady=8)

        self._autoscroll_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(toolbar, text="Auto-Scroll", variable=self._autoscroll_var,
                        font=("Courier New", 10)).pack(side="right", padx=8)

        ctk.CTkButton(toolbar, text="🗑 Leeren", width=90,
                      fg_color=COLORS["bg_input"], hover_color=COLORS["border"],
                      font=("Courier New", 10), height=28,
                      command=self._clear).pack(side="right", padx=6, pady=8)

        ctk.CTkButton(toolbar, text="↻ Laden", width=90,
                      fg_color=COLORS["bg_input"], hover_color=COLORS["border"],
                      font=("Courier New", 10), height=28,
                      command=self._load_from_db).pack(side="right", padx=0, pady=8)

        # Statistik-Bar
        self._stat_var = tk.StringVar(value="Warte auf Ereignisse…")
        ctk.CTkLabel(toolbar, textvariable=self._stat_var,
                     font=("Courier New", 10), text_color=COLORS["text_muted"]).pack(side="left", padx=20)

        # Log-Textbox
        self._log = ctk.CTkTextbox(self, font=("Courier New", 11),
                                    fg_color=COLORS["bg_dark"],
                                    text_color=COLORS["text_primary"],
                                    scrollbar_button_color=COLORS["border"])
        self._log.pack(fill="both", expand=True, padx=4, pady=4)
        self._log.configure(state="disabled")

        # Tags für Farb-Coding
        self._log._textbox.tag_config("timestamp", foreground=COLORS["text_muted"])
        self._log._textbox.tag_config("device",    foreground=COLORS["accent_blue"])
        self._log._textbox.tag_config("key",       foreground=COLORS["accent_cyan"])
        self._log._textbox.tag_config("special",   foreground=COLORS["risk_medium"])
        self._log._textbox.tag_config("danger",    foreground=COLORS["risk_crit"])
        self._log._textbox.tag_config("wpm_high",  foreground=COLORS["risk_high"])
        self._log._textbox.tag_config("enter",     foreground=COLORS["risk_medium"])

    def add_event(self, event: KeystrokeEvent):
        if self._filter_device and event.device_id != self._filter_device:
            return
        self._entries.append(event.to_dict() if hasattr(event, 'to_dict') else event)
        if len(self._entries) > self.MAX_ENTRIES:
            self._entries = self._entries[-self.MAX_ENTRIES:]

        ts = event.timestamp[11:23] if len(event.timestamp) > 11 else event.timestamp
        key = event.key
        wpm = event.wpm_estimate
        dev = event.device_name[:20]

        self._log.configure(state="normal")
        tb = self._log._textbox

        tb.insert("end", f"{ts}", "timestamp")
        tb.insert("end", f"  [{dev}]", "device")
        tb.insert("end", "  ")

        # Spezial-Keys farblich hervorheben
        if key in ("[ENTER]",):
            tb.insert("end", f"{key}", "enter")
        elif key.startswith("[") and key.endswith("]"):
            tb.insert("end", f"{key}", "special")
        else:
            tb.insert("end", f"{key}", "key")

        # WPM
        if wpm > 600:
            tb.insert("end", f"  ⚡{wpm:.0f}wpm", "wpm_high")
        elif wpm > 150:
            tb.insert("end", f"  {wpm:.0f}wpm", "danger")

        tb.insert("end", "\n")
        self._log.configure(state="disabled")

        if self._autoscroll_var.get():
            self._log._textbox.see("end")

        total = len(self._entries)
        self._stat_var.set(f"Gesamt: {total} Ereignisse | Letztes: {ts} | {dev}")

    def _load_from_db(self):
        events = self.db.get_keystrokes(limit=500)
        self._clear(silent=True)
        for ev in events:
            ks = KeystrokeEvent(**ev)
            self.add_event(ks)

    def _clear(self, silent=False):
        self._entries.clear()
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")
        if not silent:
            self._stat_var.set("Log geleert.")

# ── Scanner Panel ─────────────────────────────────────────────────────────────
class ScannerPanel(ctk.CTkFrame):
    def __init__(self, parent, monitor: DeviceMonitor):
        super().__init__(parent, fg_color=COLORS["bg_dark"])
        self.monitor = monitor
        self._selected_device = None
        self._build()

    def _build(self):
        left = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], width=220, corner_radius=8)
        left.pack(side="left", fill="y", padx=(8, 4), pady=8)
        left.pack_propagate(False)

        ctk.CTkLabel(left, text="  Gerät wählen",
                     font=("Courier New", 12, "bold"),
                     text_color=COLORS["accent_blue"]).pack(anchor="w", padx=8, pady=(10, 4))

        self._device_list = ctk.CTkScrollableFrame(left, fg_color="transparent")
        self._device_list.pack(fill="both", expand=True)

        # Scan-Optionen
        right = ctk.CTkFrame(self, fg_color=COLORS["bg_dark"])
        right.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=8)

        scan_hdr = ctk.CTkFrame(right, fg_color=COLORS["bg_card"], corner_radius=8)
        scan_hdr.pack(fill="x")

        ctk.CTkLabel(scan_hdr, text="  Scan-Optionen",
                     font=("Courier New", 13, "bold"),
                     text_color=COLORS["accent_blue"]).pack(side="left", padx=10, pady=8)

        scan_btns = ctk.CTkFrame(scan_hdr, fg_color="transparent")
        scan_btns.pack(side="right", padx=10, pady=6)

        for label, key in [("lsusb", "lsusb"), ("sysfs", "sysfs"),
                            ("HID-Interfaces", "hid"), ("Risiko", "risk"), ("Vollscan", "full")]:
            ctk.CTkButton(scan_btns, text=label, width=110,
                          fg_color=COLORS["bg_input"], hover_color=COLORS["border"],
                          font=("Courier New", 10), height=28,
                          command=lambda k=key: self._run_scan(k)).pack(side="left", padx=3)

        # Ergebnis
        self._result = ctk.CTkTextbox(right, font=("Courier New", 11),
                                       fg_color=COLORS["bg_card"],
                                       text_color=COLORS["text_primary"])
        self._result.pack(fill="both", expand=True, pady=(6, 0))
        self._result.insert("end", "← Gerät auswählen, dann Scan-Typ anklicken.\n\n"
                                    "Verfügbare Scans:\n"
                                    "  lsusb         — Detaillierte USB-Descriptor-Ausgabe\n"
                                    "  sysfs         — Kernel sysfs Attribute (Speed, Power, Klassen)\n"
                                    "  HID-Interfaces — Prüft registrierte evdev Input-Geräte\n"
                                    "  Risiko        — Heuristik-Analyse (BadUSB-Indikatoren)\n"
                                    "  Vollscan      — Alle obigen Scans kombiniert\n")
        self._result.configure(state="disabled")

    def refresh_devices(self, devices: list[USBDevice]):
        for w in self._device_list.winfo_children():
            w.destroy()
        for dev in devices:
            btn = ctk.CTkButton(
                self._device_list,
                text=f"{dev.product or dev.device_id}\n{dev.vid}:{dev.pid}",
                fg_color=COLORS["bg_input"] if self._selected_device != dev.fingerprint else COLORS["accent_blue"],
                hover_color=COLORS["border"],
                font=("Courier New", 10), height=44, anchor="w",
                command=lambda d=dev: self._select(d)
            )
            btn.pack(fill="x", pady=2, padx=4)

    def _select(self, device: USBDevice):
        self._selected_device = device.fingerprint
        self._result.configure(state="normal")
        self._result.delete("1.0", "end")
        self._result.insert("end", f"Ausgewählt: {device.product or device.device_id}\n"
                                    f"VID:PID   : {device.vid}:{device.pid}\n"
                                    f"Fingerprint: {device.fingerprint}\n\n"
                                    "Scan-Typ anklicken →\n")
        self._result.configure(state="disabled")

    def _run_scan(self, scan_type: str):
        if not self._selected_device:
            messagebox.showwarning("Kein Gerät", "Bitte zuerst ein Gerät in der linken Liste auswählen.")
            return

        self._result.configure(state="normal")
        self._result.delete("1.0", "end")
        self._result.insert("end", f"Scanne ({scan_type})…\n")
        self._result.configure(state="disabled")

        def _do():
            result = self.monitor.scan_device(self._selected_device, scan_type)
            self._show_result(scan_type, result)

        threading.Thread(target=_do, daemon=True).start()

    def _show_result(self, scan_type: str, result: dict):
        self._result.configure(state="normal")
        self._result.delete("1.0", "end")
        self._result.insert("end", f"═══ Scan: {scan_type.upper()} ══════════════════════════════\n\n")

        def _fmt(obj, indent=0):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        self._result.insert("end", " " * indent + f"{k}:\n")
                        _fmt(v, indent + 2)
                    else:
                        self._result.insert("end", " " * indent + f"{k}: {v}\n")
            elif isinstance(obj, list):
                for item in obj:
                    self._result.insert("end", " " * indent + f"• {item}\n")
            else:
                self._result.insert("end", str(obj) + "\n")

        _fmt(result)
        self._result.configure(state="disabled")

# ── Verlauf Panel ─────────────────────────────────────────────────────────────
class HistoryPanel(ctk.CTkFrame):
    def __init__(self, parent, db):
        super().__init__(parent, fg_color=COLORS["bg_dark"])
        self.db = db
        self._build()

    def _build(self):
        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=0)
        toolbar.pack(fill="x")
        ctk.CTkLabel(toolbar, text="  Geräteverlauf (aus Datenbank)",
                     font=("Courier New", 13, "bold"),
                     text_color=COLORS["accent_blue"]).pack(side="left", padx=10, pady=8)
        ctk.CTkButton(toolbar, text="↻ Aktualisieren", width=130,
                      fg_color=COLORS["bg_input"], hover_color=COLORS["border"],
                      font=("Courier New", 10), height=28,
                      command=self.refresh).pack(side="right", padx=10, pady=8)

        self._box = ctk.CTkTextbox(self, font=("Courier New", 11),
                                    fg_color=COLORS["bg_dark"],
                                    text_color=COLORS["text_primary"])
        self._box.pack(fill="both", expand=True, padx=4, pady=4)
        self.refresh()

    def refresh(self):
        devices = self.db.get_all()
        self._box.configure(state="normal")
        self._box.delete("1.0", "end")
        if not devices:
            self._box.insert("end", "Noch keine Geräte in der Datenbank.\n")
        else:
            self._box.insert("end", f"{'FINGERPRINT':<18} {'VID:PID':<12} {'STATUS':<14} {'RISK':<10} {'PRODUKT':<28} {'ZULETZT'}\n")
            self._box.insert("end", "─" * 110 + "\n")
            for dev in sorted(devices, key=lambda d: d.last_seen, reverse=True):
                line = (f"{dev.fingerprint:<18} {dev.vid}:{dev.pid:<10} "
                        f"{dev.status.value:<14} {dev.risk_level.value:<10} "
                        f"{(dev.product or '—')[:26]:<28} {dev.last_seen[:19]}\n")
                self._box.insert("end", line)
        self._box.configure(state="disabled")

# ── Einstellungen Panel ───────────────────────────────────────────────────────
class SettingsPanel(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=COLORS["bg_dark"])
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="  Einstellungen & Systeminfo",
                     font=("Courier New", 14, "bold"),
                     text_color=COLORS["accent_blue"]).pack(anchor="w", padx=20, pady=(20, 10))

        info_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=8)
        info_frame.pack(fill="x", padx=20, pady=10)

        infos = [
            ("Log-Verzeichnis",  str(LOG_DIR)),
            ("pyudev verfügbar", "✓ Ja" if PYUDEV_OK else "✗ Nein — pip install pyudev"),
            ("evdev verfügbar",  "✓ Ja" if EVDEV_OK  else "✗ Nein — pip install evdev"),
            ("Root-Rechte",      "✓ Ja" if __import__('os').geteuid() == 0 else "⚠ Nein — HID-Monitoring benötigt Root"),
        ]
        for label, value in infos:
            row = ctk.CTkFrame(info_frame, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=3)
            ctk.CTkLabel(row, text=f"{label}:", width=180, anchor="w",
                         font=("Courier New", 11), text_color=COLORS["text_muted"]).pack(side="left")
            ctk.CTkLabel(row, text=value, anchor="w",
                         font=("Courier New", 11), text_color=COLORS["text_primary"]).pack(side="left")

        ctk.CTkLabel(self, text="  Hinweise zur Nutzung",
                     font=("Courier New", 13, "bold"),
                     text_color=COLORS["accent_blue"]).pack(anchor="w", padx=20, pady=(20, 6))

        hints = [
            "• Für vollständiges HID-Monitoring (Keystroke-Aufzeichnung) sind Root-Rechte erforderlich.",
            "• Starte das Programm mit: sudo python3 usb_guard_gui.py",
            "• Alternativ: udev-Regel erstellen, um Gruppe 'input' Zugriff auf /dev/input/* zu geben.",
            "• Die Whitelist-Datenbank wird unter ~/.usbguard/whitelist.json gespeichert.",
            "• Keystroke-Events werden in ~/.usbguard/keystroke_events.jsonl aufgezeichnet.",
            "• Der HID-Watcher startet nur für Geräte, die als WHITELISTED markiert wurden.",
            "• Extrem hohe WPM-Werte (>600) lösen automatisch einen Alert aus.",
        ]
        hint_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=8)
        hint_frame.pack(fill="x", padx=20)
        for hint in hints:
            ctk.CTkLabel(hint_frame, text=hint, anchor="w",
                         font=("Courier New", 10), text_color=COLORS["text_muted"],
                         wraplength=700).pack(anchor="w", padx=12, pady=2)
        ctk.CTkLabel(hint_frame, text="").pack(pady=4)

# ── Haupt-App ─────────────────────────────────────────────────────────────────
class USBGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("USBGuard — HID Protection & Monitoring")
        self.geometry("1200x780")
        self.minsize(900, 600)
        self.configure(fg_color=COLORS["bg_dark"])

        self.monitor = get_monitor()
        self._setup_callbacks()
        self._build_ui()
        self._start_monitor()
        self._start_status_bar_tick()

    # ── Callbacks ─────────────────────────────────────────────────────────────
    def _setup_callbacks(self):
        self.monitor.on_device_added      = self._cb_device_added
        self.monitor.on_device_removed    = self._cb_device_removed
        self.monitor.on_whitelist_request = self._cb_whitelist_request
        self.monitor.on_keystroke         = self._cb_keystroke
        self.monitor.on_alert             = self._cb_alert
        self.monitor.on_status_change     = self._cb_status_change

    def _cb_device_added(self, device: USBDevice):
        self.after(0, self._refresh_dashboard)

    def _cb_device_removed(self, device: USBDevice):
        self.after(0, self._refresh_dashboard)

    def _cb_whitelist_request(self, device: USBDevice):
        def _show():
            dlg = WhitelistDialog(self, device, self._on_whitelist_decision)
            dlg.focus()
        self.after(0, _show)

    def _cb_keystroke(self, event: KeystrokeEvent):
        self.after(0, lambda: self._keystroke_panel.add_event(event))

    def _cb_alert(self, device: USBDevice, message: str):
        def _show():
            AlertToast(self, message)
            self._status_var.set(f"🚨 {message[:80]}")
        self.after(0, _show)

    def _cb_status_change(self, device: USBDevice):
        self.after(0, self._refresh_dashboard)

    def _on_whitelist_decision(self, fingerprint: str, status: DeviceStatus):
        self.monitor.set_device_status(fingerprint, status)

    # ── UI aufbauen ───────────────────────────────────────────────────────────
    def _build_ui(self):
        # Titelleiste
        titlebar = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=0, height=50)
        titlebar.pack(fill="x")
        titlebar.pack_propagate(False)

        ctk.CTkLabel(titlebar, text="⚡ USBGuard",
                     font=("Courier New", 18, "bold"),
                     text_color=COLORS["accent_blue"]).pack(side="left", padx=20, pady=10)

        self._conn_var = tk.StringVar(value="⬤ Monitor startet…")
        ctk.CTkLabel(titlebar, textvariable=self._conn_var,
                     font=("Courier New", 11),
                     text_color=COLORS["text_muted"]).pack(side="left", padx=20)

        ctk.CTkLabel(titlebar,
                     text="BadUSB / HID-Injection Detection",
                     font=("Courier New", 10),
                     text_color=COLORS["text_muted"]).pack(side="right", padx=20)

        # Tab-Leiste
        self._tabs = ctk.CTkTabview(self, fg_color=COLORS["bg_dark"],
                                     segmented_button_fg_color=COLORS["bg_card"],
                                     segmented_button_selected_color=COLORS["accent_blue"],
                                     segmented_button_unselected_color=COLORS["bg_input"])
        self._tabs.pack(fill="both", expand=True, padx=6, pady=4)

        for tab in ["📋 Dashboard", "⌨ Keystroke Log", "🔍 Scanner", "📜 Verlauf", "⚙ Einstellungen"]:
            self._tabs.add(tab)

        self._build_dashboard(self._tabs.tab("📋 Dashboard"))
        self._keystroke_panel = KeystrokePanel(self._tabs.tab("⌨ Keystroke Log"), self.monitor.db)
        self._keystroke_panel.pack(fill="both", expand=True)
        self._scanner_panel = ScannerPanel(self._tabs.tab("🔍 Scanner"), self.monitor)
        self._scanner_panel.pack(fill="both", expand=True)
        self._history_panel = HistoryPanel(self._tabs.tab("📜 Verlauf"), self.monitor.db)
        self._history_panel.pack(fill="both", expand=True)
        SettingsPanel(self._tabs.tab("⚙ Einstellungen")).pack(fill="both", expand=True)

        # Status-Leiste
        statusbar = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], height=26, corner_radius=0)
        statusbar.pack(fill="x", side="bottom")
        statusbar.pack_propagate(False)
        self._status_var = tk.StringVar(value="Bereit.")
        ctk.CTkLabel(statusbar, textvariable=self._status_var,
                     font=("Courier New", 10), text_color=COLORS["text_muted"]).pack(side="left", padx=10)

    def _build_dashboard(self, parent):
        # Obere Stats-Leiste
        self._stats_frame = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"], height=60, corner_radius=0)
        self._stats_frame.pack(fill="x")
        self._stats_frame.pack_propagate(False)

        self._stat_vars = {}
        for label in ["Verbunden", "Whitelisted", "Blockiert", "HID-Geräte", "Alerts"]:
            box = ctk.CTkFrame(self._stats_frame, fg_color=COLORS["bg_input"], corner_radius=6)
            box.pack(side="left", padx=8, pady=8)
            var = tk.StringVar(value="0")
            self._stat_vars[label] = var
            ctk.CTkLabel(box, text=f"  {label}  ", font=("Courier New", 9),
                         text_color=COLORS["text_muted"]).pack(pady=(4, 0))
            ctk.CTkLabel(box, textvariable=var, font=("Courier New", 16, "bold"),
                         text_color=COLORS["accent_blue"]).pack(pady=(0, 4), padx=16)

        self._alert_count = 0

        # Geräteliste (scrollbar)
        self._device_scroll = ctk.CTkScrollableFrame(parent, fg_color=COLORS["bg_dark"],
                                                       label_text="  Erkannte USB-Geräte",
                                                       label_font=("Courier New", 12, "bold"),
                                                       label_fg_color=COLORS["bg_dark"])
        self._device_scroll.pack(fill="both", expand=True, padx=6, pady=(4, 6))

        self._refresh_dashboard()

    def _refresh_dashboard(self):
        for w in self._device_scroll.winfo_children():
            w.destroy()

        devices = self.monitor.get_connected_devices()
        all_db  = self.monitor.db.get_all()

        connected    = len(devices)
        whitelisted  = sum(1 for d in all_db if d.status == DeviceStatus.WHITELISTED)
        blocked      = sum(1 for d in all_db if d.status == DeviceStatus.BLOCKED)
        hid_count    = sum(1 for d in devices if d.is_hid)

        self._stat_vars["Verbunden"].set(str(connected))
        self._stat_vars["Whitelisted"].set(str(whitelisted))
        self._stat_vars["Blockiert"].set(str(blocked))
        self._stat_vars["HID-Geräte"].set(str(hid_count))
        self._stat_vars["Alerts"].set(str(self._alert_count))

        if not devices:
            ctk.CTkLabel(self._device_scroll,
                         text="Keine USB-Geräte verbunden.\nStecke ein Gerät ein…",
                         font=("Courier New", 12), text_color=COLORS["text_muted"]).pack(pady=40)
        else:
            for dev in sorted(devices, key=lambda d: d.risk_level.value, reverse=True):
                card = DeviceCard(self._device_scroll, dev, self.monitor,
                                   on_scan=self._open_scanner_for,
                                   on_refresh=self._refresh_dashboard)
                card.pack(fill="x", pady=4, padx=4)

        # Scanner-Geräteliste auch refreshen
        if hasattr(self, '_scanner_panel'):
            self._scanner_panel.refresh_devices(devices)

        self._status_var.set(f"Dashboard aktualisiert — {connected} Gerät(e) verbunden | {datetime.now().strftime('%H:%M:%S')}")

    def _open_scanner_for(self, device: USBDevice):
        self._tabs.set("🔍 Scanner")
        self._scanner_panel._select(device)

    def _start_monitor(self):
        def _run():
            self.monitor.start()
            self.after(0, lambda: self._conn_var.set(
                "⬤ Monitor aktiv" if PYUDEV_OK else "⬤ Manueller Modus (kein pyudev)"
            ))
            self.after(500, self._refresh_dashboard)
        threading.Thread(target=_run, daemon=True).start()

    def _start_status_bar_tick(self):
        """Periodischer Refresh alle 30s."""
        def _tick():
            self._refresh_dashboard()
            if hasattr(self, '_history_panel'):
                self._history_panel.refresh()
            self.after(30_000, _tick)
        self.after(30_000, _tick)

    def on_closing(self):
        self.monitor.stop()
        self.destroy()

# ── Einstiegspunkt ────────────────────────────────────────────────────────────
def main():
    app = USBGuardApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()

if __name__ == "__main__":
    main()
