#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  USBGuard — Installations- und Start-Skript
# ═══════════════════════════════════════════════════════════════
#
#  Dieses Skript:
#    1. Prüft Abhängigkeiten
#    2. Installiert udev-Regel für Input-Zugriff ohne Root
#    3. Startet die USBGuard GUI
#
# Nutzung:
#   chmod +x run_usbguard.sh
#   ./run_usbguard.sh           # normaler Start
#   sudo ./run_usbguard.sh      # mit Root (volles HID-Monitoring)
#   ./run_usbguard.sh --install # udev-Regel installieren

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "  ⚡ USBGuard — HID Protection & Monitoring"
echo "  ══════════════════════════════════════════"
echo ""

# ── Abhängigkeiten prüfen ────────────────────────────────────
echo "  [1/3] Prüfe Python-Abhängigkeiten…"
pip install pyudev evdev customtkinter pillow --break-system-packages -q 2>/dev/null || \
pip install pyudev evdev customtkinter pillow -q 2>/dev/null || true

# ── udev-Regel (optional, für Non-Root HID-Zugriff) ──────────
UDEV_RULE_FILE="/etc/udev/rules.d/99-usbguard-input.rules"
UDEV_RULE_CONTENT='KERNEL=="event*", SUBSYSTEM=="input", GROUP="input", MODE="0660"'

if [ "$1" == "--install" ]; then
    echo "  [2/3] Installiere udev-Regel (Root erforderlich)…"
    if [ "$EUID" -ne 0 ]; then
        echo "  ⚠  Root-Rechte benötigt: sudo $0 --install"
        exit 1
    fi
    echo "$UDEV_RULE_CONTENT" > "$UDEV_RULE_FILE"
    udevadm control --reload-rules
    udevadm trigger
    # Benutzer zur input-Gruppe hinzufügen
    REAL_USER="${SUDO_USER:-$USER}"
    usermod -aG input "$REAL_USER" 2>/dev/null || true
    echo "  ✓ udev-Regel installiert: $UDEV_RULE_FILE"
    echo "  ✓ Benutzer '$REAL_USER' zur Gruppe 'input' hinzugefügt"
    echo "  ℹ  Bitte abmelden und wieder anmelden, damit Gruppenänderung wirksam wird."
    echo ""
else
    echo "  [2/3] udev-Regel übersprungen (--install für Installation)"
fi

# ── Start ─────────────────────────────────────────────────────
echo "  [3/3] Starte USBGuard GUI…"
echo ""

if [ "$EUID" -eq 0 ]; then
    echo "  ⬤ Root-Modus: Volles HID-Monitoring aktiviert"
else
    echo "  ℹ  Non-Root-Modus: HID-Monitoring ggf. eingeschränkt"
    echo "     Für volles Monitoring: sudo $0  oder  $0 --install"
fi

echo ""
cd "$SCRIPT_DIR"
python3 usb_guard_gui.py
