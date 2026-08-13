#!/usr/bin/env bash
#
# enable_hotspot.sh
#
# Turns wlan0 into a standalone WiFi access point (hostapd + dnsmasq),
# removed from NetworkManager's control so that "airmon-ng check kill"
# (run when starting wifi_realtime.py on the two Alfa adapters) can never
# take the hotspot down with it.
#
# This script assumes the configuration files described in the companion
# documentation (MISE_EN_PLACE_HOTSPOT.md) are already in place:
#   /etc/NetworkManager/NetworkManager.conf   (with [keyfile] section ready
#                                               to receive the unmanaged line)
#   /etc/hostapd/hostapd.conf
#   /etc/default/hostapd
#   /etc/dnsmasq.d/valise-ap.conf
#   /etc/systemd/system/wlan0-static.service
#
# It does NOT create these files -- it only toggles the system between
# "wlan0 managed by NetworkManager" and "wlan0 managed by hostapd/dnsmasq".
#
# Usage:
#   sudo ./enable_hotspot.sh

set -euo pipefail

NM_CONF="/etc/NetworkManager/NetworkManager.conf"
UNMANAGED_LINE="unmanaged-devices=interface-name:wlan0"

if [[ $EUID -ne 0 ]]; then
    echo "Ce script doit etre execute avec sudo." >&2
    exit 1
fi

echo "=== Verification de l'etat actuel ==="

# Idempotence check: if hostapd is already active, assume the hotspot is
# already up and stop here rather than restarting services unnecessarily
# (a needless hostapd/dnsmasq restart would briefly drop any phone/tablet
# already connected).
if systemctl is-active --quiet hostapd; then
    echo "hostapd est deja actif -- le hotspot semble deja en place."
    echo "Rien a faire. (Utilise disable_hotspot.sh puis ce script si tu veux forcer un redemarrage propre.)"
    exit 0
fi

echo "=== Etape 1/4 : wlan0 retire du controle de NetworkManager ==="

if grep -q "unmanaged-devices=interface-name:wlan0" "$NM_CONF" 2>/dev/null; then
    echo "  deja present dans $NM_CONF"
else
    if grep -q "^\[keyfile\]" "$NM_CONF" 2>/dev/null; then
        # [keyfile] section already exists: append our line right after it.
        sed -i "/^\[keyfile\]/a ${UNMANAGED_LINE}" "$NM_CONF"
    else
        # No [keyfile] section yet: create it at the end of the file.
        printf '\n[keyfile]\n%s\n' "$UNMANAGED_LINE" >> "$NM_CONF"
    fi
    echo "  ligne ajoutee : $UNMANAGED_LINE"
fi

echo "=== Etape 2/4 : redemarrage de NetworkManager pour appliquer le changement ==="
systemctl restart NetworkManager
sleep 2

echo "=== Etape 3/4 : IP statique + hostapd + dnsmasq ==="
systemctl unmask hostapd || true   # hostapd est masque par defaut sur Raspberry Pi OS
systemctl enable --now wlan0-static.service
systemctl enable --now hostapd
systemctl enable --now dnsmasq

echo "=== Etape 4/4 : verification ==="
sleep 2
if systemctl is-active --quiet hostapd && systemctl is-active --quiet dnsmasq; then
    echo "Hotspot actif."
    echo "SSID/IP : voir /etc/hostapd/hostapd.conf et /etc/systemd/system/wlan0-static.service"
    ip -4 addr show wlan0 | grep inet || true
else
    echo "ATTENTION : hostapd ou dnsmasq n'a pas demarre correctement." >&2
    echo "Verifie les logs :" >&2
    echo "  journalctl -u hostapd -n 30 --no-pager" >&2
    echo "  journalctl -u dnsmasq -n 30 --no-pager" >&2
    exit 1
fi
