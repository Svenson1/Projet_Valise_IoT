#!/usr/bin/env bash
#
# disable_hotspot.sh
#
# Reverses enable_hotspot.sh: stops hostapd/dnsmasq/wlan0-static, removes
# the "unmanaged" line from NetworkManager.conf, and restarts
# NetworkManager so it takes wlan0 back under its control (reconnecting
# to any previously known WiFi network automatically, using profiles that
# were never touched by this setup).
#
# Usage:
#   sudo ./disable_hotspot.sh

set -euo pipefail

NM_CONF="/etc/NetworkManager/NetworkManager.conf"

if [[ $EUID -ne 0 ]]; then
    echo "Ce script doit etre execute avec sudo." >&2
    exit 1
fi

echo "=== Verification de l'etat actuel ==="
if ! systemctl is-active --quiet hostapd; then
    echo "hostapd n'est pas actif -- le hotspot semble deja desactive."
    echo "On verifie quand meme que NetworkManager.conf est propre."
fi

echo "=== Etape 1/3 : arret des services du hotspot ==="
systemctl disable --now hostapd 2>/dev/null || true
systemctl disable --now dnsmasq 2>/dev/null || true
systemctl disable --now wlan0-static.service 2>/dev/null || true

echo "=== Etape 2/3 : on rend wlan0 a NetworkManager ==="
if grep -q "unmanaged-devices=interface-name:wlan0" "$NM_CONF" 2>/dev/null; then
    sed -i '/unmanaged-devices=interface-name:wlan0/d' "$NM_CONF"
    echo "  ligne retiree de $NM_CONF"
else
    echo "  rien a retirer, la ligne n'etait pas presente"
fi

echo "=== Etape 3/3 : redemarrage de NetworkManager ==="
systemctl restart NetworkManager
sleep 3

echo "=== Verification ==="
# nmcli device status will show wlan0 back as "connected"/"disconnected"
# (managed), rather than "unmanaged", once NetworkManager has picked it
# back up.
nmcli device status | grep -E "^DEVICE|wlan0" || true
echo ""
echo "wlan0 est de nouveau gere par NetworkManager."
echo "S'il ne se reconnecte pas seul a un reseau connu, relance-le avec :"
echo "  nmcli device connect wlan0"
