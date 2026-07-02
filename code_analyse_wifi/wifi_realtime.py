#!/usr/bin/env python3
"""
wifi_realtime.py

Version temps reel du pipeline de scan Wi-Fi, deux interfaces en mode
monitor simultanement :
  - une interface "radar" qui fait du channel hopping en continu
    (airodump-ng sans --bssid/-c) pour lister tous les reseaux visibles
  - une interface "cible" fixee sur un seul canal/BSSID choisi
    manuellement, qui capture en DIRECT (tshark -i, pas de fichier pcap
    intermediaire) les clients associes a ce reseau

Design a UN SEUL thread de fond (le lecteur tshark de la cible, seul
travail vraiment asynchrone : les paquets arrivent independamment de
notre cycle d'affichage). Le reste -- lecture du radar, lecture clavier
-- se fait de facon synchrone dans la boucle principale :
  - le CSV du radar est relu directement a chaque tick (I/O rapide, pas
    besoin d'un thread dedie)
  - la saisie clavier est geree via select.select() sur stdin avec un
    timeout, ce qui evite un thread+queue tout en reagissant plus vite
    qu'un sleep(1) classique

Affichage console en deux zones, rafraichi chaque seconde :
  1. Table des reseaux detectes par le radar (numero de selection STABLE :
     ordre de premiere detection, jamais retrie, pour que le numero tape
     par l'operateur reste valide entre deux rafraichissements)
  2. Reseau actuellement ecoute + liste des clients vus dessus

Usage:
    sudo python3 wifi_realtime.py
"""

import subprocess
import threading
import select
import time
import re
import csv
import os
import sys
import signal
from datetime import datetime

REFRESH_INTERVAL = 1.0  # seconds between display refreshes
RADAR_CSV_DIR = "radar_csv"

RADAR_FIELDNAMES = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed',
                     'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV',
                     'LAN_IP', 'ID_length', 'ESSID', 'Key']

# Matches ASCII control characters (0x00-0x1F minus tab, plus 0x7F) -- notably
# \r and ESC, which a terminal will happily act on instead of printing.
CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def sanitize(text):
    """
    L'ESSID (et les noms de vendor resolus par wlan.*_resolved) viennent
    directement de donnees radio non fiables : un AP mal forme -- ou
    deliberement malveillant, dans le contexte d'un outil d'audit -- peut y
    placer n'importe quel octet, y compris des caracteres de controle
    (\\r, sequences d'echappement ANSI...). Affiches tels quels dans un
    terminal, ils peuvent deplacer le curseur ou reecrire la ligne en
    cours -- symptome typique : l'affichage semble "s'ecraser" a gauche.
    On neutralise systematiquement ces caracteres des l'ingestion de la
    donnee, pas seulement au moment de l'affichage.
    """
    if not text:
        return ""
    return CONTROL_CHARS_RE.sub("?", text)


def make_run_prefix():
    """
    Chemin (dossier + prefixe de fichier) unique pour cette execution,
    horodate. Tous les CSV du radar atterrissent dans RADAR_CSV_DIR/
    plutot que dans le dossier courant, et l'horodatage dans le nom
    suffit a garantir qu'une execution ne peut jamais relire le fichier
    laisse par une execution precedente -- plus besoin de deplacer les
    vieux fichiers a la main.
    """
    os.makedirs(RADAR_CSV_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join(RADAR_CSV_DIR, f"radar_{stamp}")


def get_interface_mac(iface):
    """Read the MAC address of a network interface directly from sysfs."""
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def list_wireless_interfaces():
    """Return interface names matching wlan<N>, as reported by iwconfig."""
    output = subprocess.run(["iwconfig"], capture_output=True, text=True).stdout
    return re.findall(r"^(wlan\d+)", output, re.MULTILINE)


def choose_two_interfaces():
    """Demande a l'operateur de choisir deux interfaces distinctes : radar et cible."""
    interfaces = list_wireless_interfaces()
    if len(interfaces) < 2:
        print("Il faut au moins 2 interfaces WiFi pour ce script (une radar, une cible).")
        sys.exit(1)

    print("Interfaces WiFi disponibles :")
    for i, iface in enumerate(interfaces):
        mac = get_interface_mac(iface) or "MAC inconnue"
        print(f"  {i} - {iface} ({mac})")

    def ask(role):
        while True:
            choice = input(f"Quelle interface pour le role '{role}' ? ")
            try:
                idx = int(choice)
                if 0 <= idx < len(interfaces):
                    return interfaces[idx]
            except ValueError:
                pass
            print("Entre un numero valide dans la liste.")

    radar_iface = ask("radar (hopping)")
    while True:
        target_iface = ask("cible (canal fixe)")
        if target_iface != radar_iface:
            break
        print("Il faut choisir une interface differente de celle du radar.")

    return radar_iface, target_iface


def enable_monitor_mode(iface):
    """Passe une interface en mode monitor via airmon-ng, gere le renommage eventuel."""
    result = subprocess.run(["sudo", "airmon-ng", "start", iface],
                             stdin=subprocess.DEVNULL, capture_output=True, text=True)
    output = result.stdout + result.stderr
    match = re.search(r"monitor mode (?:vif )?enabled.*?\[?(\w+mon)\]?", output, re.IGNORECASE)
    if match:
        return match.group(1)
    candidate = f"{iface}mon"
    check = subprocess.run(["iwconfig", candidate], capture_output=True, text=True)
    if check.returncode == 0:
        return candidate
    return iface


# =============================================================================
# RADAR : lecture synchrone du CSV, appelee depuis la boucle principale
# =============================================================================

class DiscoveryRadar:
    """
    Lance un airodump-ng en continu (hopping) et expose poll(), a appeler
    depuis la boucle principale : relit le CSV et met a jour la liste des
    reseaux. Pas de thread ni de lock ici -- un seul appelant (le main
    loop), donc pas besoin de synchronisation.

    self._order fixe l'ordre d'affichage de facon STABLE (ordre de
    premiere apparition) : un reseau garde toujours le meme numero une
    fois vu, meme si sa puissance -- donc son rang "naturel" -- change
    d'un tick a l'autre.
    """

    def __init__(self, iface, csv_prefix):
        self.iface = iface
        self.csv_prefix = csv_prefix
        self._networks = {}
        self._order = []
        self._proc = None

    def start(self):
        self._proc = subprocess.Popen(
            ["sudo", "airodump-ng", "-w", self.csv_prefix, "--write-interval", "1",
             "--output-format", "csv", self.iface],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    def poll(self):
        """A appeler une fois par tick de la boucle principale."""
        csv_file = f"{self.csv_prefix}-01.csv"
        if not os.path.exists(csv_file):
            return
        with open(csv_file, errors="replace") as f:
            lines = f.read().splitlines()
        reader = csv.DictReader(lines, fieldnames=RADAR_FIELDNAMES)
        for row in reader:
            if row["BSSID"] in (None, "BSSID"):
                continue
            if row["BSSID"] == "Station MAC":
                break  # section STATION : le radar ne s'occupe que des APs
            row = {k: (sanitize(v.strip()) if isinstance(v, str) else v) for k, v in row.items()}
            bssid = row["BSSID"]
            if not bssid:
                continue
            if bssid not in self._networks:
                self._order.append(bssid)
            self._networks[bssid] = row

    def get_networks(self):
        """Liste des reseaux dans l'ordre stable de decouverte (index = numero de selection)."""
        return [self._networks[b] for b in self._order]

    def stop(self):
        if self._proc:
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.terminate()


# =============================================================================
# TARGET LISTENER : seul thread de fond du script -- capture live tshark
# =============================================================================

class TargetListener:
    """
    Possede l'interface B. switch_target() fixe le canal puis (re)lance un
    tshark en direct (-i, pas de fichier pcap intermediaire) filtre sur un
    seul BSSID. Un thread de fond lit sa sortie ligne par ligne des que des
    paquets arrivent -- c'est le seul endroit du script ou un thread est
    reellement necessaire, car cette arrivee est asynchrone par nature et
    ne peut pas etre calee sur notre cycle d'affichage sans perdre des
    paquets entre deux rafraichissements.
    """

    FIELDS = ["wlan.bssid", "wlan.sa", "wlan.da", "wlan.sa_resolved", "wlan.da_resolved"]

    def __init__(self, iface):
        self.iface = iface
        self.current_bssid = None
        self.current_essid = None
        self.current_channel = None
        self._clients = {}
        self._lock = threading.Lock()
        self._proc = None
        self._reader_thread = None
        self._stop_event = threading.Event()

    def switch_target(self, bssid, channel, essid=""):
        self._stop_current()

        subprocess.run(["sudo", "iw", "dev", self.iface, "set", "channel", str(channel)],
                        stdin=subprocess.DEVNULL, capture_output=True)

        self.current_bssid = bssid
        self.current_essid = sanitize(essid)
        self.current_channel = channel
        with self._lock:
            self._clients = {}

        self._stop_event = threading.Event()
        cmd = ["sudo", "tshark", "-i", self.iface, "-l", "-T", "fields",
               "-E", "separator=,", "-Y", f"wlan.bssid=={bssid} && wlan.fc.type==2"]
        for field in self.FIELDS:
            cmd += ["-e", field]

        self._proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def _read_loop(self):
        for line in self._proc.stdout:
            if self._stop_event.is_set():
                break
            parts = line.strip().split(",")
            if len(parts) < 5:
                continue
            bssid, src, dst, src_vendor, dst_vendor = parts
            with self._lock:
                for mac, vendor in ((src, src_vendor), (dst, dst_vendor)):
                    if mac and mac != bssid:
                        self._clients[mac] = sanitize(vendor) or self._clients.get(mac, "")

    def get_clients(self):
        with self._lock:
            return dict(self._clients)

    def _stop_current(self):
        self._stop_event.set()
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._reader_thread:
            self._reader_thread.join(timeout=1)

    def stop(self):
        self._stop_current()


# =============================================================================
# AFFICHAGE
# =============================================================================

def render(networks, listener):
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

    print("=" * 90)

    print(" RADAR - reseaux detectes (tape un numero + Entree pour ecouter un reseau)")
    print("=" * 90)
    print(f"{'No':<4}{'BSSID':<20}{'CH':<5}{'PWR':<6}{'ESSID':<28}{'CHIFFREMENT'}")
    for i, net in enumerate(networks):
        essid = (net.get("ESSID") or "")[:26]
        essid = essid[:26] if essid else "<SSID masque>"
        print(f"{i:<4}{net.get('BSSID', ''):<20}{net.get('channel', ''):<5}"
              f"{net.get('Power', ''):<6}{essid:<28}{net.get('Privacy', '')}")

    print()
    print("=" * 90)
    if listener.current_bssid:
        print(f" ECOUTE EN COURS : {listener.current_essid or '(SSID inconnu)'} "
              f"({listener.current_bssid}) - canal {listener.current_channel}")
    else:
        print(" ECOUTE EN COURS : aucune (choisis un reseau ci-dessus)")
    print("=" * 90)
    clients = listener.get_clients()
    if not clients:
        print("  (aucun client detecte pour le moment)")
    else:
        for mac, vendor in sorted(clients.items()):
            print(f"  - {mac}  ({vendor or 'vendor inconnu'})")


# =============================================================================
# MAIN
# =============================================================================

def main():
    if "SUDO_UID" not in os.environ:
        print("Root access is required. Please execute this with sudo.")
        sys.exit(1)

    radar_iface_raw, target_iface_raw = choose_two_interfaces()

    run_prefix = make_run_prefix()

    print("Nettoyage des processus concurrents et passage en mode monitor...")
    subprocess.run(["sudo", "airmon-ng", "check", "kill"], stdin=subprocess.DEVNULL)
    radar_iface = enable_monitor_mode(radar_iface_raw)
    target_iface = enable_monitor_mode(target_iface_raw)
    print(f"Radar : {radar_iface}   |   Cible : {target_iface}")

    radar = DiscoveryRadar(radar_iface, csv_prefix=run_prefix)
    listener = TargetListener(target_iface)
    radar.start()

    try:
        while True:
            radar.poll()
            networks = radar.get_networks()

            # select() attend au plus REFRESH_INTERVAL secondes une entree
            # clavier -- remplace un thread+queue dedies a la saisie tout
            # en reagissant plus vite qu'un sleep() fixe si l'operateur
            # tape quelque chose avant la fin du tick.
            ready, _, _ = select.select([sys.stdin], [], [], REFRESH_INTERVAL)
            if ready:
                raw = sys.stdin.readline().strip()
                if raw.isdigit():
                    idx = int(raw)
                    if 0 <= idx < len(networks):
                        target = networks[idx]
                        listener.switch_target(target["BSSID"], target["channel"],
                                                target.get("ESSID", ""))

            render(networks, listener)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nArret en cours...")
        radar.stop()
        listener.stop()
        # Filet de securite : si un sous-processus a quand meme laisse le
        # terminal dans un etat casse (raw mode, no-echo...), on le remet
        # dans un etat "sain" avant de rendre la main.
        subprocess.run(["stty", "sane"])
        print("Pense a repasser les interfaces en mode managed :")
        print(f"  sudo airmon-ng stop {radar_iface}")
        print(f"  sudo airmon-ng stop {target_iface}")


if __name__ == "__main__":
    main()