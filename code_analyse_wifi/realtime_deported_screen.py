#!/usr/bin/env python3
"""
wifi_realtime.py

Version temps reel du pipeline de scan Wi-Fi, deux interfaces en mode
monitor simultanement :
  - une interface "radar" qui fait du channel hopping en continu
    (airodump-ng sans --bssid/-c) pour lister tous les reseaux visibles
  - une interface "cible" fixee sur un seul canal/BSSID choisi
    manuellement, qui capture en DIRECT (tshark -i, pas de fichier pcap
    intermediaire) l'AP et les clients associes a ce reseau, avec leur
    puissance de signal (RSSI) pour faire de la goniometrie manuelle

Design a UN SEUL thread de fond pour la capture (le lecteur tshark de la
cible, seul travail vraiment asynchrone : les paquets arrivent
independamment de notre cycle d'affichage), PLUS un deuxieme thread pour
le serveur web (voir plus bas). Le reste -- lecture du radar, lecture
clavier -- se fait de facon synchrone dans la boucle principale :
  - le CSV du radar est relu directement a chaque tick (I/O rapide, pas
    besoin d'un thread dedie)
  - la saisie clavier est geree via select.select() sur stdin avec un
    timeout, ce qui evite un thread+queue tout en reagissant plus vite
    qu'un sleep(1) classique

SOURCE UNIQUE DE VERITE : build_snapshot()
-------------------------------------------
Le calcul des donnees a afficher (ages, tri, moyennes RSSI, formatage) est
fait UNE SEULE FOIS par tick, dans build_snapshot(), qui retourne un simple
dict JSON-compatible. Deux "vues" different consomment ce meme dict :
  - render_terminal() : ecrit ce dict au format texte ANSI dans le terminal
  - le serveur web (Flask + Server-Sent Events) : encode ce dict en JSON et
    le pousse aux navigateurs connectes
Aucun calcul n'est duplique entre les deux ; seul le format de sortie change.

SERVEUR WEB (Flask + SSE)
--------------------------
Un mini serveur Flask tourne dans un thread de fond des le lancement du
script, et sert le dernier snapshot en continu a un navigateur distant
(telephone/tablette connecte au hotspot du Pi -- voir
MISE_EN_PLACE_HOTSPOT.md) via Server-Sent Events (SSE), PAS des websockets
ou du Flask-SocketIO : SSE utilise l'API navigateur native EventSource, donc
zero librairie JS externe a charger -- important puisque le hotspot n'a pas
d'acces a internet, un CDN pour un client socket.io ne fonctionnerait pas.

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
import json
import logging
from collections import deque
from datetime import datetime

from flask import Flask, Response, render_template_string

REFRESH_INTERVAL = 3.0  # seconds between display refreshes
RADAR_CSV_DIR = "radar_csv"

# Networks not seen (per airodump-ng's own Last_time_seen field) for longer
# than this are dropped from the radar table. Unlike the direction-finding
# table in TargetListener, here we DO want removal: airodump-ng's CSV never
# forgets a BSSID on its own (see project notes), so without active pruning
# the radar list only ever grows, including networks that are long gone.
STALE_TIMEOUT = 60  # seconds

# How many recent RSSI samples to keep per station for the moving average.
# 5 samples is a compromise: enough to smooth out per-packet noise (multipath,
# reflections) without lagging too much behind a real approach/move-away.
RSSI_HISTORY_LEN = 5

# --- Web dashboard settings -------------------------------------------------
WEB_HOST = "0.0.0.0"  # listen on every interface (including the hotspot's wlan0), not just localhost
WEB_PORT = 5000

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

        self._purge_stale()

    def _purge_stale(self):
        """
        Drop any BSSID whose airodump-ng Last_time_seen is older than
        STALE_TIMEOUT. Called once per poll(), after the CSV re-read, so
        stale entries never survive more than one tick past their timeout.
        """
        now = time.time()
        stale_bssids = []
        for bssid, row in self._networks.items():
            last_seen_str = (row.get("Last_time_seen") or "").strip()
            if not last_seen_str:
                continue  # no timestamp to judge by: never purge on missing data
            try:
                dt = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            age_seconds = now - dt.timestamp()
            if age_seconds > STALE_TIMEOUT:
                stale_bssids.append(bssid)

        for bssid in stale_bssids:
            del self._networks[bssid]
            self._order.remove(bssid)

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
    Owns interface B. switch_target() locks the radio channel, then (re)starts
    a live tshark capture (-i, no intermediate pcap file) filtered on a single
    BSSID. A background thread reads its output line by line as packets
    arrive -- this is the only place in the script where a thread is truly
    needed for capture, since packet arrival is asynchronous by nature and
    cannot be tied to our display refresh cycle without dropping packets in
    between.

    DIRECTION-FINDING MODE (RSSI table)
    ------------------------------------
    Instead of only listing client MAC addresses, this class builds a
    unified "stations" table that includes BOTH the access point and every
    client talking to it, each with a live RSSI reading. This is the data
    source for the manual direction-finding workflow: walk around / rotate
    the antenna, watch the RSSI of the station you're trying to locate, and
    move towards higher values.

    How AP vs client is determined (no separate lookup, just an addressing
    rule applied to each captured frame):
      - Beacon frames are sent by the AP; if the source address (wlan.sa)
        equals the BSSID we're filtering on, the transmitter of this frame
        is the AP itself.
      - Data frames are exchanged between the AP and a client. If the BSSID
        appears as the destination (wlan.da), then the source (wlan.sa) is
        a client sending to the AP (uplink).

    Where the RSSI comes from: the radiotap header field `dbm_antsignal`,
    which is metadata ADDED BY OUR OWN WIFI ADAPTER at capture time -- it is
    not part of the 802.11 protocol itself. It reflects the signal strength
    of that specific frame as received by OUR antenna, regardless of who
    transmitted it.

    Entries are never removed from the stations table (no timeout-based
    eviction). Instead we track `last_seen` per station so the UI can show
    an "age" column -- purely informational.
    """

    # Field order matters: it must match the order of "-e" flags in the
    # tshark command built in switch_target().
    FIELDS = ["wlan.bssid", "wlan.sa", "wlan.da", "wlan.sa_resolved", "wlan.da_resolved",
              "radiotap.dbm_antsignal"]

    def __init__(self, iface):
        self.iface = iface
        self.current_bssid = None
        self.current_essid = None
        self.current_channel = None

        # Unified table: MAC address -> station info dict, for BOTH the AP
        # and its clients.
        #
        # station info dict layout:
        #   "role"      : "AP" or "CLIENT"
        #   "vendor"    : resolved vendor string (best-effort, may be empty)
        #   "pwr"       : most recent instantaneous RSSI in dBm (int) or None
        #   "history"   : deque of the last RSSI_HISTORY_LEN RSSI samples,
        #                 used to compute the moving average
        #   "last_seen" : time.time() timestamp of the last frame that
        #                 updated this entry
        self._stations = {}
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
            self._stations = {}

        self._stop_event = threading.Event()

        cmd = ["sudo", "tshark", "-i", self.iface, "-l", "-T", "fields",
               "-E", "separator=,", "-Y", f"wlan.bssid=={bssid}"]
        for field in self.FIELDS:
            cmd += ["-e", field]

        self._proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def _update_station(self, mac, role, vendor, rssi):
        """
        Create or refresh one station's entry. Called with the lock already
        NOT held -- this method acquires it itself, since it's called from
        multiple points in _read_loop.
        """
        now = time.time()
        with self._lock:
            entry = self._stations.get(mac)
            if entry is None:
                entry = {
                    "role": role,
                    "vendor": vendor or "",
                    "pwr": None,
                    "history": deque(maxlen=RSSI_HISTORY_LEN),
                    "last_seen": now,
                }
                self._stations[mac] = entry

            entry["role"] = role
            if vendor:
                entry["vendor"] = vendor
            entry["last_seen"] = now

            if rssi is not None:
                entry["pwr"] = rssi
                entry["history"].append(rssi)

    def _read_loop(self):
        for line in self._proc.stdout:
            if self._stop_event.is_set():
                break
            parts = line.strip().split(",")
            if len(parts) < 6:
                continue
            bssid, src, dst, src_vendor, dst_vendor, dbm_raw = parts[:6]

            rssi = None
            if dbm_raw:
                try:
                    rssi = int(dbm_raw.split()[0])
                except ValueError:
                    rssi = None

            if src == bssid:
                self._update_station(bssid, "AP", sanitize(src_vendor), rssi)
            elif dst == bssid and src:
                self._update_station(src, "CLIENT", sanitize(src_vendor), rssi)

    def get_stations(self):
        """
        Returns a plain-dict snapshot of the stations table, safe to read
        without holding the lock afterwards. Moving average is computed
        here rather than stored, since it's cheap and only needed at
        render/snapshot time.
        """
        with self._lock:
            snapshot = {}
            for mac, entry in self._stations.items():
                history = entry["history"]
                avg = sum(history) / len(history) if history else None
                snapshot[mac] = {
                    "role": entry["role"],
                    "vendor": entry["vendor"],
                    "pwr": entry["pwr"],
                    "avg": avg,
                    "last_seen": entry["last_seen"],
                }
            return snapshot

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
# SNAPSHOT : seule fonction qui calcule les donnees a afficher (une fois par
# tick), consommee ensuite par render_terminal() ET par le serveur web.
# =============================================================================

def build_snapshot(networks, listener):
    """
    Computes everything the UI needs to show, as a plain JSON-serializable
    dict, from the raw radar network list and the current TargetListener
    state. This is the SINGLE place where ages are computed, stations are
    sorted, and numbers are rounded for display -- both render_terminal()
    (ANSI text) and the Flask SSE endpoint (JSON) consume this same dict
    without recomputing anything themselves.

    Shape of the returned dict:
    {
        "networks": [
            {"index": 0, "bssid": "...", "channel": "6", "pwr": "-45",
             "age": 3, "essid": "MyWifi", "privacy": "WPA2"},
            ...
        ],
        "listening": {"essid": "...", "bssid": "...", "channel": 6} or None,
        "stations": [
            {"mac": "...", "role": "AP", "pwr": -40, "avg": -41.2,
             "age": 1, "vendor": "TP-Link"},
            ...
        ]
    }
    """
    now = time.time()

    networks_out = []
    for i, net in enumerate(networks):
        essid = (net.get("ESSID") or "").strip() or "<SSID masque>"
        last_seen_str = (net.get("Last_time_seen") or "").strip()
        age_seconds = None
        if last_seen_str:
            try:
                dt = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
                age_seconds = max(0, int(now - dt.timestamp()))
            except ValueError:
                pass
        networks_out.append({
            "index": i,
            "bssid": net.get("BSSID", ""),
            "channel": net.get("channel", ""),
            "pwr": net.get("Power", ""),
            "age": age_seconds,
            "essid": essid,
            "privacy": net.get("Privacy", ""),
        })

    listening = None
    if listener.current_bssid:
        listening = {
            "essid": listener.current_essid or "(SSID inconnu)",
            "bssid": listener.current_bssid,
            "channel": listener.current_channel,
        }

    stations = listener.get_stations()

    def sort_key(item):
        mac, info = item
        is_client = info["role"] != "AP"
        pwr_for_sort = info["pwr"] if info["pwr"] is not None else -999
        return (is_client, -pwr_for_sort)

    stations_out = []
    for mac, info in sorted(stations.items(), key=sort_key):
        age_seconds = max(0, int(now - info["last_seen"]))
        stations_out.append({
            "mac": mac,
            "role": info["role"],
            "pwr": info["pwr"],
            "avg": round(info["avg"], 1) if info["avg"] is not None else None,
            "age": age_seconds,
            "vendor": info["vendor"] or "vendor inconnu",
        })

    return {"networks": networks_out, "listening": listening, "stations": stations_out}


# =============================================================================
# AFFICHAGE TERMINAL : formate le snapshot en texte ANSI
# =============================================================================

def render_terminal(snapshot):
    lines = []
    lines.append("=" * 110)
    lines.append(" RADAR - reseaux detectes (tape un numero + Entree pour ecouter un reseau)")
    lines.append("=" * 110)
    lines.append(f"{'No':<4}{'BSSID':<20}{'CH':<5}{'PWR':<6}{'AGE':<6}{'ESSID':<28}{'CHIFFREMENT'}")
    for net in snapshot["networks"]:
        age_str = f"{net['age']}s" if net["age"] is not None else "?"
        essid = net["essid"][:26]
        lines.append(f"{net['index']:<4}{net['bssid']:<20}{net['channel']:<5}"
                     f"{net['pwr']:<6}{age_str:<6}{essid:<28}{net['privacy']}")

    lines.append("")
    lines.append("=" * 110)
    listening = snapshot["listening"]
    if listening:
        lines.append(f" ECOUTE EN COURS : {listening['essid']} "
                      f"({listening['bssid']}) - canal {listening['channel']}")
    else:
        lines.append(" ECOUTE EN COURS : aucune (choisis un reseau ci-dessus)")
    lines.append("=" * 110)

    lines.append(f"{'MAC':<20}{'ROLE':<8}{'PWR':<7}{'AVG':<7}{'AGE':<6}{'VENDOR'}")
    if not snapshot["stations"]:
        lines.append("(aucune trame recue pour le moment)")
    else:
        for st in snapshot["stations"]:
            pwr_str = f"{st['pwr']}" if st["pwr"] is not None else "?"
            avg_str = f"{st['avg']}" if st["avg"] is not None else "?"
            age_str = f"{st['age']}s"
            lines.append(f"{st['mac']:<20}{st['role']:<8}{pwr_str:<7}{avg_str:<7}{age_str:<6}{st['vendor']}")

    frame = "\033[2J\033[3J\033[H" + "\n".join(lines) + "\n"
    sys.stdout.write(frame)
    sys.stdout.flush()


# =============================================================================
# SERVEUR WEB : Flask + Server-Sent Events, tourne dans son propre thread
# =============================================================================

class WebState:
    """
    Thread-safe holder for the latest snapshot. The main loop calls
    set_snapshot() once per tick, right after computing it with
    build_snapshot(). The Flask SSE endpoint (running in its own thread)
    calls get_snapshot() on its own timer to push updates to connected
    browsers. No history, no diffing -- just "what's the current full
    picture", refreshed wholesale each tick.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._snapshot = {"networks": [], "listening": None, "stations": []}

    def set_snapshot(self, snapshot):
        with self._lock:
            self._snapshot = snapshot

    def get_snapshot(self):
        with self._lock:
            return self._snapshot


# Minimal single-page dashboard. No external JS/CSS libraries (the hotspot
# has no internet access) -- just vanilla JS using the browser's built-in
# EventSource API to receive SSE pushes, and plain HTML tables re-rendered
# on every message.
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Valise WiFi - Dashboard</title>
  <style>
    body { font-family: monospace; background: #111; color: #eee; margin: 1em; }
    h2 { color: #7fd; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 1.5em; }
    th, td { border: 1px solid #444; padding: 4px 8px; text-align: left; font-size: 14px; }
    th { background: #222; }
    tr.ap { color: #ffd27f; font-weight: bold; }
    #listening { margin-bottom: 1em; color: #7fd; }
  </style>
</head>
<body>
  <h2>Radar</h2>
  <table id="networks">
    <thead><tr><th>No</th><th>BSSID</th><th>CH</th><th>PWR</th><th>AGE</th><th>ESSID</th><th>Chiffrement</th></tr></thead>
    <tbody></tbody>
  </table>

  <div id="listening">Ecoute en cours : aucune</div>

  <h2>Stations (AP + clients)</h2>
  <table id="stations">
    <thead><tr><th>MAC</th><th>Role</th><th>PWR</th><th>AVG</th><th>AGE</th><th>Vendor</th></tr></thead>
    <tbody></tbody>
  </table>

  <script>
    // EventSource is a native browser API: it opens one long-lived HTTP
    // connection to /stream and fires onmessage each time the server
    // writes a new "data: ...\\n\\n" block. No library needed.
    const source = new EventSource('/stream');

    source.onmessage = function(event) {
      const snap = JSON.parse(event.data);
      renderNetworks(snap.networks);
      renderListening(snap.listening);
      renderStations(snap.stations);
    };

    function renderNetworks(networks) {
      const tbody = document.querySelector('#networks tbody');
      tbody.innerHTML = '';
      for (const net of networks) {
        const row = document.createElement('tr');
        row.innerHTML = `<td>${net.index}</td><td>${net.bssid}</td><td>${net.channel}</td>
                          <td>${net.pwr}</td><td>${net.age ?? '?'}s</td>
                          <td>${net.essid}</td><td>${net.privacy}</td>`;
        tbody.appendChild(row);
      }
    }

    function renderListening(listening) {
      const div = document.getElementById('listening');
      if (!listening) {
        div.textContent = 'Ecoute en cours : aucune';
      } else {
        div.textContent = `Ecoute en cours : ${listening.essid} (${listening.bssid}) - canal ${listening.channel}`;
      }
    }

    function renderStations(stations) {
      const tbody = document.querySelector('#stations tbody');
      tbody.innerHTML = '';
      for (const st of stations) {
        const row = document.createElement('tr');
        if (st.role === 'AP') row.classList.add('ap');
        row.innerHTML = `<td>${st.mac}</td><td>${st.role}</td>
                          <td>${st.pwr ?? '?'}</td><td>${st.avg ?? '?'}</td>
                          <td>${st.age}s</td><td>${st.vendor}</td>`;
        tbody.appendChild(row);
      }
    }
  </script>
</body>
</html>
"""


def create_web_app(web_state):
    """
    Builds the Flask app with exactly two routes:
      GET /        -> the HTML page above (loaded once by the browser)
      GET /stream  -> the SSE endpoint (stays open, keeps pushing updates)
    Kept as a factory function (rather than a module-level `app = Flask(...)`)
    so that web_state -- created in main() -- can be captured by closures
    without relying on a global variable.
    """
    app = Flask(__name__)

    # Flask/Werkzeug logs one line per HTTP request by default. Since /stream
    # stays open and is polled internally, and since our terminal UI clears
    # and redraws the screen every tick with raw ANSI codes, any stray log
    # line printed to stdout by Flask would visually corrupt that redraw.
    # Silencing it here keeps the terminal display clean.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/stream")
    def stream():
        def event_stream():
            while True:
                snapshot = web_state.get_snapshot()
                # SSE wire format: "data: <payload>\n\n" -- the blank line
                # is what tells the browser's EventSource "this message is
                # complete, deliver it now".
                yield f"data: {json.dumps(snapshot)}\n\n"
                time.sleep(REFRESH_INTERVAL)

        return Response(
            event_stream(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",  # prevents any reverse proxy from buffering the stream
            },
        )

    return app


def start_web_server(web_state):
    """
    Starts the Flask app in a daemon background thread. threaded=True lets
    Flask's development server handle more than one open /stream connection
    at a time (e.g. two phones watching the dashboard simultaneously)
    without one blocking the other. use_reloader=False is required: Flask's
    auto-reloader tries to run in the main thread and re-exec the process,
    which doesn't make sense here since we're already inside a background
    thread of a larger script.
    """
    app = create_web_app(web_state)

    def run():
        app.run(host=WEB_HOST, port=WEB_PORT, threaded=True, use_reloader=False)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


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

    # The web server is started once, before the main loop, and lives for
    # the whole run: it doesn't need to know about interfaces or targets,
    # it only ever reads whatever build_snapshot() last produced.
    web_state = WebState()
    start_web_server(web_state)
    print(f"Dashboard web disponible sur http://192.168.4.1:{WEB_PORT}/")

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

            snapshot = build_snapshot(networks, listener)
            web_state.set_snapshot(snapshot)
            render_terminal(snapshot)
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