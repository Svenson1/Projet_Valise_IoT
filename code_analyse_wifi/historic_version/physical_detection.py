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
  2. Reseau actuellement ecoute : AP + tous les clients vus dessus, avec
     pour chacun : role (AP/CLIENT), RSSI instantane, RSSI moyenne
     glissante, et age (secondes depuis la derniere trame recue de cette
     station). Rien n'est jamais supprime de cette table -- l'age est
     purement informatif, il sert a savoir si une entree est "fraiche"
     ou obsolete, pas a la faire disparaitre.

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
from collections import deque
from datetime import datetime

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

        Parsing Last_time_seen here mirrors exactly what render() already
        does to compute the AGE column -- kept as a small local helper
        instead of a shared function to avoid coupling poll()'s internal
        purging logic to the display code.
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
    needed, since packet arrival is asynchronous by nature and cannot be
    tied to our display refresh cycle without dropping packets in between.

    DIRECTION-FINDING MODE (RSSI table)
    ------------------------------------
    Instead of only listing client MAC addresses, this class now builds a
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
        a client sending to the AP (uplink). We ignore the reverse
        direction (AP -> client, i.e. wlan.sa == BSSID) for role
        assignment there since that's already covered by the beacon case,
        but it also feeds fresh RSSI samples for the AP.

    Where the RSSI comes from: the radiotap header field `dbm_antsignal`,
    which is metadata ADDED BY OUR OWN WIFI ADAPTER at capture time -- it is
    not part of the 802.11 protocol itself. It reflects the signal strength
    of that specific frame as received by OUR antenna, regardless of who
    transmitted it. That's exactly the quantity we want for direction
    finding: "how strong does this station's signal look to ME, right now".

    Entries are never removed from the stations table (no timeout-based
    eviction). Instead we track `last_seen` per station so the UI can show
    an "age" column -- purely informational, to let the operator judge
    whether a reading is fresh or stale, without the row disappearing and
    breaking their mental map of who's on screen.
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
        # and its clients. Keying by MAC (not by role) keeps this simple:
        # there's exactly one entry per physical radio we've heard from.
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

        # Filter is now just "wlan.bssid==<bssid>", with no wlan.fc.type
        # restriction: we need BOTH beacon frames (type/subtype = management
        # beacon, sent only by the AP, used to detect and refresh the AP's
        # RSSI) and data frames (exchanged between AP and clients, used to
        # detect and refresh each client's RSSI). Restricting to
        # wlan.fc.type==2 (data only), as the previous client-only version
        # did, would silently exclude the AP itself since APs don't send
        # data frames to themselves.
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

            # Role can only go from unknown to known, never flip -- a given
            # MAC is either the AP or a client for the lifetime of this
            # capture (it's tied to wlan.bssid, which doesn't change mid
            # capture since we restart the whole tshark process on
            # switch_target()).
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
                    # dbm_antsignal can occasionally hold multiple
                    # comma-separated values if tshark's own field
                    # separator collides with a multi-antenna reading;
                    # in practice with separator="," this is rare, but
                    # we defensively take the first token.
                    rssi = int(dbm_raw.split()[0])
                except ValueError:
                    rssi = None

            if src == bssid:
                # Frame transmitted by the AP itself (beacon, or downlink
                # data frame AP -> client). Either way, this sample tells
                # us the AP's RSSI as seen by our antenna.
                self._update_station(bssid, "AP", sanitize(src_vendor), rssi)
            elif dst == bssid and src:
                # Uplink data frame: client -> AP. The transmitter (src) is
                # a client of this network.
                self._update_station(src, "CLIENT", sanitize(src_vendor), rssi)
            # Any other combination (e.g. broadcast/malformed frames that
            # slipped through the display filter) is ignored: we can't
            # reliably attribute it to a role.

    def get_stations(self):
        """
        Returns a plain-dict snapshot of the stations table, safe to read
        without holding the lock afterwards. Moving average is computed
        here rather than stored, since it's cheap and only needed at
        render time.
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
# AFFICHAGE
# =============================================================================

def render(networks, listener):
    lines = []
    lines.append("=" * 110)
    lines.append(" RADAR - reseaux detectes (tape un numero + Entree pour ecouter un reseau)")
    lines.append("=" * 110)
    lines.append(f"{'No':<4}{'BSSID':<20}{'CH':<5}{'PWR':<6}{'AGE':<6}{'ESSID':<28}{'CHIFFREMENT'}")
    now = time.time()
    for i, net in enumerate(networks):
        essid = (net.get("ESSID") or "").strip()
        essid = essid[:26] if essid else "<SSID masque>"
        last_seen_str = net.get("Last_time_seen", "").strip()
        age_str = "?"
        if last_seen_str:
            try:
                dt = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
                age_seconds = int(now - dt.timestamp())
                if age_seconds < 0:
                    age_seconds = 0
                age_str = f"{age_seconds}s"
            except ValueError:
                pass

        lines.append(f"{i:<4}{net.get('BSSID', ''):<20}{net.get('channel', ''):<5}"
                     f"{net.get('Power', ''):<6}{age_str:<6}{essid:<28}{net.get('Privacy', '')}")

    lines.append("")
    lines.append("=" * 110)
    if listener.current_bssid:
        lines.append(f" ECOUTE EN COURS : {listener.current_essid or '(SSID inconnu)'} "
                      f"({listener.current_bssid}) - canal {listener.current_channel}")
    else:
        lines.append(" ECOUTE EN COURS : aucune (choisis un reseau ci-dessus)")
    lines.append("=" * 110)

    # Direction-finding table: AP + clients, with instantaneous RSSI, moving
    # average RSSI, and age. Sort order: AP always first (it's the anchor of
    # the network), then clients sorted by strongest instantaneous signal
    # first -- that's the ordering that's actually useful while walking
    # around with the antenna: "what's closest / strongest right now" at
    # the top.
    stations = listener.get_stations()
    header = f"{'MAC':<20}{'ROLE':<8}{'PWR':<7}{'AVG':<7}{'AGE':<6}{'VENDOR'}"
    lines.append(header)
    if not stations:
        lines.append("(aucune trame recue pour le moment)")
    else:
        def sort_key(item):
            mac, info = item
            is_client = info["role"] != "AP"
            # AP (False) sorts before CLIENT (True); within clients, higher
            # instantaneous power (closer to 0 dBm, i.e. stronger) first.
            # Missing pwr (None) is pushed to the bottom via -999.
            pwr_for_sort = info["pwr"] if info["pwr"] is not None else -999
            return (is_client, -pwr_for_sort)

        for mac, info in sorted(stations.items(), key=sort_key):
            pwr_str = f"{info['pwr']}" if info["pwr"] is not None else "?"
            avg_str = f"{info['avg']:.1f}" if info["avg"] is not None else "?"
            age_seconds = int(now - info["last_seen"])
            if age_seconds < 0:
                age_seconds = 0
            age_str = f"{age_seconds}s"
            vendor = info["vendor"] or "vendor inconnu"
            lines.append(f"{mac:<20}{info['role']:<8}{pwr_str:<7}{avg_str:<7}{age_str:<6}{vendor}")

    frame = "\033[2J\033[3J\033[H" + "\n".join(lines) + "\n"
    sys.stdout.write(frame)
    sys.stdout.flush()


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