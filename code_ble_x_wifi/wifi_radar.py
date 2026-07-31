#!/usr/bin/env python3

"""
wifi capture logic
"""

import subprocess
import threading
import time
import re
import csv
import os
import sys
import signal
from collections import deque
from datetime import datetime

RADAR_CSV_DIR = "radar_csv"

#network not seen for mor than STALE_TIMEOUT are removed
STALE_TIMEOUT = 60  # seconds

#HIstoric for the average
RSSI_HISTORY_LEN = 5


#Dual EMA for defining the trend
EMA_FAST_ALPHA = 0.5    # reacts quickly to recent samples
EMA_SLOW_ALPHA = 0.05   # slow-moving baseline
TREND_HYSTERESIS_DB = 1.5  # gap (dB) required before a trend is reported

#-------------Distance Estimation-----------------------
#generic literature value
PATH_LOSS_P0 = -38.0   # dBm at 1m
PATH_LOSS_N = 3.2      # typical indoor path loss exponent

RADAR_FIELDNAMES = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed',
                     'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV',
                     'LAN_IP', 'ID_length', 'ESSID', 'Key']

#for the cli sanitizing
CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

def sanitize(text):
    """
    Strip control characters from radio-sourced strings (ESSID, resolved
    vendor names). A malformed or malicious AP can embed \\r or ANSI escape
    sequences that would corrupt a terminal.
    """
    if not text:
        return ""
    return CONTROL_CHARS_RE.sub("?", text)

def make_run_prefix():
    """
    Unique, timestamped path prefix for this run's radar CSV files, under
    RADAR_CSV_DIR/. Guarantees a run never reads a previous run's leftover
    file.
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
    """Ask the operator to pick two distinct interfaces: radar and target."""
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
    """Switch an interface to monitor mode via airmon-ng, handling renaming."""
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


def estimate_distance(pwr_filtered):
    """
    Convert a filtered RSSI (dBm) into an estimated distance (m) using the
    log-distance path loss model.
    """
    if pwr_filtered is None:
        return None
    return 10 ** ((PATH_LOSS_P0 - pwr_filtered) / (10 * PATH_LOSS_N))

def compute_trend(ema_fast, ema_slow):
    """
    Compare the fast and slow RSSI EMA to flag an approach/retreat trend.
    A hysteresis band absorbs ordinary RF noise so the indicator doesn't
    flicker.
    """
    if ema_fast is None or ema_slow is None:
        return None
    delta = ema_fast - ema_slow
    if delta > TREND_HYSTERESIS_DB:
        return "approche"
    elif delta < -TREND_HYSTERESIS_DB:
        return "eloigne"
    return "stable"

#=======================
#Radar
#=======================

class DiscoveryRadar:
    """
    Runs a continuous hopping airodump-ng and exposes poll(), called
    repeatedly from ONE background thread to re-read
    the CSV and refresh the network list.

    self._order keeps display order STABLE (first-seen order): a network
    keeps the same selection number even as its signal-based rank changes.
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
        """Call once per background-thread tick."""
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
                break  # STATION section: radar only cares about APs
            row = {k: (sanitize(v.strip()) if isinstance(v, str) else v) for k, v in row.items()}
            bssid = row["BSSID"]
            if not bssid:
                continue
            if bssid not in self._networks:
                self._order.append(bssid)
            self._networks[bssid] = row

        self._purge_stale()

    def _purge_stale(self):
        """Drop any BSSID whose Last_time_seen is older than STALE_TIMEOUT."""
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
        """Networks in stable discovery order (index = selection number)."""
        return [self._networks[b] for b in self._order]

    def stop(self):
        if self._proc:
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.terminate()

#========================================
#TargetListener
#========================================

class TargetListener:
    """
    start a live tshark capture to track a AP (filtered on one bssid)

    Builds a unified "stations" table (AP + every client talking to it),
    each with a live RSSI reading, used for manual direction finding and
    the sonar trend/distance indicators.
    """
    FIELDS = ["wlan.bssid", "wlan.sa", "wlan.da", "wlan.sa_resolved", "wlan.da_resolved",
              "radiotap.dbm_antsignal"]

    def __init__(self, iface):
        self.iface = iface
        self.current_bssid = None
        self.current_essid = None
        self.current_channel = None

        self._stations = {}
        self._lock = threading.Lock()
        self._switch_lock = threading.Lock()

        self._proc = None
        self._reader_thread = None
        self._stop_event = threading.Event()

    def switch_target(self, bssid, channel, essid=""):
        with self._switch_lock:
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
        now = time.time()
        with self._lock:
            entry = self._stations.get(mac)
            if entry is None:
                entry = {
                    "role": role,
                    "vendor": vendor or "",
                    "pwr": None,
                    "history": deque(maxlen=RSSI_HISTORY_LEN),
                    "ema_slow": None,
                    "ema_fast": None,
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
                if entry["ema_fast"] is None:
                    entry["ema_slow"] = float(rssi)
                    entry["ema_fast"] = float(rssi)
                else:
                    entry["ema_slow"] = EMA_SLOW_ALPHA * rssi + (1 - EMA_SLOW_ALPHA) * entry["ema_slow"]
                    entry["ema_fast"] = EMA_FAST_ALPHA * rssi + (1 - EMA_FAST_ALPHA) * entry["ema_fast"]

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
                    "ema_slow": entry["ema_slow"],
                    "ema_fast": entry["ema_fast"],
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
        with self._switch_lock:
            self._stop_current()

#===============================================================
#SNAPSHOT
#===============================================================
def build_snapshot(networks, listener):
    """
    Build the JSON-serializable dict the UI needs, from the raw radar
    network list and the current TargetListener state.

    Shape:
    {
        "networks": [{"index", "bssid", "channel", "pwr", "age", "essid", "privacy"}, ...],
        "listening": {"essid", "bssid", "channel"} or None,
        "stations": [{"mac", "role", "pwr", "avg", "distance_m", "trend",
                       "age", "vendor"}, ...]
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
            "distance_m": round(estimate_distance(info["ema_slow"]), 1) if info["ema_slow"] is not None else None,
            "trend": compute_trend(info["ema_fast"], info["ema_slow"]),
            "age": age_seconds,
            "vendor": info["vendor"] or "vendor inconnu",
        })

    return {"networks": networks_out, "listening": listening, "stations": stations_out}
