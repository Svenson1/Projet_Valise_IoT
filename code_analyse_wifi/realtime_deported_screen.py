#!/usr/bin/env python3
"""
wifi_realtime.py

Real-time Wi-Fi scanning pipeline using two interfaces in monitor mode:
  - a "radar" interface doing continuous channel hopping (airodump-ng)
    to list every visible network
  - a "target" interface locked on one manually-selected channel/BSSID,
    live-capturing (tshark -i, no intermediate pcap) the AP and its
    associated clients with RSSI, for manual direction
    finding and a "sonar" approach/retreat indicator

Threading: a single background thread handles the target's live tshark
capture (the only truly asynchronous work -- packets arrive independently
of the display cycle). Everything else (radar CSV polling, keyboard input)
runs synchronously in the main loop via select.select() with a timeout.

Single source of truth: build_snapshot() computes all display data once
per tick, as a plain JSON-serializable dict. Both render_terminal() (ANSI)
and the Flask/SSE web dashboard consume that same dict without
recomputing anything.

Web dashboard: a Flask app runs in a background thread, pushing the
latest snapshot to connected browsers (phone/tablet on the Pi's hotspot)
via Server-Sent Events.

Sonar feature: a dual-EMA RSSI trend detector (approaching / moving away
/ stable) plus an informational distance estimate.
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

# Networks not seen (per airodump-ng's Last_time_seen) for longer than this
# are dropped from the radar table. airodump-ng's CSV never forgets a BSSID
# on its own, so active pruning is needed here (unlike TargetListener).
STALE_TIMEOUT = 60  # seconds

# Samples kept per station for the simple moving average. 5 is a
# compromise between smoothing per-packet noise and staying responsive.
RSSI_HISTORY_LEN = 5

# --- Web dashboard settings -------------------------------------------------
WEB_HOST = "0.0.0.0"  # listen on every interface, including the hotspot's wlan0
WEB_PORT = 5000

# --- Sonar trend detection (dual EMA) ---------------------------------------
EMA_FAST_ALPHA = 0.5    # reacts quickly to recent samples
EMA_SLOW_ALPHA = 0.05   # slow-moving baseline
TREND_HYSTERESIS_DB = 1.5  # gap (dB) required before a trend is reported

# --- Distance estimation (log-distance path loss model) --------------------
# d = 10 ^ ((P0 - PWR_filtered) / (10 * n))
# Generic literature values, NOT calibrated for this hardware/environment:
# treat this as a rough order of magnitude, not a precise measurement.
# Purely informational -- independent from the trend detection above.
PATH_LOSS_P0 = -38.0   # dBm at 1m
PATH_LOSS_N = 3.2      # typical indoor path loss exponent

RADAR_FIELDNAMES = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed',
                     'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV',
                     'LAN_IP', 'ID_length', 'ESSID', 'Key']

# ASCII control chars (0x00-0x1F minus tab, plus 0x7F) -- notably \r and ESC,
# which a terminal would act on instead of printing.
CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def sanitize(text):
    """
    Strip control characters from radio-sourced strings (ESSID, resolved
    vendor names). A malformed or malicious AP can embed \\r or ANSI escape
    sequences that would otherwise corrupt the terminal redraw.
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
    log-distance path loss model (Mazuelas et al., 2009). Informational
    only.
    """
    if pwr_filtered is None:
        return None
    return 10 ** ((PATH_LOSS_P0 - pwr_filtered) / (10 * PATH_LOSS_N))


def compute_trend(ema_fast, ema_slow):
    """
    Compare the fast and slow RSSI EMA to flag an approach/retreat trend.
    A hysteresis band (TREND_HYSTERESIS_DB) absorbs ordinary RF noise so
    the indicator doesn't flicker.
    """
    if ema_fast is None or ema_slow is None:
        return None
    delta = ema_fast - ema_slow
    if delta > TREND_HYSTERESIS_DB:
        return "approche"
    elif delta < -TREND_HYSTERESIS_DB:
        return "eloigne"
    return "stable"


# =============================================================================
# RADAR: synchronous CSV polling, called from the main loop
# =============================================================================

class DiscoveryRadar:
    """
    Runs a continuous hopping airodump-ng and exposes poll(), called from
    the main loop to re-read the CSV and refresh the network list. No
    thread/lock needed: single caller.

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
        """Call once per main-loop tick."""
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


# =============================================================================
# TARGET LISTENER: the script's only background thread -- live tshark capture
# =============================================================================

class TargetListener:
    """
    Owns interface B. switch_target() locks the radio channel, then (re)starts
    a live tshark capture (-i, no intermediate pcap) filtered on one BSSID.
    A background thread reads its output as packets arrive -- the only place
    a thread is truly needed, since packet arrival is asynchronous.

    Builds a unified "stations" table (AP + every client talking to it),
    each with a live RSSI reading, used for manual direction finding and
    the sonar trend/distance indicators.

    AP vs client, determined per captured frame (no separate lookup):
      - Beacon frames: source (wlan.sa) == BSSID -> that's the AP.
      - Data frames: BSSID as destination (wlan.da) -> source (wlan.sa)
        is a client sending to the AP (uplink).

    RSSI source: radiotap's `dbm_antsignal`, added by OUR OWN adapter at
    capture time -- signal strength of that
    frame as seen by our antenna, regardless of who transmitted it.

    Stations are never evicted (no timeout); `last_seen` just feeds an
    informational "age" column.
    """

    # Field order must match the "-e" flags built in switch_target().
    FIELDS = ["wlan.bssid", "wlan.sa", "wlan.da", "wlan.sa_resolved", "wlan.da_resolved",
              "radiotap.dbm_antsignal"]

    def __init__(self, iface):
        self.iface = iface
        self.current_bssid = None
        self.current_essid = None
        self.current_channel = None

        # mac -> station dict: role ("AP"/"CLIENT"), vendor, pwr (latest
        # RSSI), history (deque for the SMA), ema_fast/ema_slow (sonar
        # trend + distance inputs), last_seen.
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
        Create or refresh one station's entry. Acquires the lock itself
        (called from multiple points in _read_loop).

        ema_fast/ema_slow are recursive (depend on previous state), unlike
        the SMA `history`, so they're updated here on arrival rather than
        recomputed at snapshot time. Both are bootstrapped to the first
        RSSI sample seen.
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
        """
        Plain-dict snapshot of the stations table, safe to read without
        the lock afterwards. The SMA is computed here (cheap, stateless);
        ema_fast/ema_slow are returned as already-stored values.
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
        self._stop_current()


# =============================================================================
# SNAPSHOT: the single function computing display data once per tick,
# consumed by both render_terminal() and the web server.
# =============================================================================

def build_snapshot(networks, listener):
    """
    Build the JSON-serializable dict the UI needs, from the raw radar
    network list and the current TargetListener state. This is the only
    place ages are computed, stations sorted, and numbers rounded.

    Shape:
    {
        "networks": [{"index", "bssid", "channel", "pwr", "age", "essid", "privacy"}, ...],
        "listening": {"essid", "bssid", "channel"} or None,
        "stations": [{"mac", "role", "pwr", "avg", "distance_m", "trend",
                       "age", "vendor"}, ...]
    }
    distance_m and trend are computed independently from ema_slow/ema_fast.
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


# =============================================================================
# TERMINAL RENDERING: formats the snapshot as ANSI text
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

    lines.append(f"{'MAC':<20}{'ROLE':<8}{'PWR':<7}{'AVG':<7}{'DIST':<8}{'TENDANCE':<10}{'AGE':<6}{'VENDOR'}")
    if not snapshot["stations"]:
        lines.append("(aucune trame recue pour le moment)")
    else:
        for st in snapshot["stations"]:
            pwr_str = f"{st['pwr']}" if st["pwr"] is not None else "?"
            avg_str = f"{st['avg']}" if st["avg"] is not None else "?"
            dist_str = f"{st['distance_m']}m" if st["distance_m"] is not None else "?"
            trend_str = st["trend"] or "?"
            age_str = f"{st['age']}s"
            lines.append(f"{st['mac']:<20}{st['role']:<8}{pwr_str:<7}{avg_str:<7}"
                         f"{dist_str:<8}{trend_str:<10}{age_str:<6}{st['vendor']}")

    frame = "\033[2J\033[3J\033[H" + "\n".join(lines) + "\n"
    sys.stdout.write(frame)
    sys.stdout.flush()


# =============================================================================
# WEB SERVER: Flask + Server-Sent Events, in its own background thread
# =============================================================================

class WebState:
    """
    Thread-safe holder for the latest snapshot. The main loop calls
    set_snapshot() once per tick; the SSE endpoint calls get_snapshot() on
    its own timer to push updates. No history, no diffing -- just the
    current full picture, refreshed wholesale each tick.
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
# has no internet access): vanilla JS with the browser's built-in
# EventSource API, plain HTML tables re-rendered on every message.
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
    .trend-approche { color: #7fff7f; font-weight: bold; }
    .trend-eloigne { color: #ff7f7f; font-weight: bold; }
    .trend-stable { color: #999; }
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
    <thead><tr><th>MAC</th><th>Role</th><th>PWR</th><th>AVG</th><th>Distance</th><th>Tendance</th><th>AGE</th><th>Vendor</th></tr></thead>
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
        const distStr = st.distance_m != null ? `${st.distance_m}m` : '?';
        const trendStr = st.trend || '?';
        row.innerHTML = `<td>${st.mac}</td><td>${st.role}</td>
                          <td>${st.pwr ?? '?'}</td><td>${st.avg ?? '?'}</td>
                          <td>${distStr}</td><td class="trend-${trendStr}">${trendStr}</td>
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
    Flask app with two routes: GET / (dashboard page) and GET /stream
    (the SSE endpoint). Kept as a factory so web_state -- created in
    main()
    """
    app = Flask(__name__)

    # Silence Werkzeug's per-request logging: it would otherwise print to
    # stdout and corrupt the terminal's ANSI redraw.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/stream")
    def stream():
        def event_stream():
            while True:
                snapshot = web_state.get_snapshot()
                # SSE format: "data: <payload>\n\n" -- the blank line marks
                # the message as complete.
                yield f"data: {json.dumps(snapshot)}\n\n"
                time.sleep(REFRESH_INTERVAL)

        return Response(
            event_stream(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",  # prevent reverse-proxy buffering
            },
        )

    return app


def start_web_server(web_state):
    """
    Run the Flask app in a daemon background thread. threaded=True allows
    multiple simultaneous /stream connections. use_reloader=False is
    required since we're already inside a background thread.
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

    # Started once, before the main loop; lives for the whole run and only
    # ever reads whatever build_snapshot() last produced.
    web_state = WebState()
    start_web_server(web_state)
    print(f"Dashboard web disponible sur http://192.168.4.1:{WEB_PORT}/")

    try:
        while True:
            radar.poll()
            networks = radar.get_networks()

            # select() waits up to REFRESH_INTERVAL seconds for keyboard
            # input -- avoids a dedicated thread+queue while reacting
            # faster than a fixed sleep() if the operator types early.
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
        # Safety net: reset the terminal in case a subprocess left it in a
        # broken state (raw mode, no echo...).
        subprocess.run(["stty", "sane"])
        print("Pense a repasser les interfaces en mode managed :")
        print(f"  sudo airmon-ng stop {radar_iface}")
        print(f"  sudo airmon-ng stop {target_iface}")


if __name__ == "__main__":
    main()