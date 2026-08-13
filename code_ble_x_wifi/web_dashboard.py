"""
web_dashboard.py

Flask + Server-Sent Events dashboard for the Valise WiFi/BLE platform.

Two independent streams (/stream/wifi and /stream/ble) so the two
background radars stay decoupled: the browser subscribes to both and
renders two panels in the same page. WebState is a tiny generic
thread-safe "latest snapshot" holder, instantiated once per radar
(wifi_state, ble_state) in valise.py -- this module doesn't know or
care what a snapshot's shape is, it just stores and republishes it.

The one write path is POST /api/wifi/target: the browser sends back the
bssid/channel/essid of whichever network row the operator clicked
"ecouter" on (already present in the snapshot it received), and this
calls listener.switch_target() directly -- the exact same entry point
the CLI keyboard loop in valise.py uses.
"""

import json
import time
import logging
import threading

from flask import Flask, Response, render_template_string, request, jsonify

WEB_HOST = "0.0.0.0"  # listen on every interface, including the hotspot's wlan0
WEB_PORT = 5000

STREAM_INTERVAL = 1.0  # how often each SSE connection is sent a fresh snapshot


class WebState:
    """
    Thread-safe holder for the latest snapshot of one radar (WiFi or BLE).
    A background thread calls set_snapshot() periodically; each SSE
    connection calls get_snapshot() on its own timer to push updates. No
    history, no diffing -- just the current full picture.
    """

    def __init__(self, empty_value):
        self._lock = threading.Lock()
        self._snapshot = empty_value

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
  <title>Valise WiFi/BLE - Dashboard</title>
  <style>
    body { font-family: monospace; background: #111; color: #eee; margin: 1em; }
    h2 { color: #7fd; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 1.5em; }
    th, td { border: 1px solid #444; padding: 4px 8px; text-align: left; font-size: 14px; }
    th { background: #222; }
    th.sortable { cursor: pointer; user-select: none; position: relative; }
    th.sortable:hover { background: #2a2a2a; }
    th .arrow { margin-left: 6px; font-size: 0.8em; color: #7fd; }
    tr.ap { color: #ffd27f; font-weight: bold; }
    #listening { margin-bottom: 1em; color: #7fd; }
    .trend-approche { color: #7fff7f; font-weight: bold; }
    .trend-eloigne { color: #ff7f7f; font-weight: bold; }
    .trend-stable { color: #999; }
    button.target-btn {
      background: #234; color: #7fd; border: 1px solid #567;
      padding: 2px 8px; cursor: pointer; font-family: monospace;
    }
    button.target-btn:hover { background: #345; }
  </style>
</head>
<body>
  <h2>WiFi - Radar</h2>
  <table id="networks">
    <thead><tr>
      <th class="sortable" data-key="index" data-type="number">No<span class="arrow"></span></th>
      <th class="sortable" data-key="bssid" data-type="string">BSSID<span class="arrow"></span></th>
      <th class="sortable" data-key="channel" data-type="number">CH<span class="arrow"></span></th>
      <th class="sortable" data-key="pwr" data-type="number">PWR<span class="arrow"></span></th>
      <th class="sortable" data-key="age" data-type="number">AGE<span class="arrow"></span></th>
      <th class="sortable" data-key="essid" data-type="string">ESSID<span class="arrow"></span></th>
      <th class="sortable" data-key="privacy" data-type="string">Chiffrement<span class="arrow"></span></th>
      <th></th>
    </tr></thead>
    <tbody></tbody>
  </table>

  <div id="listening">Ecoute en cours : aucune</div>

  <h2>WiFi - Stations (AP + clients)</h2>
  <table id="stations">
    <thead><tr>
      <th class="sortable" data-key="mac" data-type="string">MAC<span class="arrow"></span></th>
      <th class="sortable" data-key="role" data-type="string">Role<span class="arrow"></span></th>
      <th class="sortable" data-key="pwr" data-type="number">PWR<span class="arrow"></span></th>
      <th class="sortable" data-key="avg" data-type="number">AVG<span class="arrow"></span></th>
      <th class="sortable" data-key="distance_m" data-type="number">Distance<span class="arrow"></span></th>
      <th class="sortable" data-key="trend" data-type="string">Tendance<span class="arrow"></span></th>
      <th class="sortable" data-key="age" data-type="number">AGE<span class="arrow"></span></th>
      <th class="sortable" data-key="vendor" data-type="string">Vendor<span class="arrow"></span></th>
    </tr></thead>
    <tbody></tbody>
  </table>

  <h2>BLE - Appareils detectes</h2>
  <table id="ble-devices">
    <thead><tr>
      <th class="sortable" data-key="address" data-type="string">Adresse<span class="arrow"></span></th>
      <th class="sortable" data-key="label" data-type="string">Label<span class="arrow"></span></th>
      <th class="sortable" data-key="rssi" data-type="number">RSSI<span class="arrow"></span></th>
      <th class="sortable" data-key="distance_m" data-type="number">Distance<span class="arrow"></span></th>
      <th class="sortable" data-key="trend" data-type="string">Tendance<span class="arrow"></span></th>
      <th class="sortable" data-key="pdu_type" data-type="string">PDU<span class="arrow"></span></th>
      <th class="sortable" data-key="last_channel" data-type="number">Ch<span class="arrow"></span></th>
      <th class="sortable" data-key="seen_count" data-type="number">Vus<span class="arrow"></span></th>
      <th class="sortable" data-key="age_s" data-type="number">AGE<span class="arrow"></span></th>
    </tr></thead>
    <tbody></tbody>
  </table>

  <script>
    // EventSource is a native browser API: it opens one long-lived HTTP
    // connection and fires onmessage each time the server writes a new
    // "data: ...\\n\\n" block. No library needed. Two independent
    // connections keep the WiFi and BLE panels fully decoupled.
    const wifiSource = new EventSource('/stream/wifi');
    const bleSource = new EventSource('/stream/ble');

    // ---- Tri par colonne (3 etats) ------------------------------------
    // On garde en memoire le dernier snapshot recu pour chaque tableau,
    // ainsi que l'etat de tri courant (colonne + etat 0/1/2). Comme le
    // flux SSE renvoie systematiquement la liste "fraiche" (etat 0 =
    // ordre serveur), on n'a pas besoin de sauvegarder un ordre initial
    // separement : il suffit de retrier lastData a chaque clic.
    const sortState = {
      networks: { key: null, state: 0 },
      stations: { key: null, state: 0 },
      'ble-devices': { key: null, state: 0 },
    };
    const lastData = {
      networks: [],
      stations: [],
      'ble-devices': [],
    };

    function applySort(tableId, rows) {
      const st = sortState[tableId];
      if (!st.key || st.state === 0) return rows;

      const header = document.querySelector(`#${tableId} th[data-key="${st.key}"]`);
      const type = header ? header.dataset.type : 'string';

      const sorted = rows.slice().sort((a, b) => {
        let valA = a[st.key];
        let valB = b[st.key];

        // Valeurs manquantes (null/undefined) toujours en fin, peu importe le sens
        if (valA == null && valB == null) return 0;
        if (valA == null) return 1;
        if (valB == null) return -1;

        if (type === 'number') {
          valA = parseFloat(valA);
          valB = parseFloat(valB);
        } else {
          valA = String(valA).toLowerCase();
          valB = String(valB).toLowerCase();
        }

        if (valA < valB) return st.state === 1 ? -1 : 1;
        if (valA > valB) return st.state === 1 ? 1 : -1;
        return 0;
      });
      return sorted;
    }

    function updateArrows(tableId) {
      const st = sortState[tableId];
      document.querySelectorAll(`#${tableId} th.sortable`).forEach(h => {
        const arrow = h.querySelector('.arrow');
        if (h.dataset.key === st.key && st.state !== 0) {
          arrow.textContent = st.state === 1 ? '▲' : '▼';
        } else {
          arrow.textContent = '';
        }
      });
    }

    function setupSortableHeaders(tableId, renderFn) {
      document.querySelectorAll(`#${tableId} th.sortable`).forEach(header => {
        header.addEventListener('click', () => {
          const key = header.dataset.key;
          const st = sortState[tableId];

          if (st.key !== key) {
            // Nouvelle colonne cliquee : on repart de zero sur elle
            st.key = key;
            st.state = 0;
          }
          st.state = (st.state + 1) % 3; // 0 -> 1 -> 2 -> 0

          updateArrows(tableId);
          renderFn(lastData[tableId]);
        });
      });
    }
    // ---------------------------------------------------------------

    wifiSource.onmessage = function(event) {
      const snap = JSON.parse(event.data);
      lastData.networks = snap.networks;
      lastData.stations = snap.stations;
      renderNetworks(snap.networks);
      renderListening(snap.listening);
      renderStations(snap.stations);
    };

    bleSource.onmessage = function(event) {
      const devices = JSON.parse(event.data);
      lastData['ble-devices'] = devices;
      renderBleDevices(devices);
    };

    function switchTarget(bssid, channel, essid) {
      fetch('/api/wifi/target', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bssid, channel, essid }),
      });
    }

    function renderNetworks(networks) {
      const tbody = document.querySelector('#networks tbody');
      tbody.innerHTML = '';
      for (const net of applySort('networks', networks)) {
        const row = document.createElement('tr');
        const btn = document.createElement('button');
        btn.className = 'target-btn';
        btn.textContent = 'ecouter';
        btn.onclick = () => switchTarget(net.bssid, net.channel, net.essid);

        row.innerHTML = `<td>${net.index}</td><td>${net.bssid}</td><td>${net.channel}</td>
                          <td>${net.pwr}</td><td>${net.age ?? '?'}s</td>
                          <td>${net.essid}</td><td>${net.privacy}</td>`;
        const btnCell = document.createElement('td');
        btnCell.appendChild(btn);
        row.appendChild(btnCell);
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
      for (const st of applySort('stations', stations)) {
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

    function renderBleDevices(devices) {
      const tbody = document.querySelector('#ble-devices tbody');
      tbody.innerHTML = '';
      for (const dev of applySort('ble-devices', devices)) {
        const row = document.createElement('tr');
        const distStr = dev.distance_m != null ? `${dev.distance_m}m` : '?';
        const trendStr = dev.trend || '?';
        row.innerHTML = `<td>${dev.address}</td><td>${dev.label}</td>
                          <td>${dev.rssi ?? '?'}</td><td>${distStr}</td>
                          <td class="trend-${trendStr}">${trendStr}</td>
                          <td>${dev.pdu_type ?? '?'}</td><td>${dev.last_channel ?? '?'}</td>
                          <td>${dev.seen_count}</td><td>${dev.age_s}s</td>`;
        tbody.appendChild(row);
      }
    }

    // Attacher les ecouteurs de clic une fois le DOM pret
    setupSortableHeaders('networks', renderNetworks);
    setupSortableHeaders('stations', renderStations);
    setupSortableHeaders('ble-devices', renderBleDevices);
  </script>
</body>
</html>
"""


def create_web_app(wifi_state, ble_state, listener):
    """
    Flask app factory.

    wifi_state / ble_state: WebState instances holding the latest
    snapshot of each radar, kept up to date by the background threads in
    valise.py.
    listener: the live TargetListener instance, needed so the POST route
    can call switch_target() directly -- the same entry point the
    keyboard loop uses, so both paths always go through the exact same
    (now thread-safe) code.
    """
    app = Flask(__name__)

    # Silence Werkzeug's per-request logging: it would otherwise print to
    # stdout and corrupt the terminal's ANSI redraw.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/stream/wifi")
    def stream_wifi():
        def event_stream():
            while True:
                snapshot = wifi_state.get_snapshot()
                yield f"data: {json.dumps(snapshot)}\n\n"
                time.sleep(STREAM_INTERVAL)

        return Response(
            event_stream(),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.route("/stream/ble")
    def stream_ble():
        def event_stream():
            while True:
                snapshot = ble_state.get_snapshot()
                yield f"data: {json.dumps(snapshot)}\n\n"
                time.sleep(STREAM_INTERVAL)

        return Response(
            event_stream(),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.route("/api/wifi/target", methods=["POST"])
    def set_wifi_target():
        data = request.get_json(silent=True) or {}
        bssid = data.get("bssid")
        channel = data.get("channel")
        essid = data.get("essid", "")

        if not bssid or not channel:
            return jsonify({"ok": False, "error": "bssid et channel requis"}), 400

        listener.switch_target(bssid, channel, essid)
        return jsonify({"ok": True})

    return app


def start_web_server(wifi_state, ble_state, listener):
    """
    Run the Flask app in a daemon background thread. threaded=True allows
    multiple simultaneous /stream connections (phone + tablet, etc.).
    use_reloader=False is required since we're already inside a
    background thread.
    """
    app = create_web_app(wifi_state, ble_state, listener)

    def run():
        app.run(host=WEB_HOST, port=WEB_PORT, threaded=True, use_reloader=False)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread