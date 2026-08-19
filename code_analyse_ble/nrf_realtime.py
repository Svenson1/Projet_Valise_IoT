#!/usr/bin/env python3
"""
nrf_realtime.py

Radar BLE pour le nRF52840-DK -- meme
pipeline que ble_realtime.py / nrf_capture.BleCapture + ble_radar.BleRadar,
avec en plus un dashboard web (Flask + Server-Sent Events) pour suivre le
RSSI en temps reel sur telephone/tablette pendant qu'on tourne l'antenne
a la main.

Architecture identique a wifi_realtime.py :
  - un seul thread de fond (celui de BleCapture, deja existant) pour la
    lecture asynchrone des paquets
  - la boucle principale reste synchrone : elle draine la queue, appelle
    radar.build_snapshot() UNE fois par tick, et cette meme liste de
    devices alimente a la fois le rendu terminal (render()) et le
    dashboard web (web_state.set_snapshot())
  - la seule entree clavier est 'q' + Entree pour arreter, geree via
    select.select() avec timeout, sans thread dedie.

"""

import json
import logging
import select
import sys
import threading
import time
from queue import Empty

from flask import Flask, Response, render_template_string

from nrf_capture import BleCapture
from ble_radar import BleRadar

REFRESH_INTERVAL_S = 2.5
CLEAR_SCREEN = "\x1b[2J\x1b[H"   # ANSI clear

# Devices weaker than this are hidden None for desactivate.
MIN_RSSI_DBM = -70
MAX_AGE_S = 0

# --- Web dashboard settings -------------------------------------------------
WEB_HOST = "0.0.0.0"  # toutes les interfaces, dont celle du hotspot Pi
WEB_PORT = 5000
STREAM_INTERVAL = 1.0  # frequence d'envoi SSE, independante de REFRESH_INTERVAL_S


def render(snapshot):
    lines = [CLEAR_SCREEN]
    lines.append("BLE radar (nRF52840-DK / antenne directionnelle) - 'q' + Enter pour arreter")
    lines.append(
        f"{'Address':<20}{'Label':<24}{'RSSI':>7}{'Dist(m)':>9}"
        f"{'Trend':>10}{'PDU':>16}{'Seen':>7}{'Ch':>5}{'Age(s)':>8}"
    )

    if not snapshot:
        lines.append("(aucun device detecte pour le moment)")
    for dev in snapshot:
        lines.append(
            f"{dev['address']:<20}"
            f"{dev['label']:<24}"
            f"{dev['rssi'] if dev['rssi'] is not None else '-':>7}"
            f"{dev['distance_m'] if dev['distance_m'] is not None else '-':>9}"
            f"{dev['trend']:>10}"
            f"{dev['pdu_type'] or '-':>16}"
            f"{dev['seen_count']:>7}"
            f"{dev['last_channel'] if dev['last_channel'] is not None else '-':>5}"
            f"{dev['age_s']:>8}"
        )

    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()


def filter_snapshot(snapshot):
    """Applique MIN_RSSI_DBM. Utilise a la fois par le terminal et le web
    pour garder les deux affichages coherents."""
    if MIN_RSSI_DBM is None or MAX_AGE_S is None:
        return snapshot
    return [d for d in snapshot if d["rssi"] is not None and d["rssi"] >= MIN_RSSI_DBM and d["age_s"] is not None and d["age_s"] <= MAX_AGE_S]


# =============================================================================
# WEB SERVER: Flask + Server-Sent Events, dans son propre thread de fond
# =============================================================================

class WebState:
    """
    Meme pattern que wifi_realtime.py : holder thread-safe pour le dernier
    snapshot (ici une liste de devices, pas un dict). La boucle principale
    appelle set_snapshot() une fois par tick ; l'endpoint SSE appelle
    get_snapshot() sur son propre timer.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._snapshot = []

    def set_snapshot(self, snapshot):
        with self._lock:
            self._snapshot = snapshot

    def get_snapshot(self):
        with self._lock:
            return self._snapshot


# Dashboard mono-page, sans dependance externe (pas d'acces internet sur le
# hotspot) : EventSource natif du navigateur + re-rendu HTML brut a chaque
# message. La ligne au RSSI le plus fort est surlignee -- utile pendant le
# balayage pour reperer le pic d'un coup d'oeil.
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Valise BLE - nRF52840-DK</title>
  <style>
    body { font-family: monospace; background: #111; color: #eee; margin: 1em; }
    h2 { color: #7fd; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #444; padding: 4px 8px; text-align: left; font-size: 14px; }
    th { background: #222; }
    tr.peak { background: #234; color: #ffd27f; font-weight: bold; }
    .trend-approche { color: #7fff7f; font-weight: bold; }
    .trend-eloigne { color: #ff7f7f; font-weight: bold; }
    .trend-stable { color: #999; }
    #status { margin-bottom: 1em; color: #7fd; }
  </style>
</head>
<body>
  <h2>nRF52840-DK - antenne directionnelle</h2>
  <div id="status">En attente de donnees...</div>
  <table id="devices">
    <thead><tr><th>Adresse</th><th>Label</th><th>RSSI</th><th>Distance</th>
      <th>Tendance</th><th>PDU</th><th>Ch</th><th>Vus</th><th>AGE</th></tr></thead>
    <tbody></tbody>
  </table>

  <script>
    const source = new EventSource('/stream');

    source.onmessage = function(event) {
      const devices = JSON.parse(event.data);
      renderDevices(devices);
    };

    function renderDevices(devices) {
      const status = document.getElementById('status');
      const tbody = document.querySelector('#devices tbody');
      tbody.innerHTML = '';

      if (!devices.length) {
        status.textContent = 'Aucun device detecte pour le moment';
        return;
      }
      status.textContent = `${devices.length} device(s) detecte(s)`;

      // Repere le RSSI max pour surligner la ligne correspondante.
      let peakRssi = null;
      for (const dev of devices) {
        if (dev.rssi != null && (peakRssi === null || dev.rssi > peakRssi)) {
          peakRssi = dev.rssi;
        }
      }

      for (const dev of devices) {
        const row = document.createElement('tr');
        if (peakRssi !== null && dev.rssi === peakRssi) row.classList.add('peak');
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
  </script>
</body>
</html>
"""


def create_web_app(web_state):
    app = Flask(__name__)

    # Silence le logging Werkzeug par requete : il corromprait sinon le
    # redraw ANSI du terminal.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/stream")
    def stream():
        def event_stream():
            while True:
                snapshot = web_state.get_snapshot()
                yield f"data: {json.dumps(snapshot)}\n\n"
                time.sleep(STREAM_INTERVAL)

        return Response(
            event_stream(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    return app


def start_web_server(web_state):
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
    capture = BleCapture()
    radar = BleRadar()
    capture.start_capture()

    web_state = WebState()
    start_web_server(web_state)
    print(f"Dashboard web disponible sur http://192.168.4.1:{WEB_PORT}/")

    try:
        while True:
            while True:
                try:
                    packet = capture.queue.get_nowait()
                except Empty:
                    break
                radar.ingest(packet)

            snapshot = filter_snapshot(radar.build_snapshot())
            web_state.set_snapshot(snapshot)
            render(snapshot)

            ready, _, _ = select.select([sys.stdin], [], [], REFRESH_INTERVAL_S)
            if ready and sys.stdin.readline().strip() == "q":
                break
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop_capture()


if __name__ == "__main__":
    main()