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

import os
import json
import time
import logging
import threading

from flask import Flask, Response, render_template_string, request, jsonify, send_from_directory

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
with open("dashboard.html", "r", encoding="utf-8") as f:
    DASHBOARD_HTML = f.read()


def create_web_app(modules, listener):
    """
    Flask app factory.

    modules : list of WebStates
    modules contains the states that will themselves contain the snapshot 
    of values needed too be displayed

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

    @app.route("/chart.umd.min.js")
    def chart_js():
        return send_from_directory(
            os.path.dirname(os.path.abspath(__file__)),
            "chart.umd.min.js"
        )

    @app.route("/chart.umd.min.js.map")
    def chart_js_map():
        return send_from_directory(
            os.path.dirname(os.path.abspath(__file__)),
            "chart.umd.min.js.map"
        )

    @app.route("/stream/wifi")
    def stream_wifi():
        def event_stream():
            while True:
                snapshot = modules["wifi_state"].get_snapshot()
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
                snapshot = modules["ble_state"].get_snapshot()
                yield f"data: {json.dumps(snapshot)}\n\n"
                time.sleep(STREAM_INTERVAL)

        return Response(
            event_stream(),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.route("/stream/hackrf")
    def stream_hackrf():
        def event_stream():
            while True:
                snapshot = modules["hackrf_state"].get_snapshot()
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


def start_web_server(modules, listener):
    """
    Run the Flask app in a daemon background thread. threaded=True allows
    multiple simultaneous /stream connections (phone + tablet, etc.).
    use_reloader=False is required since we're already inside a
    background thread.
    """
    app = create_web_app(modules, listener)

    def run():
        app.run(host=WEB_HOST, port=WEB_PORT, threaded=True, use_reloader=False)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread
