#!/usr/bin/env python3
"""
valise.py
Single entry point for the Valise WiFi/BLE platform. Ties together the
WiFi radar (wifi_radar.py), the BLE radar (ble_capture.py + ble_radar.py)
and the web dashboard (web_dashboard.py) into one process.

Threading model:
  - wifi_bg_loop(): ONE background thread. Polls DiscoveryRadar, builds
    the WiFi snapshot, publishes it to wifi_state. This is the only
    thread that ever touches the DiscoveryRadar object directly.
  - ble_bg_loop(): ONE background thread, doing two things at different
    paces in the same loop:
      * drains ble_capture.queue continuously (short timeout) so packets
        are ingested as they arrive rather than bursting once every
        REFRESH_INTERVAL
      * publishes a fresh BLE snapshot to ble_state every REFRESH_INTERVAL
  - Flask (its own background thread, started by web_dashboard.py):
    serves the dashboard, streams both snapshots over SSE, and exposes
    POST /api/wifi/target for the "ecouter" button.
  - Main thread: keyboard loop (select.select on stdin) for picking a
    WiFi network to listen to from the terminal, AND the optional
    terminal debug display (combined WiFi + BLE), refreshed on the same
    tick. Both the keyboard loop and the web button call
    listener.switch_target() -- the exact same function, made safe for
    concurrent callers by the _switch_lock added in wifi_radar.py.

Usage:
    sudo python3 valise.py
"""

import os
import sys
import select
import subprocess
import threading
import time
from queue import Empty

import wifi_radar
from wifi_radar import DiscoveryRadar, TargetListener
from ble_capture import BleCapture
from ble_radar import BleRadar
from hackrf_capture import HackRfCapture, HackRfConfig
from web_dashboard import WebState, start_web_server, WEB_PORT

REFRESH_INTERVAL =2.0     # how often each radar publishes a fresh snapshot
TERMINAL_TICK = 2.0        # how often the terminal display / keyboard loop wakes up


# =============================================================================
# BACKGROUND THREADS
# =============================================================================

def wifi_bg_loop(radar, listener, wifi_state, stop_event):
    """Owns DiscoveryRadar: poll -> build_snapshot -> publish, on a timer."""
    while not stop_event.is_set():
        radar.poll()
        networks = radar.get_networks()
        snapshot = wifi_radar.build_snapshot(networks, listener)
        wifi_state.set_snapshot(snapshot)
        stop_event.wait(REFRESH_INTERVAL)


def ble_bg_loop(ble_capture, ble_radar_obj, ble_state, stop_event):
    """
    Drains the BLE capture queue continuously so packets are ingested as
    they arrive, while publishing a snapshot to ble_state only every
    REFRESH_INTERVAL -- decoupling ingestion rate from publish rate.
    """
    last_publish = 0.0
    while not stop_event.is_set():
        try:
            packet = ble_capture.queue.get(timeout=0.5)
            ble_radar_obj.ingest(packet)
        except Empty:
            pass

        now = time.time()
        if now - last_publish >= REFRESH_INTERVAL:
            ble_state.set_snapshot(ble_radar_obj.build_snapshot())
            last_publish = now

def hackrf_bg_loop(hackrf_capture, hackrf_state, stop_event):
    while not stop_event.is_set():
        snapshot = hackrf_capture.build_snapshot()
        hackrf_state.set_snapshot(snapshot)
        stop_event.wait(REFRESH_INTERVAL)


# =============================================================================
# TERMINAL DISPLAY (debug fallback, mirrors the web dashboard's content)
# =============================================================================

def render_terminal(wifi_snapshot, ble_snapshot):
    lines = []
    lines.append("=" * 110)
    lines.append(" WIFI - RADAR (tape un numero + Entree pour ecouter un reseau)")
    lines.append("=" * 110)
    lines.append(f"{'No':<4}{'BSSID':<20}{'CH':<5}{'PWR':<6}{'AGE':<6}{'ESSID':<28}{'CHIFFREMENT'}")
    for net in wifi_snapshot["networks"]:
        age_str = f"{net['age']}s" if net["age"] is not None else "?"
        essid = net["essid"][:26]
        lines.append(f"{net['index']:<4}{net['bssid']:<20}{net['channel']:<5}"
                     f"{net['pwr']:<6}{age_str:<6}{essid:<28}{net['privacy']}")

    lines.append("")
    listening = wifi_snapshot["listening"]
    if listening:
        lines.append(f" ECOUTE EN COURS : {listening['essid']} "
                      f"({listening['bssid']}) - canal {listening['channel']}")
    else:
        lines.append(" ECOUTE EN COURS : aucune (choisis un reseau ci-dessus)")
    lines.append("-" * 110)

    lines.append(f"{'MAC':<20}{'ROLE':<8}{'PWR':<7}{'AVG':<7}{'DIST':<8}{'TENDANCE':<10}{'AGE':<6}{'VENDOR'}")
    if not wifi_snapshot["stations"]:
        lines.append("(aucune trame recue pour le moment)")
    else:
        for st in wifi_snapshot["stations"]:
            pwr_str = f"{st['pwr']}" if st["pwr"] is not None else "?"
            avg_str = f"{st['avg']}" if st["avg"] is not None else "?"
            dist_str = f"{st['distance_m']}m" if st["distance_m"] is not None else "?"
            trend_str = st["trend"] or "?"
            age_str = f"{st['age']}s"
            lines.append(f"{st['mac']:<20}{st['role']:<8}{pwr_str:<7}{avg_str:<7}"
                         f"{dist_str:<8}{trend_str:<10}{age_str:<6}{st['vendor']}")

    lines.append("")
    lines.append("=" * 110)
    lines.append(" BLE - APPAREILS DETECTES")
    lines.append("=" * 110)
    lines.append(
        f"{'Address':<20}{'Label':<24}{'RSSI':>7}{'Dist(m)':>9}"
        f"{'Trend':>10}{'PDU':>16}{'Seen':>7}{'Ch':>5}{'Age(s)':>8}"
    )
    if not ble_snapshot:
        lines.append("(aucun appareil detecte pour le moment)")
    for dev in ble_snapshot:
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

    # --- WiFi interface setup (interactive, once, at startup) --------------
    radar_iface_raw, target_iface_raw = wifi_radar.choose_two_interfaces()
    run_prefix = wifi_radar.make_run_prefix()

    print("Nettoyage des processus concurrents et passage en mode monitor...")
    subprocess.run(["sudo", "airmon-ng", "check", "kill"], stdin=subprocess.DEVNULL)
    radar_iface = wifi_radar.enable_monitor_mode(radar_iface_raw)
    target_iface = wifi_radar.enable_monitor_mode(target_iface_raw)
    print(f"Radar : {radar_iface}   |   Cible : {target_iface}")

    radar = DiscoveryRadar(radar_iface, csv_prefix=run_prefix)
    listener = TargetListener(target_iface)
    radar.start()

    # --- BLE setup -----------------------------------------------------------
    ble_capture = BleCapture()
    ble_radar_obj = BleRadar()
    ble_capture.start_capture()

    # --- HackRF setup -----------------------------------------------------------
    hackrf_capture = HackRfCapture()
    hackrf_capture.start_capture()
    hackrf_listener = HackRfConfig(hackrf_capture)

    # --- Shared state + background threads ------------------------------
    modules = {}
    wifi_state = WebState(empty_value={"networks": [], "listening": None, "stations": []})
    ble_state = WebState(empty_value=[])
    hackrf_state = WebState(empty_value={"values_x": [], "values_y": [], "values_max": []})

    modules = {
        "wifi_state": wifi_state,
        "ble_state": ble_state,
        "hackrf_state": hackrf_state,
    }

    stop_event = threading.Event()
    wifi_thread = threading.Thread(target=wifi_bg_loop, args=(radar, listener, wifi_state, stop_event), daemon=True)
    ble_thread = threading.Thread(target=ble_bg_loop, args=(ble_capture, ble_radar_obj, ble_state, stop_event), daemon=True)
    hackrf_thread = threading.Thread(target=hackrf_bg_loop, args=(hackrf_capture, hackrf_state, stop_event), daemon=True)
    wifi_thread.start()
    ble_thread.start()
    hackrf_thread.start()

    # --- Web dashboard -----------------------------------------------------
    start_web_server(modules, listener, hackrf_listener)
    print(f"Dashboard web disponible sur http://192.168.4.1:{WEB_PORT}/")
    print("Affichage terminal (debug) actif -- 'q' + Entree pour quitter.\n")
    time.sleep(1)  # let the first snapshots land before the first redraw

    try:
        while True:
            wifi_snapshot = wifi_state.get_snapshot()
            ble_snapshot = ble_state.get_snapshot()
            # render_terminal(wifi_snapshot, ble_snapshot)

            # select() waits up to TERMINAL_TICK seconds for keyboard input.
            # Network numbers are resolved against the snapshot currently on
            # screen, so what the operator sees matches what gets targeted.
            ready, _, _ = select.select([sys.stdin], [], [], TERMINAL_TICK)
            if ready:
                raw = sys.stdin.readline().strip()
                if raw == "q":
                    break
                if raw.isdigit():
                    idx = int(raw)
                    networks = wifi_snapshot["networks"]
                    if 0 <= idx < len(networks):
                        net = networks[idx]
                        listener.switch_target(net["bssid"], net["channel"], net["essid"])
    except KeyboardInterrupt:
        pass
    finally:
        print("\nArret en cours...")
        stop_event.set()
        radar.stop()
        listener.stop()
        ble_capture.stop_capture()
        hackrf_capture.stop_capture()
        wifi_thread.join(timeout=2)
        ble_thread.join(timeout=2)
        # Safety net: reset the terminal in case a subprocess left it in a
        # broken state (raw mode, no echo...).
        subprocess.run(["stty", "sane"])
        print("Pense a repasser les interfaces en mode managed :")
        print(f"  sudo airmon-ng stop {radar_iface}")
        print(f"  sudo airmon-ng stop {target_iface}")


if __name__ == "__main__":
    main()
