"""
Terminal radar display for the nRF52840-DK
Identical to realtime.py except for the capture
source import - ble_radar.py and the display logic are fully reused
unmodified, since nrf_capture.BleCapture exposes the same packet shape.
"""

import select
import sys
from queue import Empty

from nrf_capture import BleCapture   # <- only change vs realtime.py
from ble_radar import BleRadar

REFRESH_INTERVAL_S = 2.5
CLEAR_SCREEN = "\x1b[2J\x1b[H"   # ANSI clear

# Devices weaker than this are hidden from display (still tracked
# internally in ble_radar.py, just not shown). Set to None to disable.
MIN_RSSI_DBM = -85


def render(snapshot):
    lines = [CLEAR_SCREEN]
    lines.append("BLE radar (nRF52840-DK / antenne directionnelle) - 'q' + Enter pour arreter")
    lines.append(
        f"{'Address':<20}{'Label':<24}{'RSSI':>7}{'Dist(m)':>9}"
        f"{'Trend':>10}{'PDU':>16}{'Seen':>7}{'Ch':>5}{'Age(s)':>8}"
    )

    if MIN_RSSI_DBM is not None:
        snapshot = [d for d in snapshot if d["rssi"] is not None and d["rssi"] >= MIN_RSSI_DBM]

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


def main():
    capture = BleCapture()
    radar = BleRadar()
    capture.start_capture()

    try:
        while True:
            while True:
                try:
                    packet = capture.queue.get_nowait()
                except Empty:
                    break
                radar.ingest(packet)

            render(radar.build_snapshot())

            ready, _, _ = select.select([sys.stdin], [], [], REFRESH_INTERVAL_S)
            if ready and sys.stdin.readline().strip() == "q":
                break
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop_capture()


if __name__ == "__main__":
    main()