"""
Terminal radar display for all nearby BLE devices.

Structure mirrors the WiFi terminal loop: one background reader thread
(inside BleCapture), everything else - draining the queue, refreshing the
display, reading keyboard input - handled synchronously here with
select.select(), no extra threads needed.
"""

import select
import sys
from queue import Empty

from ble_capture import BleCapture
from ble_radar import BleRadar

REFRESH_INTERVAL_S = 2.5
CLEAR_SCREEN = "\x1b[2J\x1b[H"   # ANSI clear


def render(snapshot):
    lines = [CLEAR_SCREEN]
    lines.append("BLE radar - press 'q' + Enter to stop")
    lines.append(
        f"{'Address':<20}{'Label':<24}{'RSSI':>7}{'Dist(m)':>9}"
        f"{'Trend':>10}{'PDU':>16}{'Seen':>7}{'Ch':>5}{'Age(s)':>8}"
    )

    if not snapshot:
        lines.append("(no device detected yet)")
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
            # Drain everything currently queued, non-blocking
            while True:
                try:
                    packet = capture.queue.get_nowait()
                except Empty:
                    break
                radar.ingest(packet)

            render(radar.build_snapshot())

            # Non-blocking keyboard check
            ready, _, _ = select.select([sys.stdin], [], [], REFRESH_INTERVAL_S)
            if ready and sys.stdin.readline().strip() == "q":
                break
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop_capture()


if __name__ == "__main__":
    main()