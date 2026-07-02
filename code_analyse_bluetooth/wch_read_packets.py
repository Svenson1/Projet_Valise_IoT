import subprocess
import json
from threading import Thread
from queue import Queue

from types import SimpleNamespace

def dict_to_object(d):
    if isinstance(d, dict):
        return SimpleNamespace(**{k: dict_to_object(v) for k, v in d.items()})
    if isinstance(d, list):
        return [dict_to_object(i) for i in d]
    return d

class BleThreadAnalyzer:

    def __init__(self, channels=[37,38,39]):
        self.channels = channels
        self.queue = Queue()

    def start_capture(self):
        self.analyzer_subprocess = subprocess.Popen(
            [
                "wch_capture",
                "-v",
            ],
            stdout=subprocess.PIPE,
            text=True,
        )

        self.reader_thread = Thread(target=self._read_tshark_output, daemon=True)
        self.reader_thread.start()

    def _read_tshark_output(self):
        """Lit les paquets produits par tshark et les ajoute dans la queue."""
        for line in self.analyzer_subprocess.stdout:
            try:
                packet = self._parse_line(line)
                self.queue.put(packet)
            except json.JSONDecodeError:
                # Ignore les lignes invalides
                continue

    def _parse_line(self, line):
        line_tab = line.strip().split()

        time = line_tab[0:3]
        channel = line_tab[3]
        advType = line_tab[4]
        rssi = line_tab[6]
        device = line_tab[10][:17]

        # print(line_tab)
        # print(time, channel, advType, rssi, device)

        packet = {
            "RSSI": float(rssi),
            "blePacket": {
                "advType": advType,
                "advAddress": [int(x, 16) for x in device.split(":")]
            }   
        }

        return dict_to_object(packet)