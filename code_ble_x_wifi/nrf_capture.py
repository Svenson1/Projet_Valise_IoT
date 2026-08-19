"""
BLE advertising capture layer for the nRF52840-DK boussole receiver.

Pipeline:
    nrfutil ble-sniffer sniff --output-pcap-file <FIFO> -> writes a live
        PCAP stream into a named pipe. Single radio hopping 37/38/39
        sequentially (not simultaneous like the WCH Analyzer Pro).
    tshark -r <FIFO>       -> reads that PCAP stream from the same FIFO.
"""

import os
import signal
import tempfile
import subprocess
import shutil
from threading import Thread
from queue import Queue
from types import SimpleNamespace


# Serial port the nRF52840-DK enumerates as on the Pi
DEFAULT_NRF_PORT = "/dev/ttyACM0"

TSHARK_FIELDS = [
    "frame.time_epoch",
    "btle.advertising_address",
    "btle.scanning_address",     # real sender for SCAN_REQ (ScanA)
    "btle.initiator_address",    # real sender for CONNECT_IND (InitA)
    "nordic_ble.rssi",
    "nordic_ble.channel",        # already 37/38/39, no remap needed
    "btle.advertising_header.pdu_type",
    "btcommon.eir_ad.entry.device_name",
    "btcommon.eir_ad.entry.company_id",
    "btcommon.eir_ad.entry.data",
    "btcommon.eir_ad.entry.uuid_16",
]

PDU_TYPE_NAMES = {
    0: "ADV_IND",
    1: "ADV_DIRECT_IND",
    2: "ADV_NONCONN_IND",
    3: "SCAN_REQ",
    4: "SCAN_RSP",
    5: "CONNECT_IND",
    6: "ADV_SCAN_IND",
    7: "ADV_EXT_IND",
}

PDU_SCAN_REQ = 3
PDU_CONNECT_IND = 5


def dict_to_object(d):
    """Recursively turn a dict into a SimpleNamespace so fields are accessed as attributes."""
    if isinstance(d, dict):
        return SimpleNamespace(**{k: dict_to_object(v) for k, v in d.items()})
    if isinstance(d, list):
        return [dict_to_object(i) for i in d]
    return d


def _parse_int(value):
    """int(x, 0) auto-detects base: handles both '76' (decimal) and '0x4c' (hex)."""
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


class BleCapture:
    """
    Runs `nrfutil ble-sniffer sniff` piped into tshark and exposes decoded
    BLE advertising packets through a thread-safe queue. Same public
    interface as the WCH-based BleCapture in ble_capture.py, so ble_radar.py
    and ble_realtime.py work unmodified against this class.
    """

    def __init__(self, port=DEFAULT_NRF_PORT):
        self.port = port
        self.queue = Queue()
        self._nrf_proc = None
        self._tshark_proc = None
        self._reader_thread = None
        self._fifo_path = None
        self._fifo_dir = None

    def start_capture(self):
        self._fifo_dir = tempfile.mkdtemp(prefix="ble_nrf_capture_")
        self._fifo_path = os.path.join(self._fifo_dir, "capture.fifo")
        os.mkfifo(self._fifo_path)

        field_args = []
        for f in TSHARK_FIELDS:
            field_args += ["-e", f]

        # Start tshark first: opening a FIFO for reading blocks until a
        # writer connects, so this just sits ready. nrfutil's own file
        # write on the same FIFO then completes the pairing and both
        # processes proceed - same  pattern as wch_capture.
        self._tshark_proc = subprocess.Popen(
            [
                "tshark",
                "-r", self._fifo_path,
                "-l",
                "-T", "fields",
                "-E", "separator=\t",
                "-E", "occurrence=f",
                *field_args,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        # nrfutil writes the PCAP stream into the FIFO
        self._nrf_proc = subprocess.Popen(
            [
                "nrfutil", "ble-sniffer", "sniff",
                "--port", self.port,
                "--output-pcap-file", self._fifo_path,
            ],
            stdin=subprocess.DEVNULL,
            stdout=None,
            stderr=None,
            start_new_session=True,
        )

        self._reader_thread = Thread(target=self._read_output, daemon=True)
        self._reader_thread.start()

    def _read_output(self):
        while self._tshark_proc is not None:
            for line in self._tshark_proc.stdout:
                packet = self._parse_line(line)
                if packet is not None:
                    self.queue.put(packet)

    def _parse_line(self, line):
        fields = line.rstrip("\n").split("\t")
        if len(fields) != len(TSHARK_FIELDS):
            return None

        (time_epoch, adv_addr, scan_addr, init_addr, rssi, rf_channel,
         pdu_type, device_name, company_id, manuf_data, uuid16) = fields

        if not adv_addr:
            return None

        pdu_type_int = _parse_int(pdu_type)

        if pdu_type_int == PDU_SCAN_REQ:
            sender_addr = scan_addr or None
        elif pdu_type_int == PDU_CONNECT_IND:
            sender_addr = init_addr or None
        else:
            sender_addr = adv_addr or None

        if not sender_addr:
            return None

        packet = {
            "time": float(time_epoch) if time_epoch else None,
            "advAddress": sender_addr.lower(),
            "RSSI": _parse_int(rssi),
            "channel": _parse_int(rf_channel),
            "pduType": pdu_type_int,
            "pduTypeName": PDU_TYPE_NAMES.get(pdu_type_int, f"0x{pdu_type_int:x}" if pdu_type_int is not None else None),
            "deviceName": device_name or None,
            "companyId": _parse_int(company_id),
            "manufacturerData": manuf_data or None,
            "uuid16": uuid16 or None,
        }
        return dict_to_object(packet)

    def stop_capture(self):
        if self._tshark_proc is not None and self._tshark_proc.poll() is None:
            self._tshark_proc.terminate()

        # nrf_proc was started in its own process group (start_new_session
        # =True), so killpg reaches both the wrapper and its
        # nrfutil-ble-sniffer child
        if self._nrf_proc is not None and self._nrf_proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._nrf_proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass

        for proc in (self._tshark_proc, self._nrf_proc):
            if proc is not None:
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

        # Fallback: if SIGTERM wasn't enough, force
        # kill whatever is left in that process group.
        if self._nrf_proc is not None and self._nrf_proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._nrf_proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=2)
        if self._fifo_path and os.path.exists(self._fifo_path):
            os.remove(self._fifo_path)
        if self._fifo_dir and os.path.exists(self._fifo_dir):
            shutil.rmtree(self._fifo_dir, ignore_errors=True)
