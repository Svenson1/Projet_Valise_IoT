"""
BLE advertising capture layer for the WCH BLE Analyzer Pro.

Pipeline:
    wch_capture -w <FIFO>  -> writes a live PCAP stream into a named pipe.
                              By default it auto-assigns its 3 internal MCUs
                              to channels 37/38/39, so all 3 advertising
                              channels are captured simultaneously with no
                              extra flags.
    tshark -r <FIFO> ...   -> reads that PCAP stream from the same FIFO and
                              dissects it into flat fields.

    NOTE: wch_capture's -w option does a plain fopen(path, "wb") - reading
    its source confirms there is no special case for "-" meaning stdout.
    `-w -` would silently create a real file literally named "-" instead of
    streaming anything. A named pipe (FIFO) works around this without
    touching wch_capture at all: fopen() on a FIFO path transparently
    becomes an OS-level pipe, so wch_capture just writes "to a file" as
    usual while tshark reads the same path as a live stream.

We deliberately do NOT parse `wch_capture -v` text output: that mode
truncates the advertising payload at 24 bytes, which makes it impossible to
reliably read manufacturer data, service UUIDs or full device names. tshark
gives us the full, un-truncated payload via its BLE dissector, the same way
the WiFi stack already relies on tshark for structured field extraction
instead of raw text scraping.

Field names below were confirmed against Wireshark's own display filter
reference (docs.wireshark.org/docs/dfref) after inspecting a real capture:
    Encapsulation: "Bluetooth Low Energy Link Layer RF" -> protocols btle_rf + btle
    - btle_rf.signal_dbm   : RSSI in dBm
    - btle_rf.channel      : raw RF channel index (0-39, NOT the logical
                              advertising channel number - see CHANNEL_MAP below)
    - btle.advertising_address        : advertiser MAC
    - btle.advertising_header.pdu_type: numeric PDU type (0-7, legacy advertising)
    - btcommon.eir_ad.entry.device_name : local name AD entry, if present
    - btcommon.eir_ad.entry.company_id  : manufacturer ID AD entry, if present
    - btcommon.eir_ad.entry.data        : raw bytes of that manufacturer entry
    - btcommon.eir_ad.entry.uuid_16     : 16-bit service UUID AD entry, if present
"""

import os
import tempfile
import subprocess
from threading import Thread
from queue import Queue
from types import SimpleNamespace


# The advertising channels are fixed radio frequencies (2402/2426/2480 MHz).
# Wireshark shows them as "Advertising channel 37/38/39" in the -V output,
# but that translation isn't exposed as its own filterable field - it's
# generated purely for display. We reproduce the mapping ourselves from the
# raw btle_rf.channel value (RF channel index 0-39).
RF_CHANNEL_TO_ADV_CHANNEL = {0: 37, 12: 38, 39: 39}

TSHARK_FIELDS = [
    "frame.time_epoch",
    "btle.advertising_address",
    "btle_rf.signal_dbm",
    "btle_rf.channel",
    "btle.advertising_header.pdu_type",
    "btcommon.eir_ad.entry.device_name",
    "btcommon.eir_ad.entry.company_id",
    "btcommon.eir_ad.entry.data",
    "btcommon.eir_ad.entry.uuid_16",
]

# Legacy advertising PDU types (btle.advertising_header.pdu_type), per the
# BLE Core spec - same set your original script had, but this time the
# tshark field genuinely is this 0-7 numeric code, not a pre-translated string.
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
    Runs wch_capture piped into tshark and exposes decoded BLE advertising
    packets through a thread-safe queue.

    Mirrors the WiFi capture architecture: one background reader thread,
    everything else (radar polling, keyboard input) is handled synchronously
    by the caller via select.select().
    """

    def __init__(self):
        self.queue = Queue()
        self._wch_proc = None
        self._tshark_proc = None
        self._reader_thread = None
        self._fifo_path = None

    def start_capture(self):
        self._fifo_path = tempfile.mktemp(prefix="ble_capture_", suffix=".fifo")
        os.mkfifo(self._fifo_path)

        # -l forces tshark to flush after every packet instead of buffering
        # for EOF, which is required to get live behavior out of a FIFO.
        # -E occurrence=f keeps only the first value of a repeating field
        # (a packet can have several AD entries; we only ask for fields
        # that each appear in at most one relevant entry per packet).
        field_args = []
        for f in TSHARK_FIELDS:
            field_args += ["-e", f]

        # Start tshark first: opening a FIFO for reading blocks until a
        # writer connects, so this just sits ready. wch_capture's own
        # fopen(path, "wb") on the same FIFO then completes the pairing
        # and both processes proceed - order doesn't really matter here,
        # but starting the reader first avoids wch_capture ever blocking
        # on an absent reader.
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

        # wch_capture writes the PCAP into the FIFO. stdin is DEVNULL so it
        # never blocks waiting on a controlling TTY (same rule as the WiFi
        # stack); stdout/stderr are only progress messages (fprintf to
        # stderr in the source), not needed here.
        self._wch_proc = subprocess.Popen(
            ["wch_capture", "-w", self._fifo_path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        self._reader_thread = Thread(target=self._read_output, daemon=True)
        self._reader_thread.start()

    def _read_output(self):
        for line in self._tshark_proc.stdout:
            packet = self._parse_line(line)
            if packet is not None:
                self.queue.put(packet)

    def _parse_line(self, line):
        fields = line.rstrip("\n").split("\t")
        if len(fields) != len(TSHARK_FIELDS):
            return None

        (time_epoch, adv_addr, rssi, rf_channel, pdu_type,
         device_name, company_id, manuf_data, uuid16) = fields

        if not adv_addr:
            # No advertising address on this PDU (e.g. some control PDUs) - not useful for the radar
            return None

        pdu_type_int = _parse_int(pdu_type)

        packet = {
            "time": float(time_epoch) if time_epoch else None,
            "advAddress": adv_addr.lower(),
            "RSSI": _parse_int(rssi),
            "channel": RF_CHANNEL_TO_ADV_CHANNEL.get(_parse_int(rf_channel)),
            "pduType": pdu_type_int,
            "pduTypeName": PDU_TYPE_NAMES.get(pdu_type_int, f"0x{pdu_type_int:x}" if pdu_type_int is not None else None),
            "deviceName": device_name or None,
            "companyId": _parse_int(company_id),
            "manufacturerData": manuf_data or None,   # hex string
            "uuid16": uuid16 or None,
        }
        return dict_to_object(packet)

    def stop_capture(self):
        for proc in (self._tshark_proc, self._wch_proc):
            if proc is not None and proc.poll() is None:
                proc.terminate()
        for proc in (self._tshark_proc, self._wch_proc):
            if proc is not None:
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=2)
        if self._fifo_path and os.path.exists(self._fifo_path):
            os.remove(self._fifo_path)