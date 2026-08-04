"""
BLE radar: tracks every advertising device seen on the 3
advertising channels, resolves identification info when
available (name, vendor, service UUID), and applies the same dual-EMA
RSSI model as the WiFi sonar to tell approaching/receding devices apart.
"""

import time
from manuf import manuf

_oui_parser = manuf.MacParser(manuf_name="./manuf_db")

# --- Sonar / distance constants, consistent with the WiFi RSSI model ---
RSSI_REF = -38.0            # RSSI at 1 meter (path-loss reference, literature value)
PATH_LOSS_N = 3.2           # path-loss exponent
EMA_FAST_ALPHA = 0.5
EMA_SLOW_ALPHA = 0.1
TREND_HYSTERESIS_DB = 2.0   # minimum fast/slow EMA delta to call it a trend
DEVICE_TIMEOUT_S = 30.0     # forget a device if not seen for this long

# Small, non-exhaustive lookup for common BLE Company IDs (Bluetooth SIG
# assigned numbers).
COMPANY_ID_NAMES = {
    0x004C: "Apple",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x0006: "Microsoft",
    0x038F: "Xiaomi",
    0x0087: "Garmin",
    0x0157: "Anhui Huami (Amazfit)",
    0x0499: "Ruuvi",
    0x02E8: "Chipolo",
}

def vendor_name(company_id):
    if company_id is None:
        return None
    return COMPANY_ID_NAMES.get(company_id, f"0x{company_id:04x}")


def estimate_distance(rssi):
    if rssi is None:
        return None
    return 10.0 ** ((RSSI_REF - rssi) / (10.0 * PATH_LOSS_N))


class TrackedDevice:
    """State kept per advertising address: RSSI history, trend, identification."""

    def __init__(self, address):
        self.address = address
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.seen_count = 0
        self.last_channel = None
        self.last_pdu_type = None
        self.name = None
        self.vendor = None
        self.uuid16 = None
        self.ema_fast = None
        self.ema_slow = None

    def update(self, packet):
        self.last_seen = time.time()
        self.seen_count += 1
        self.last_channel = packet.channel
        self.last_pdu_type = packet.pduTypeName

        # Identification fields only show up on some advertising packets
        # (e.g. name is often only in SCAN_RSP) - keep the latest non-empty
        # value instead of overwriting with blanks on every packet.
        if packet.deviceName:
            self.name = packet.deviceName
        if packet.companyId is not None:
            self.vendor = vendor_name(packet.companyId)
        if packet.uuid16:
            self.uuid16 = packet.uuid16

        if packet.RSSI is None:
            return

        # Dual-EMA, same split as the WiFi sonar: fast EMA reacts quickly and
        # feeds the trend detector, slow EMA is the stable baseline used for
        # distance estimation.
        if self.ema_fast is None:
            self.ema_fast = self.ema_slow = float(packet.RSSI)
        else:
            self.ema_fast = EMA_FAST_ALPHA * packet.RSSI + (1 - EMA_FAST_ALPHA) * self.ema_fast
            self.ema_slow = EMA_SLOW_ALPHA * packet.RSSI + (1 - EMA_SLOW_ALPHA) * self.ema_slow

    @property
    def trend(self):
        """'approche' / 'eloigne' / 'stable'"""
        if self.ema_fast is None or self.ema_slow is None:
            return "stable"
        delta = self.ema_fast - self.ema_slow
        if delta > TREND_HYSTERESIS_DB:
            return "approche"
        if delta < -TREND_HYSTERESIS_DB:
            return "eloigne"
        return "stable"

    @property
    def distance_m(self):
        return estimate_distance(self.ema_slow)

    @property
    def label(self):
        """Best-effort display label: device name if advertised, else vendor from Company ID."""
        if self.name:
            return self.name
        if self.vendor:
            return f"({self.vendor})"
        oui_vendor = _oui_parser.get_manuf(self.address)
        if oui_vendor:
            return f"({oui_vendor})"
        return "-"


class BleRadar:
    """Keeps track of every BLE advertiser seen across the 3 advertising channels."""

    def __init__(self):
        self.devices = {}   # advAddress -> TrackedDevice

    def ingest(self, packet):
        device = self.devices.get(packet.advAddress)
        if device is None:
            device = TrackedDevice(packet.advAddress)
            self.devices[packet.advAddress] = device
        device.update(packet)

    def prune_stale(self):
        """Drop devices not seen recently"""
        now = time.time()
        stale = [addr for addr, d in self.devices.items() if now - d.last_seen > DEVICE_TIMEOUT_S]
        for addr in stale:
            del self.devices[addr]

    def build_snapshot(self):
        """
        Single source of truth for the display layer
        same pattern as the WiFi stack's build_snapshot().
        """
        self.prune_stale()
        devices = list(self.devices.values())
        #le tri fait sauter le radar dans tout les sens
        #devices = sorted(
        #    self.devices.values(),
        #    key=lambda d: d.ema_fast if d.ema_fast is not None else -999,
        #    reverse=True,
        #)
        return [
            {
                "address": d.address,
                "label": d.label,
                "rssi": round(d.ema_fast, 1) if d.ema_fast is not None else None,
                "distance_m": round(d.distance_m, 2) if d.distance_m is not None else None,
                "trend": d.trend,
                "pdu_type": d.last_pdu_type,
                "seen_count": d.seen_count,
                "last_channel": d.last_channel,
                "age_s": round(time.time() - d.last_seen, 1),
            }
            for d in devices
        ]