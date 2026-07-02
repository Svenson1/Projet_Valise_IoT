import argparse
import time
from serial.tools import list_ports
from serial.serialutil import SerialException
from SnifferAPI.Sniffer import Sniffer

ADV_TYPES = {
    0: "ADV_IND",
    1: "ADV_DIRECT_IND",
    2: "ADV_NONCONN_IND",
    3: "SCAN_REQ",
    4: "SCAN_RSP",
    5: "CONNECT_REQ",
    6: "ADV_SCAN_IND",
    7: "EXT_ADV",
}


def list_com_ports():
    return list(list_ports.comports())


def port_name_to_portnum(port_name):
    if not port_name.upper().startswith("COM"):
        raise ValueError(f"Port name must be a COM port, got {port_name!r}")
    value = int(port_name[3:])
    return value - 1


def hex_bytes(data):
    if data is None:
        return None
    return " ".join(f"{b:02x}" for b in data)


def format_address(addr):
    if not addr:
        return None
    return ":".join(f"{b:02x}" for b in addr[:6])


addr_list = {
    "adv": [],
}

def print_packet(packet):
    print("----- packet -----")
    print(f"id={packet.id} packetCounter={packet.packetCounter} valid={packet.valid} OK={packet.OK}")
    if hasattr(packet, "time"):
        print(f"time={packet.time:.6f}")
    print(f"protover={packet.protover} payloadLength={packet.payloadLength}")
    print(
        f"RSSI={getattr(packet, 'RSSI', None)} crcOK={getattr(packet, 'crcOK', None)} "
        f"direction={getattr(packet, 'direction', None)} encrypted={getattr(packet, 'encrypted', None)}"
    )

    ble = getattr(packet, "blePacket", None)
    if ble is not None:
        ptype = "TBD"
        adv_type = ADV_TYPES.get(getattr(ble, "advType", None), getattr(ble, "advType", None))
        print(f"BLE type={ptype} advType={adv_type}")
        print(f"accessAddress={hex_bytes(getattr(ble, 'accessAddress', None))}")
        print(f"advAddress={format_address(getattr(ble, 'advAddress', None))}")
        print(f"scanAddress={format_address(getattr(ble, 'scanAddress', None))}")
        print(f"name={getattr(ble, 'name', None)}")
        print(f"payload={hex_bytes(getattr(ble, 'payload', None))}")

    else:
        print("No BLE packet parsed")


def get_addr_rssi(packet):
    ble = getattr(packet, "blePacket", None)
    packet_rssi = packet.RSSI
    if ble is None:
        return

    name = ble.name
    accessAddr = hex_bytes(getattr(ble, 'accessAddress', None))
    scanAddress = format_address(getattr(ble, 'scanAddress', None)) # Addr of device scanning
    advAddress = format_address(getattr(ble, 'advAddress', None)) # Addr of devices connecting

    if advAddress is None:
        return

    for i, device_info in enumerate(addr_list["adv"]):
        if device_info["addr"] != advAddress and device_info["addr"] != scanAddress:
            continue

        device_info["seen"] += 1
        # if packet_rssi > device_info["rssi"]:
        device_info["rssi"] = packet_rssi
        return
    

    # if packet_rssi < -50:
    #     return

    addr_list["adv"].append({
        "addr": advAddress,
        "rssi": packet_rssi,
        "seen": 1,
        "name": name,
        "advType": ADV_TYPES.get(getattr(ble, "advType", None), getattr(ble, "advType", None))
    })

    if scanAddress is None:
        return

    addr_list["adv"].append({
        "addr": scanAddress,
        "rssi": packet_rssi,
        "seen": 1,
        "name": name,  
        "advType": ADV_TYPES.get(getattr(ble, "advType", None), getattr(ble, "advType", None))   
    })


def calcul_distance(rssi, n):
    if rssi is None:
        return None
    return 10.0 ** ((-60.0 - rssi) / (10.0 * n))

def print_addr_scanned():
    print("=====================================")
    print("Printing Scanned devices list with RSSI")
    print(f"{'Addresse':<20}  {'RSSI':>10}  {'Times seen':<10}  {'Nom':<10}")

    
    for device in addr_list["adv"]:
        dist_low = calcul_distance(device["rssi"], 2)
        dist_high = calcul_distance(device["rssi"], 3.5)
        print(f"{device["addr"]:<20} {device["rssi"]:>10} {device["seen"]:<10} {device["name"]:<10} {device["advType"]:<30} {dist_low:.2f} - {dist_high:.2f}")



def main():
    parser = argparse.ArgumentParser(description="SnifferAPI real-time BLE packet display")
    parser.add_argument("--list", action="store_true", help="List available COM ports")
    parser.add_argument("--port", help="COM port to use, for example COM9")
    parser.add_argument("--interval", type=float, default=0.2, help="Polling interval in seconds")
    parser.add_argument("--wait", type=float, default=1.0, help="Wait time after starting the sniffer thread")
    args = parser.parse_args()

    ports = list_com_ports()
    if args.list:
        if not ports:
            print("Aucun port série détecté.")
            return
        print("Ports série disponibles :")
        for port in ports:
            print(f"  {port.device}  {port.description}  {port.hwid}")
        return

    if not ports:
        raise RuntimeError("Aucun port série détecté sur cette machine.")

    selected_port = args.port or ports[0].device
    print(f"Utilisation du port série : {selected_port}")

    try:
        sniffer = Sniffer(portnum=selected_port)
    except Exception as exc:
        raise RuntimeError(f"Impossible de créer l'objet Sniffer: {exc}") from exc

    try:
        sniffer.start()
        time.sleep(args.wait)
        sniffer.scan(findScanRsp=True)

        print("Sniffer démarré. Appuyez sur Ctrl+C pour arrêter.")
        while True:
            packets = sniffer.getPackets()
            for packet in packets:
                # print_packet(packet)
                get_addr_rssi(packet)
            print_addr_scanned()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Arrêt du sniffer...")
    except SerialException as exc:
        print(f"Erreur de port série : {exc}")
    finally:
        try:
            sniffer.doExit(join=True)
        except Exception:
            pass


if __name__ == "__main__":
    main()
