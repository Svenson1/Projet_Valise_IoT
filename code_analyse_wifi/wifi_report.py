#!/usr/bin/env python3
"""
wifi_report.py

Analyse un ou plusieurs fichiers .pcap issus d'une capture airodump-ng
(ou autre) et produit UN SEUL rapport structure en deux sections :
  - SECTION 1 : RESEAUX (BSSID, SSID, chiffrement, clients associes)
  - SECTION 2 : ADRESSES MAC (vendor, SSID probes, reseaux frequentes)

Peut etre utilise de deux facons :
  - en ligne de commande, sur des pcap deja existants
  - importe comme module par wifi_audit_v3.py, pour enchainer
    automatiquement l'analyse juste apres la capture (phase 2 du pipeline)

Usage (ligne de commande):
    python3 wifi_report.py /chemin/vers/dossier_pcap/
    python3 wifi_report.py capture-01.pcap capture-02.pcap
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run_tshark_fields(pcap_path, display_filter, fields):
    """
    Lance tshark sur un pcap avec un filtre d'affichage et une liste de
    champs, retourne une liste de listes (une liste par paquet matche).
    """
    cmd = ["tshark", "-r", str(pcap_path), "-Y", display_filter, "-T", "fields", "-E", "separator=,"]
    for field in fields:
        cmd += ["-e", field]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [!] tshark a échoué sur {pcap_path.name}: {result.stderr.strip()}", file=sys.stderr)
        return []

    rows = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        rows.append(line.split(","))
    return rows


def decode_ssid_hex(raw_hex):
    """
    Le champ wlan.ssid sort en hexadecimal sous tshark -T fields (c'est
    un champ FT_BYTES), il faut donc le redecoder en texte explicitement.
    Un SSID vide ou cache renvoie une chaine vide.
    """
    if not raw_hex:
        return ""
    try:
        return bytes.fromhex(raw_hex).decode("utf-8", errors="replace")
    except ValueError:
        return raw_hex  # au cas ou ce ne soit pas du hex propre


def classify_encryption(rsn_version, privacy_bit):
    """
    Heuristique simple de classification du chiffrement a partir des
    tags releves sur les beacons/probe responses :
      - tag RSN present -> WPA2/WPA3 (RSN est le tag commun aux deux)
      - bit privacy active sans tag RSN -> WEP ou WPA1 (non distingue ici)
      - bit privacy desactive -> reseau ouvert
    Ce n'est pas un parsing complet des capacites 802.11, juste un indicateur
    suffisant pour prioriser les reseaux interessants.
    """
    if rsn_version:
        return "WPA2/WPA3"
    if privacy_bit == "1" or privacy_bit == "True":
        return "WEP/WPA"
    return "Open"


def new_client_entry():
    """Structure vide pour un client, reutilisee a chaque premiere rencontre."""
    return {
        "vendor": None,
        "probed_ssids": set(),
        "networks": set(),
    }


def parse_networks(pcap_path, networks):
    """
    Etape 1 : extraire l'identite des reseaux a partir des beacons et
    probe responses (subtype 0x08 et 0x05). Met a jour le dict networks
    passe en parametre (cle = BSSID).
    """
    fields = ["wlan.bssid", "wlan.ssid", "wlan.rsn.version", "wlan.fixed.capabilities.privacy"]
    rows = run_tshark_fields(pcap_path, "wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05", fields)

    for row in rows:
        if len(row) < 4 or not row[0]:
            continue
        bssid, ssid_hex, rsn_version, privacy = row[0], row[1], row[2], row[3]
        ssid = decode_ssid_hex(ssid_hex) or "(SSID cache)"

        net = networks.setdefault(bssid, {
            "ssid": ssid,
            "encryption": classify_encryption(rsn_version, privacy),
            "clients": set(),
        })
        # Si on avait initialement un SSID cache et qu'on en trouve un vrai, on le mets a jour
        if ssid != "(SSID cache)":
            net["ssid"] = ssid


def parse_probe_requests(pcap_path, clients):
    """
    Etape 2 : extraire l'historique des SSID recherches par chaque client
    via les probe requests (subtype 0x04). C'est la source de l'historique
    de connexion d'un appareil (ex: "Cafe_Free_Wifi", "Office_Network").
    """
    fields = ["wlan.sa", "wlan.sa_resolved", "wlan.ssid"]
    rows = run_tshark_fields(pcap_path, "wlan.fc.type_subtype==0x04", fields)

    for row in rows:
        if len(row) < 3 or not row[0]:
            continue
        mac, vendor, ssid_hex = row[0], row[1], row[2]
        ssid = decode_ssid_hex(ssid_hex)
        if not ssid:
            continue  # probe request "broadcast" sans SSID precis, rien a tirer

        client = clients.setdefault(mac, new_client_entry())
        client["probed_ssids"].add(ssid)
        if vendor and client["vendor"] is None:
            client["vendor"] = vendor


def parse_associations(pcap_path, networks, clients):
    """
    Etape 3 : extraire les liens client <-> reseau via les trames de
    donnees (type 2). Le transmetteur ou destinataire qui n'est pas le
    BSSID lui-meme est considere comme client de ce reseau.
    """
    fields = ["wlan.bssid", "wlan.sa", "wlan.da", "wlan.sa_resolved", "wlan.da_resolved"]
    rows = run_tshark_fields(pcap_path, "wlan.fc.type==2", fields)

    for row in rows:
        if len(row) < 5:
            continue
        bssid, src, dst, src_vendor, dst_vendor = row[0], row[1], row[2], row[3], row[4]
        if not bssid:
            continue

        for mac, vendor in ((src, src_vendor), (dst, dst_vendor)):
            if not mac or mac == bssid:
                continue
            client = clients.setdefault(mac, new_client_entry())
            client["networks"].add(bssid)
            if vendor and client["vendor"] is None:
                client["vendor"] = vendor
            if bssid in networks:
                networks[bssid]["clients"].add(mac)


def analyze_pcap(pcap_path, networks, clients):
    """Lance les trois etapes d'extraction sur un seul fichier pcap."""
    print(f"  -> analyse de {pcap_path.name}")
    parse_networks(pcap_path, networks)
    parse_probe_requests(pcap_path, clients)
    parse_associations(pcap_path, networks, clients)


def build_full_report(networks, clients):
    """
    Genere le texte du rapport UNIQUE, en deux sections : d'abord les
    reseaux, ensuite les adresses MAC.
    """
    lines = []

    lines.append("=" * 70)
    lines.append("SECTION 1 - RESEAUX DETECTES")
    lines.append("=" * 70)
    lines.append("")
    for bssid, net in sorted(networks.items(), key=lambda kv: kv[1]["ssid"]):
        lines.append(f'Reseau : "{net["ssid"]}"')
        lines.append(f"BSSID : {bssid}")
        lines.append(f"Chiffrement : {net['encryption']}")
        lines.append(f"Clients detectes : {len(net['clients'])}")
        for mac in sorted(net["clients"]):
            client = clients.get(mac, {})
            vendor = client.get("vendor") or "Vendor inconnu"
            lines.append(f"  - MAC: {mac} ({vendor})")
        lines.append("")  # ligne vide entre deux reseaux

    lines.append("=" * 70)
    lines.append("SECTION 2 - ADRESSES MAC DETECTEES")
    lines.append("=" * 70)
    lines.append("")
    for mac, client in sorted(clients.items()):
        vendor = client["vendor"] or "Vendor inconnu"
        lines.append(f"Adresse MAC : {mac} ({vendor})")
        if client["networks"]:
            lines.append(f"  Reseaux associes : {', '.join(sorted(client['networks']))}")
        if client["probed_ssids"]:
            probed = ", ".join(f'"{s}"' for s in sorted(client["probed_ssids"]))
            lines.append(f"  SSIDs probes (historique) : {probed}")
        lines.append("")

    return "\n".join(lines)


def collect_pcap_files(paths):
    """Accepte des fichiers .pcap/.cap individuels ou un dossier a parcourir."""
    pcap_files = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            pcap_files.extend(sorted(path.glob("*.pcap")))
            pcap_files.extend(sorted(path.glob("*.cap")))
        elif path.is_file():
            pcap_files.append(path)
        else:
            print(f"  [!] introuvable, ignore : {p}", file=sys.stderr)
    return pcap_files


def run_full_report(inputs, output_dir="."):
    """
    Point d'entree reutilisable : prend une liste de chemins (fichiers ou
    dossiers), lance l'analyse complete, ecrit le rapport unique sur disque
    et retourne son chemin (ou None si rien a analyser).

    Utilisee a la fois par main() (mode CLI classique) et par
    wifi_audit_v3.py (mode pipeline automatique : ce module est importe
    directement, sans repasser par subprocess/argparse).
    """
    pcap_files = collect_pcap_files(inputs)
    if not pcap_files:
        print("Aucun fichier pcap trouve.", file=sys.stderr)
        return None

    networks = {}
    clients = {}

    print(f"Analyse de {len(pcap_files)} fichier(s) pcap...")
    for pcap_path in pcap_files:
        analyze_pcap(pcap_path, networks, clients)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report_text = build_full_report(networks, clients)
    report_file = output_path / "rapport_complet.txt"
    report_file.write_text(report_text, encoding="utf-8")

    print(f"\n{len(networks)} reseau(x) et {len(clients)} adresse(s) MAC detecte(s).")
    print(f"Rapport ecrit dans : {report_file}")
    return report_file


def main():
    parser = argparse.ArgumentParser(description="Genere un rapport unique (reseaux + adresses MAC) depuis des pcap Wi-Fi.")
    parser.add_argument("inputs", nargs="+", help="Fichiers .pcap/.cap ou dossier les contenant")
    parser.add_argument("-o", "--output-dir", default=".", help="Dossier de sortie du rapport (defaut: dossier courant)")
    args = parser.parse_args()

    run_full_report(args.inputs, args.output_dir)


if __name__ == "__main__":
    main()