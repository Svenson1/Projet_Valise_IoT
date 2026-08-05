#!/usr/bin/env python3
import subprocess  # allow to run system commands (for aircrack)
import re          # for regex
import csv
import os           # to interact with the os
import time         # enable delays
import shutil       # shell utilities
import signal        # to send SIGINT to background processes (clean shutdown)
from datetime import datetime

active_wireless_networks = []

# Channels 1, 6 and 11 are the only non-overlapping channels in the 2.4GHz band
# (Europe: 13 channels, 5MHz spacing, ~20-22MHz signal width). A network sitting
# on one of these is "cleaner" RF-wise, which we use as a small bonus in scoring.
NON_OVERLAPPING_CHANNELS = {1, 6, 11}

# Output folder for the final report (phase 2), kept separate from the .pcap
# files so the working directory doesn't get cluttered.
REPORT_OUTPUT_DIR = "reports"


def check_for_bssid(bssid, lst):
    if len(lst) == 0:
        return True
    for item in lst:
        if bssid == item["BSSID"]:
            return False  # Le BSSID existe déjà, on ne l'ajoute pas en double
    return True

def check_for_essid(essid, lst):
    check_status = True
    if len(lst) == 0:
        return check_status
    for item in lst:
        if essid == item["ESSID"]:
            check_status = False
    return check_status

"""
check_for_bssid / check_for_essid:
Small helper functions to avoid adding duplicate networks to a list, based on
either the BSSID (MAC address of the AP, unique) or the ESSID (network name,
NOT guaranteed unique -- two different APs can share the same SSID).
Kept here for compatibility even though the main loop below uses its own
inline duplicate-check logic against BSSID.
"""


if not 'SUDO_UID' in os.environ.keys():
    print("Root access is required. Please execute this with sudo.")
    exit()

"""
Root check:
airmon-ng / airodump-ng / aireplay-ng all need raw access to the wireless
interface (changing mode, injecting/sniffing packets), which requires root
privileges on Linux. We bail out immediately if not running under sudo,
rather than letting a later subprocess call fail silently.
"""


for file_name in os.listdir():
    if ".csv" in file_name:
        print("Existing .csv files detected in your directory. Moving them to a backup folder now.")
        directory = os.getcwd()
        try:
            os.mkdir(directory + "/backup/")
        except:
            print("The backup directory is already present.")
        timestamp = datetime.now()
        shutil.move(file_name, directory + "/backup/" + str(timestamp) + "-" + file_name)

"""
Cleanup routine:
Any leftover .csv file from a previous run would otherwise get picked up by
the parsing loop below (which scans the whole working directory for ".csv"
files), polluting the current scan with stale data. We move old files into a
timestamped backup/ folder instead of deleting them, so nothing is lost.
"""


wlan_pattern = re.compile("wlan[0-9]+")
check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())

if len(check_wifi_result) == 0:
    print("No WiFi adapter found. Please attach one and retry.")
    exit()

"""
Adapter discovery:
`iwconfig` lists all network interfaces with wireless extensions. We grep the
output for interface names matching "wlan<number>" (standard Linux naming for
WiFi NICs) and bail out if none is found -- e.g. forgot to plug the Alfa
adapter, or USB passthrough into the VM isn't active.
"""


print("Here are the available WiFi interfaces:")
for index, item in enumerate(check_wifi_result):
    print(f"{index} - {item}")

while True:
    wifi_interface_choice = input("Which interface would you like to use? ")
    try:
        if check_wifi_result[int(wifi_interface_choice)]:
            break
    except:
        print("Enter a valid number from the list provided.")

hacknic = check_wifi_result[int(wifi_interface_choice)]

"""
Interface selection:
Lets the operator pick which detected interface to use, in case multiple
adapters are plugged in (e.g. built-in WiFi + the Alfa external one). Input
is validated in a loop until a valid index is provided.
"""


print("WiFi adapter is ready!\nLet's terminate any interfering processes:")
kill_confilict_processes = subprocess.run(["sudo", "airmon-ng", "check", "kill"])

print("Switching the WiFi adapter to monitor mode:")
put_in_monitored_mode = subprocess.run(
    ["sudo", "airmon-ng", "start", hacknic],
    capture_output=True, text=True
)
airmon_output = put_in_monitored_mode.stdout + put_in_monitored_mode.stderr
print(airmon_output)

"""
Conflict killing + monitor mode:
`airmon-ng check kill` stops NetworkManager/wpa_supplicant and any other
process that might fight over the interface (e.g. forcing it back to managed
mode mid-scan). `airmon-ng start <iface>` then switches the adapter into
monitor mode, which is required for passive sniffing: in monitor mode the
NIC reports ALL 802.11 frames on air, regardless of destination MAC,
including management frames (beacons, probe requests) -- not just frames
addressed to this host like in normal "managed" mode.
"""

# --- Detecting the real monitor interface name -----------------------------
# Depending on the driver, airmon-ng may rename the interface (e.g. wlan0 ->
# wlan0mon) or may keep the same name and just flip its mode internally. We
# can't assume `hacknic` is still correct -- if we keep using the old name
# while the kernel renamed it, airodump-ng will fail silently (errors are
# redirected to DEVNULL further down).
monitor_iface = hacknic
match = re.search(r"monitor mode (?:vif )?enabled.*?\[?(\w+mon)\]?", airmon_output, re.IGNORECASE)
if match:
    monitor_iface = match.group(1)
else:
    # Fallback: try the conventional "<iface>mon" name and check it actually
    # exists before trusting it.
    candidate = f"{hacknic}mon"
    check = subprocess.run(["iwconfig", candidate], capture_output=True, text=True)
    if check.returncode == 0:
        monitor_iface = candidate

print(f"Interface monitor utilisée : {monitor_iface}")
# -----------------------------------------------------------------------------

discover_access_points = subprocess.Popen(
    ["sudo", "airodump-ng", "-w", "file", "--write-interval", "1",
     "--output-format", "csv", monitor_iface],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)

"""
Discovery phase:
Launches airodump-ng in the background (Popen, non-blocking) without any
--bssid or -c filter, so it channel-hops across the whole band and reports
EVERY access point and client it sees. --write-interval 1 forces it to
flush the CSV file to disk every second, so our polling loop below can read
fresh data while the scan is still running.

Note: because there's no channel filter here, AP beacons (frequent, easy to
catch even while hopping) are reliably captured, but client-side traffic
(sporadic, especially from idle devices) is much more likely to be missed --
this is the main reason the "STATION" section of the CSV can stay empty
during this broad discovery phase. Targeting a single channel/BSSID later
(capture phase) gives airodump much more dwell time to catch client frames.
"""

try:
    while True:
        subprocess.call("clear", shell=True)
        for file_name in os.listdir():
            fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed',
                          'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV',
                          'LAN_IP', 'ID_length', 'ESSID', 'Key']
            if ".csv" in file_name:
                with open(file_name) as csv_h:
                    csv_h.seek(0)
                    csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                    for row in csv_reader:
                        if row["BSSID"] == "BSSID":
                            pass  # header row of the AP section, skip
                        elif row["BSSID"] == "Station MAC":
                            break  # we hit the header of the STATION section -> stop here,
                                   # this loop only cares about the AP section
                        else:
                            # Strip whitespace: airodump's CSV puts a space after each
                            # comma ("BSSID, First time seen, ..."), so raw values look
                            # like " WPA2" instead of "WPA2" -- this breaks any later
                            # string comparison or int() conversion if left unstripped.
                            row = {k: (v.strip() if isinstance(v, str) else v) for k, v in row.items()}

                            # Update-in-place if we've already seen this BSSID (values
                            # like Power/beacons change over time), otherwise append.
                            deja_present = False
                            for item in active_wireless_networks:
                                if item["BSSID"] == row["BSSID"]:
                                    item.update(row)
                                    deja_present = True
                                    break
                            if not deja_present:
                                active_wireless_networks.append(row)

        print("Currently scanning networks. Hit Ctrl+C to pick a target for the attack.\n")
        print("No |\tBSSID              |\tChannel|\tESSID                         |\tPower|")
        print("___|\t___________________|\t_______|\t______________________________|\t_____|")
        for index, item in enumerate(active_wireless_networks):
            print(f"{index}\t{item['BSSID']}\t{item['channel']}\t\t{item['ESSID']}\t\t\t{item['Power']}")
        time.sleep(1)

except KeyboardInterrupt:
    print("\nTime to choose your target.")

"""
Live scan display loop:
Re-reads the CSV from scratch every second (cheap enough at this scale) and
maintains a deduplicated, continuously-updated table of detected networks.
Ctrl+C breaks out of the infinite loop to move on to target selection.
"""

discover_access_points.send_signal(signal.SIGINT)
try:
    discover_access_points.wait(timeout=5)
except subprocess.TimeoutExpired:
    discover_access_points.terminate()
print("Scan de découverte arrêté.")

"""
Stopping the background scan:
The Popen process from the discovery phase is still running in the
background even after Ctrl+C breaks OUR display loop -- it's a separate OS
process. We send it SIGINT (same as a manual Ctrl+C) so airodump-ng closes
its CSV file cleanly, then wait for it to exit. Without this step, the
process keeps writing to disk and holding the monitor interface, which can
conflict with the targeted capture phase that follows.
"""

# =============================================================================
# AUTOMATIC BEST-AP SELECTION
# =============================================================================

def count_clients_per_bssid(csv_file_name):
    """
    Parse the 'STATION' section of the airodump CSV (the second table in the
    file, listing client devices) and count how many distinct clients are
    associated with each BSSID.

    Input:
    - csv_file_name: path to the airodump-generated CSV file.

    Output:
    - dict mapping BSSID (str) -> number of associated clients (int).
      Clients with BSSID "(not associated)" (probing but not connected to
      any visible AP) are ignored, since they can't be attributed to a
      specific network.
    """
    counts = {}
    client_fieldnames = ['Station_MAC', 'First_time_seen', 'Last_time_seen',
                          'Power', 'packets', 'BSSID', 'Probed_ESSIDs']
    with open(csv_file_name) as f:
        lines = f.read().splitlines()

    # Find where the STATION section starts; if it's not there at all (no
    # clients seen for the whole scan), return an empty dict gracefully.
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("Station MAC"))
    except StopIteration:
        return counts

    reader = csv.DictReader(lines[start + 1:], fieldnames=client_fieldnames)
    for row in reader:
        bssid = (row.get("BSSID") or "").strip()
        if bssid and bssid != "(not associated)":
            counts[bssid] = counts.get(bssid, 0) + 1
    return counts


def score_network(item, client_counts):
    """
    Compute a 0..1 desirability score for one access point, combining three
    weighted factors:
      - 50% signal power (closer to 0 dBm = stronger = better)
      - 30% bonus if the channel is one of the non-overlapping ones (1/6/11)
      - 20% number of currently associated clients (more clients = more
        live traffic to capture/analyze)

    Input:
    - item: dict for one AP, as stored in active_wireless_networks
      (expects at least "Power", "channel", "BSSID" keys).
    - client_counts: dict from count_clients_per_bssid().

    Output:
    - (score, n_clients) tuple: score is a float (higher = better),
      n_clients is just passed through for display purposes.
    """
    try:
        power = int(item["Power"])
    except (ValueError, TypeError):
        power = -90  # worst-case default if the value is missing/invalid

    try:
        channel = int(item["channel"])
    except (ValueError, TypeError):
        channel = -1

    n_clients = client_counts.get(item["BSSID"], 0)

    power_score = max(0.0, min(1.0, (power + 90) / 60))   # maps -90..-30 dBm to 0..1
    channel_bonus = 1.0 if channel in NON_OVERLAPPING_CHANNELS else 0.0
    client_score = min(n_clients, 10) / 10.0               # capped at 10 clients

    return (0.5 * power_score) + (0.3 * channel_bonus) + (0.2 * client_score), n_clients


def select_best_aps(networks, csv_file_name, top_n=3):
    """
    Rank all detected networks by score and return the top_n.

    Input:
    - networks: list of AP dicts (active_wireless_networks).
    - csv_file_name: path to the scan CSV, used to derive client counts.
    - top_n: how many networks to keep.

    Output:
    - list of (score, n_clients, network_dict) tuples, sorted best-first,
      truncated to top_n entries.
    """
    client_counts = count_clients_per_bssid(csv_file_name)

    # Discard entries with no usable BSSID/channel (e.g. malformed rows).
    valid = [n for n in networks if n.get("BSSID") and n.get("channel")]

    scored = []
    for net in valid:
        score, n_clients = score_network(net, client_counts)
        scored.append((score, n_clients, net))

    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[:top_n]


# Locate the CSV file written by airodump during the discovery phase, so we
# can re-read its STATION section for client counts.
csv_files = [f for f in os.listdir() if f.endswith(".csv") and "file" in f]
latest_csv = csv_files[0] if csv_files else None

if latest_csv is None:
    print("Impossible de retrouver le fichier CSV de scan, abandon.")
    exit()

TOP_N = 3
best_aps = select_best_aps(active_wireless_networks, latest_csv, top_n=TOP_N)

print(f"\n=== Top {TOP_N} réseaux sélectionnés automatiquement ===")
print("No |\tBSSID              |\tCH |\tESSID                    |\tPWR|\tCLIENTS|\tSCORE")
for index, (score, n_clients, net) in enumerate(best_aps):
    print(f"{index}\t{net['BSSID']}\t{net['channel']}\t{net['ESSID'][:24]:<24}\t"
          f"{net['Power']}\t{n_clients}\t{score:.3f}")

# You can either trust the automatic ranking fully, or ask for a manual
# confirmation before burning capture time on the wrong targets.
confirm = input(f"\nLancer la capture sur ces {len(best_aps)} réseaux ? [O/n] ").strip().lower()
if confirm == "n":
    print("Capture annulée.")
    exit()


# =============================================================================
# TARGETED CAPTURE OF SELECTED ACCESS POINTS
# =============================================================================

CAPTURE_TIME = 60  # seconds per target, adjust to taste

# Every .pcap file successfully produced during this loop is collected here,
# so phase 2 (the report) knows exactly which files to analyze afterwards --
# no need to re-scan the whole working directory and risk picking up old
# captures from a previous run.
captured_pcaps = []

for score, n_clients, net in best_aps:
    bssid = net["BSSID"]
    channel = net["channel"]
    essid = net["ESSID"] or "hidden"
    safe_essid = re.sub(r"[^\w\-]", "_", essid)[:30]
    prefix = f"{safe_essid}_{bssid.replace(':', '')}"

    print(f"\n[capture] {essid} ({bssid}) canal {channel} pendant {CAPTURE_TIME}s...")
    capture_proc = subprocess.Popen(
        ["sudo", "airodump-ng", "--bssid", bssid, "-c", channel,
         "--output-format", "pcap", "-w", prefix, monitor_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(CAPTURE_TIME)
    capture_proc.send_signal(signal.SIGINT)
    try:
        capture_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        capture_proc.terminate()

    cap_file = f"{prefix}-01.cap"
    if os.path.exists(cap_file):
        final_name = f"{prefix}.pcap"
        os.rename(cap_file, final_name)
        captured_pcaps.append(final_name)
        print(f"-> Capture sauvegardée : {final_name}")
    else:
        print(f"-> Aucun fichier de capture généré pour {essid}.")

"""
Targeted capture:
Unlike the discovery phase, each call here is locked to a single --bssid and
channel, so airodump-ng spends 100% of its time listening on that one
channel instead of hopping -- this is precisely what gives client-side
traffic (and therefore the STATION section, if you re-parsed these
per-target CSVs) a much better chance of being captured.
We use --output-format pcap to get a `.cap` file directly compatible with
Wireshark/tshark, then rename it to `.pcap` purely for naming clarity (no
functional difference -- aircrack-ng's .cap IS the pcap format).
"""

# =============================================================================
# PHASE 2 (AUTOMATIC): ANALYZE THE CAPTURES AND BUILD THE REPORT
# =============================================================================

if captured_pcaps:
    print(f"\n=== Phase 2 : analyse automatique de {len(captured_pcaps)} capture(s) ===")
    import wifi_report  # local module, must sit next to this script
    report_path = wifi_report.run_full_report(captured_pcaps, output_dir=REPORT_OUTPUT_DIR)
    if report_path:
        print(f"\nPipeline termine. Rapport disponible : {report_path}")
else:
    print("\nAucune capture exploitable, phase 2 (analyse) ignoree.")

"""
Automatic phase 2:
Instead of asking the operator to run "python3 wifi_report.py *.pcap" by
hand once captures are done, we import wifi_report.py as a regular Python
module (it lives in the same folder as this script) and call its
run_full_report() function directly, passing it the exact list of .pcap
files produced above. This skips subprocess/argparse entirely -- it's a
plain in-process function call, which is simpler and faster than spawning
a second Python process. The single combined report (networks then MAC
addresses) ends up in the REPORT_OUTPUT_DIR folder.
"""

print("\nTerminé. Pense à repasser l'interface en mode managed avec :")
print(f"  sudo airmon-ng stop {monitor_iface}")