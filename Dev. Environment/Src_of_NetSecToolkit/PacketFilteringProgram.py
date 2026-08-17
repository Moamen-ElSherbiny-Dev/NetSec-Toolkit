# Packet Filtering Program
# Must Run as Administrator
#
# Called by GUI with args: <action> [value]
#
# Actions & args:
#   add_trusted   <ip>
#   show_trusted
#   block_ip      <ip>
#   block_port    <port>
#   unblock_ip    <ip>
#   unblock_port  <port>
#   check         <ip_or_port>
#   show_rules
#   show_ddos
#   start_sniff              (background DDoS engine - long-running)

import os
import sys
import time
import threading
from datetime import datetime
from collections import defaultdict

def _get_base_dir():
    # When frozen by PyInstaller, use the exe's directory for logs/data.
    # When running as plain .py, use the script's directory as before.
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))
script_dir      = _get_base_dir()
TRUSTED_FILE    = os.path.join(script_dir, "Config\\trusted_ips.txt")
LOG_FILE        = os.path.join(script_dir, "Logs\\PacketFilteringProgramLogs.txt")

DDOS_THRESHOLD  = 20
RESET_TIME      = 10

# In-memory state (matters only for the sniff action which is long-running)
trusted_ips     = []
rules           = []          # [{"type": "IP"|"Port", "value": str}]
ddos_blocked    = []
request_count   = defaultdict(int)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def write_log(msg: str):
    try:
        with open(LOG_FILE, "a") as f:
            ts = datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
            f.write(f"[{ts}] {msg}\n")
    except Exception as e:
        print(f"[Warning]: Could not write log - {e}")


# ---------------------------------------------------------------------------
# Trusted IPs
# ---------------------------------------------------------------------------
def load_trusted_ips():
    global trusted_ips
    try:
        with open(TRUSTED_FILE) as f:
            trusted_ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        trusted_ips = []


def save_trusted_ips():
    with open(TRUSTED_FILE, "w") as f:
        for ip in trusted_ips:
            f.write(ip + "\n")


def add_trusted(ip: str):
    load_trusted_ips()
    if ip in trusted_ips:
        print(f"[Info]: {ip} is already in the trusted list.")
        return
    trusted_ips.append(ip)
    save_trusted_ips()
    print(f"[Info]: Trusted IP added -> {ip}")
    write_log(f"Trusted IP added: {ip}")


def show_trusted():
    load_trusted_ips()
    if not trusted_ips:
        print("[Info]: No trusted IPs configured.")
    else:
        print("[Info]: Trusted IPs:")
        for ip in trusted_ips:
            print(f"  * {ip}")


# ---------------------------------------------------------------------------
# Firewall rule helpers
# ---------------------------------------------------------------------------
def fw_rule_label(kind: str, value: str) -> str:
    """Canonical Windows Firewall rule name used by this tool."""
    return f"NetSec Block {kind} {value}"


def fw_rule_exists_windows(label: str) -> bool:
    out = os.popen(f'netsh advfirewall firewall show rule name="{label}"').read()
    return "No rules match" not in out


# ---------------------------------------------------------------------------
# Block / Unblock IP & Port
# ---------------------------------------------------------------------------
def block_ip(ip: str):
    label = fw_rule_label("IP", ip)
    if fw_rule_exists_windows(label):
        print(f"[Info]: {ip} is already blocked.")
        return
    os.system(
        f'netsh advfirewall firewall add rule name="{label}" '
        f'dir=in action=block remoteip={ip}'
    )
    print(f"[Info]: IP {ip} -> BLOCKED")
    write_log(f"IP blocked: {ip}")


def block_port(port: str):
    label = fw_rule_label("Port", port)
    if fw_rule_exists_windows(label):
        print(f"[Info]: Port {port} is already blocked.")
        return
    os.system(
        f'netsh advfirewall firewall add rule name="{label}" '
        f'protocol=TCP dir=in action=block localport={port}'
    )
    print(f"[Info]: Port {port} -> BLOCKED")
    write_log(f"Port blocked: {port}")


def unblock_ip(ip: str):
    label = fw_rule_label("IP", ip)
    if not fw_rule_exists_windows(label):
        print(f"[Info]: No block rule found for IP {ip}.")
        return
    os.system(f'netsh advfirewall firewall delete rule name="{label}"')
    print(f"[Info]: IP {ip} -> UNBLOCKED")
    write_log(f"IP unblocked: {ip}")


def unblock_port(port: str):
    label = fw_rule_label("Port", port)
    if not fw_rule_exists_windows(label):
        print(f"[Info]: No block rule found for Port {port}.")
        return
    os.system(f'netsh advfirewall firewall delete rule name="{label}"')
    print(f"[Info]: Port {port} -> UNBLOCKED")
    write_log(f"Port unblocked: {port}")


def check_status(value: str):
    ip_label   = fw_rule_label("IP",   value)
    port_label = fw_rule_label("Port", value)
    ddos_label = f"NetSec DDoS Block {value}"

    blocked = (
        fw_rule_exists_windows(ip_label)
        or fw_rule_exists_windows(port_label)
        or fw_rule_exists_windows(ddos_label)
    )
    status = "BLOCKED" if blocked else "ALLOWED"
    print(f"[Info]: {value}  ->  {status}")
    write_log(f"Status checked: {value} = {status}")


def show_rules():
    result = os.popen("netsh advfirewall firewall show rule name=all").read()
    found  = False
    print("[Info]: Active NetSec block rules:\n")
    for line in result.splitlines():
        if "Rule Name:" in line and "NetSec Block" in line:
            rule_label = line.split("Rule Name:")[-1].strip()
            print(f"  * {rule_label}")
            found = True
    if not found:
        print("  (no active block rules found)")
    write_log("Viewed show rules")


# ---------------------------------------------------------------------------
# DDoS info (blocked list is per-session; we read the log file for history)
# ---------------------------------------------------------------------------
def show_ddos():
    print("[Info]: DDoS auto-blocked IPs (from log):\n")
    found = False
    try:
        with open(LOG_FILE) as f:
            for line in f:
                if "DDoS auto-blocked" in line:
                    print(f"  {line.strip()}")
                    found = True
    except FileNotFoundError:
        pass
    if not found:
        print("  (no DDoS blocks recorded)")


# ---------------------------------------------------------------------------
# DDoS sniff engine  (long-running; started as a separate process via GUI)
# ---------------------------------------------------------------------------
def _auto_block_ddos(ip: str):
    label = f"NetSec DDoS Block {ip}"
    if fw_rule_exists_windows(label):
        return
    os.system(
        f'netsh advfirewall firewall add rule name="{label}" '
        f'dir=in action=block remoteip={ip}'
    )
    write_log(f"DDoS auto-blocked: {ip}")
    print(f"[DDoS DETECTED]  Auto-blocked -> {ip}")


def _register_packet(ip: str):
    load_trusted_ips()
    if ip in trusted_ips:
        return
    request_count[ip] += 1
    if request_count[ip] >= DDOS_THRESHOLD:
        _auto_block_ddos(ip)
        request_count[ip] = 0


def _process_packet(packet):
    try:
        from scapy.all import IP as ScapyIP
        if packet.haslayer(ScapyIP):
            _register_packet(packet[ScapyIP].src)
    except Exception:
        pass


def _reset_counters():
    while True:
        time.sleep(RESET_TIME)
        request_count.clear()


def start_sniff():
    """Start the DDoS detection sniffer (blocks forever)."""
    try:
        from scapy.all import sniff
    except ImportError:
        print("[Error]: scapy is not installed. Run: pip install scapy")
        sys.exit(1)

    print("[Info]: DDoS sniffer started. Monitoring inbound IP traffic...")
    print(f"[Info]: Threshold: {DDOS_THRESHOLD} packets / {RESET_TIME}s  ->  auto-block")
    print("[Info]: Press Ctrl-C to stop.\n")

    threading.Thread(target=_reset_counters, daemon=True).start()

    try:
        sniff(filter="ip", prn=_process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[Info]: Sniffer stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("[Error]: Usage: PacketFilteringProgram.py <action> [value]")
        sys.exit(1)

    action = sys.argv[1].strip().lower()
    value  = sys.argv[2].strip() if len(sys.argv) >= 3 else ""

    dispatch = {
        "add_trusted":  lambda: add_trusted(value),
        "show_trusted": show_trusted,
        "block_ip":     lambda: block_ip(value),
        "block_port":   lambda: block_port(value),
        "unblock_ip":   lambda: unblock_ip(value),
        "unblock_port": lambda: unblock_port(value),
        "check":        lambda: check_status(value),
        "show_rules":   show_rules,
        "show_ddos":    show_ddos,
        "start_sniff":  start_sniff,
    }

    handler = dispatch.get(action)
    if handler is None:
        print(f"[Error]: Unknown action '{action}'.")
        print("Valid actions: add_trusted | show_trusted | block_ip | block_port |")
        print("               unblock_ip | unblock_port | check | show_rules | show_ddos | start_sniff")
        sys.exit(1)

    handler()


if __name__ == "__main__":
    main()