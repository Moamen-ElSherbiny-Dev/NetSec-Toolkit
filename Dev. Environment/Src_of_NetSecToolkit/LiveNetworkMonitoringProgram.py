# Live Network Monitoring Program
#
# Called by GUI with args: <mode> [network_base]
#   mode: live | arp
#   network_base: required for arp mode, e.g. 192.168.1
#
# Usage:
#   python LiveNetworkMonitoringProgram.py live
#   python LiveNetworkMonitoringProgram.py arp 192.168.1

import os
import sys
import time
import psutil
from datetime import datetime

def _get_base_dir():
    # When frozen by PyInstaller, use the exe's directory for logs/data.
    # When running as plain .py, use the script's directory as before.
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))
script_dir = _get_base_dir()


# ---------------------------------------------------------------------------
# IP & ARP scan
# ---------------------------------------------------------------------------
def ip_arp_scan(base_ip: str):
    if base_ip.count(".") != 2:
        print(f"[Error]: Invalid network address format. Expected X.X.X  got -> {base_ip}")
        sys.exit(1)

    print(f"[Info]: Scanning network {base_ip}.0/24 ...\n")

    devices = []
    logs    = [f"\n# Network scan: {base_ip}.x"]
    dt      = datetime.now()
    ts      = dt.strftime("%Y-%m-%d | %H:%M:%S")

    # --- Ping sweep ---
    for i in range(1, 255):
        ip       = f"{base_ip}.{i}"
        response = os.system(f"ping -n 1 -w 250 {ip} > nul 2>&1")
        if response == 0:
            print(f"  [ONLINE]  {ip}")
            devices.append(ip)
            logs.append(f"[{ts}.{dt.microsecond}] Device online: {ip}")

    if not devices:
        print("\n[Info]: No active devices found on the network.")
        return

    # --- ARP table ---
    print(f"\n[Info]: Resolving MAC addresses for {len(devices)} device(s)...\n")
    logs.append("\n# ARP Results")
    arp_output = os.popen("arp -a").read()

    found_any = False
    for line in arp_output.splitlines():
        for ip in devices:
            if ip in line:
                print(f"  {line.strip()}")
                logs.append(f"[{ts}.{dt.microsecond}] MAC -> {line.strip()}")
                found_any = True

    if not found_any:
        print("[Info]: No MAC entries found in ARP table (try running as administrator).")

    # Write log
    log_path = os.path.join(script_dir, "Logs\\LiveNetworkMonitoringProgram - IP_ARPLogs.txt")
    try:
        with open(log_path, "a") as f:
            for entry in logs:
                f.write(entry + "\n")
    except Exception as e:
        print(f"[Warning]: Could not write ARP log - {e}")

    print("\n[Info]: ARP scan complete.")


# ---------------------------------------------------------------------------
# Live traffic monitoring  (streams until Ctrl-C / GUI closes the process)
# ---------------------------------------------------------------------------
def live_monitoring():
    print("[Info]: Live traffic monitoring started. Press Ctrl-C to stop.\n")
    log_path = os.path.join(script_dir, "Logs\\LiveNetworkMonitoringProgram - Live MonitoringLogs.txt")

    try:
        while True:
            connections = psutil.net_connections(kind="inet")
            batch_logs  = []
            dt          = datetime.now()
            ts          = dt.strftime("%Y-%m-%d | %H:%M:%S")

            counter = 0
            for conn in connections:
                counter += 1

                # Resolve process name
                try:
                    app_name = psutil.Process(conn.pid).name() if conn.pid else "System"
                except Exception:
                    app_name = "Unknown"

                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"

                msg = (
                    f"[{ts}.{dt.microsecond}] "
                    f"#{counter:>4} | {app_name:<25} | "
                    f"{laddr:<22} -> {raddr:<22} | {conn.status}"
                )
                print(msg)
                batch_logs.append(msg)

            print()   # blank line between snapshots

            # Flush logs
            try:
                with open(log_path, "a") as f:
                    for line in batch_logs:
                        f.write(line + "\n")
            except Exception as e:
                print(f"[Warning]: Could not write live log - {e}")

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[Info]: Monitoring stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("[Error]: Usage: LiveNetworkMonitoringProgram.py <mode> [network_base]")
        print("         modes: live | arp")
        sys.exit(1)

    mode = sys.argv[1].strip().lower()

    if mode == "arp":
        if len(sys.argv) < 3:
            print("[Error]: ARP mode requires a network base address, e.g. 192.168.1")
            sys.exit(1)
        base_ip = sys.argv[2].strip()
        ip_arp_scan(base_ip)

    elif mode == "live":
        live_monitoring()

    else:
        print(f"[Error]: Unknown mode '{mode}'. Valid options: live | arp")
        sys.exit(1)


if __name__ == "__main__":
    main()