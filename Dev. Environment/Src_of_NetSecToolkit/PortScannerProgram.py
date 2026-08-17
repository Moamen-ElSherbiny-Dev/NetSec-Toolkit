# Port Scanner Program
# Called by GUI with args: port_start port_end
# Usage: python PortScannerProgram.py <port_start> <port_end>

import socket
import sys
import os
from datetime import datetime

# ---------------------------------------------------------------------------
# Import ServicesDictionary from the same folder as this script
# ---------------------------------------------------------------------------
def _get_base_dir():
    # When frozen by PyInstaller, use the exe's directory for logs/data.
    # When running as plain .py, use the script's directory as before.
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))
script_dir = _get_base_dir()
sys.path.insert(0, script_dir)
from ServicesDictionary import services


# ---------------------------------------------------------------------------
# Argument parsing - GUI passes two positional args
# ---------------------------------------------------------------------------
def parse_args():
    if len(sys.argv) != 3:
        print("[Error]: Usage: PortScannerProgram.py <port_start> <port_end>")
        sys.exit(1)

    try:
        port_start = int(sys.argv[1])
        port_end   = int(sys.argv[2])
    except ValueError:
        print("[Error]: Both arguments must be integers.")
        sys.exit(1)

    if port_start < 1:
        print("[Error]: Port start must be >= 1.")
        sys.exit(1)

    if port_end > 65535:
        print("[Error]: Port end must be <= 65535.")
        sys.exit(1)

    if port_end <= port_start:
        print("[Error]: Port end must be greater than port start.")
        sys.exit(1)

    return port_start, port_end


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------
def scan(port_start, port_end):
    ip   = "127.0.0.1"
    logs = [f"\n# Scan started: Port {port_start} -> {port_end}"]

    print(f"[Info]: Scanning {ip}  Ports {port_start} - {port_end} ...\n")

    for port in range(port_start, port_end + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result     = sock.connect_ex((ip, port))
        service    = services.get(port, "Unknown Service")
        time_now   = datetime.now().strftime("%Y-%m-%d | %H:%M:%S")

        if result == 0:
            msg = f"[{time_now}] Port: {port:>5} | OPEN   | {service:<25} | TCP"
        else:
            msg = f"[{time_now}] Port: {port:>5} | closed"

        print(msg)
        logs.append(msg)
        sock.close()

    # Write log
    log_path = os.path.join(script_dir, "Logs\\PortScannerProgramLogs.txt")
    try:
        with open(log_path, "a") as f:
            for line in logs:
                f.write(line + "\n")
    except Exception as e:
        print(f"[Warning]: Could not write log - {e}")

    print("\n[Info]: Scan complete.")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    p_start, p_end = parse_args()
    scan(p_start, p_end)