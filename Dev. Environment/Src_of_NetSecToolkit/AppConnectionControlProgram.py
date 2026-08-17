# App Connection Control Program
# Must Run as Administrator
#
# Called by GUI with args: <action> <exe_path>
# action: block | unblock | status | list
#
# Usage examples:
#   python AppConnectionControlProgram.py block   "C:\Path\app.exe"
#   python AppConnectionControlProgram.py unblock "C:\Path\app.exe"
#   python AppConnectionControlProgram.py status  "C:\Path\app.exe"
#   python AppConnectionControlProgram.py list

import os
import sys
from datetime import datetime

def _get_base_dir():
    # When frozen by PyInstaller, use the exe's directory for logs/data.
    # When running as plain .py, use the script's directory as before.
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))
script_dir = _get_base_dir()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_rule_name(app_name: str) -> str:
    return f"Block {app_name}"


def rule_exists(rule: str) -> bool:
    result = os.popen(f'netsh advfirewall firewall show rule name="{rule}"').read()
    return "No rules match" not in result


def write_log(message: str):
    log_path = os.path.join(script_dir, "Logs\\AppConnectionControlProgramLogs.txt")
    try:
        with open(log_path, "a") as f:
            ts = datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
            f.write(f"[{ts}] {message}\n")
    except Exception as e:
        print(f"[Warning]: Could not write log - {e}")


def parse_exe_path(raw: str) -> tuple[str, str, str]:
    """Validate the path and return (path, app_name, rule_name)."""
    path = raw.strip().strip('"')
    if not os.path.exists(path):
        print(f"[Error]: Path does not exist -> {path}")
        sys.exit(1)
    if not path.lower().endswith(".exe"):
        print("[Error]: Path must point to an .exe file.")
        sys.exit(1)
    name = os.path.basename(path)
    return path, name, get_rule_name(name)


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
def do_block(path: str, app_name: str, rule: str):
    if rule_exists(rule):
        msg = f"[Info]: {app_name} is already BLOCKED."
        print(msg)
        write_log(f"{app_name} | already blocked")
    else:
        os.system(
            f'netsh advfirewall firewall add rule name="{rule}" '
            f'dir=out action=block program="{path}" enable=yes'
        )
        print(f"[Info]: {app_name} -> BLOCKED successfully.")
        write_log(f"{app_name} | blocked successfully")


def do_unblock(path: str, app_name: str, rule: str):
    if not rule_exists(rule):
        print(f"[Info]: {app_name} is not blocked.")
        write_log(f"{app_name} | already unblocked")
    else:
        os.system(f'netsh advfirewall firewall delete rule name="{rule}"')
        print(f"[Info]: {app_name} -> UNBLOCKED successfully.")
        write_log(f"{app_name} | unblocked successfully")


def do_status(path: str, app_name: str, rule: str):
    if rule_exists(rule):
        print(f"[Info]: {app_name} -> Status: BLOCKED")
        write_log(f"{app_name} | Status checked: BLOCKED")
    else:
        print(f"[Info]: {app_name} -> Status: NOT BLOCKED")
        write_log(f"{app_name} | Status checked: NOT BLOCKED")


def do_list():
    result = os.popen("netsh advfirewall firewall show rule name=all").read()
    found = False
    print("[Info]: Blocked applications:\n")
    for line in result.splitlines():
        if "Rule Name:" in line and "Block " in line:
            rule_name = line.split("Rule Name:")[-1].strip()
            if rule_name.startswith("Block "):
                app = rule_name[len("Block "):]
                print(f"  * {app}  ->  BLOCKED")
                found = True
    if not found:
        print("  (no blocked applications found)")
    write_log("Viewed blocked apps list")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("[Error]: Usage: AppConnectionControlProgram.py <action> [exe_path]")
        print("         actions: block | unblock | status | list")
        sys.exit(1)

    action = sys.argv[1].strip().lower()

    if action == "list":
        do_list()
        return

    if len(sys.argv) < 3:
        print(f"[Error]: Action '{action}' requires an exe path as the second argument.")
        sys.exit(1)

    exe_raw = " ".join(sys.argv[2:])   # handle paths with spaces
    path, app_name, rule = parse_exe_path(exe_raw)

    if action == "block":
        do_block(path, app_name, rule)
    elif action == "unblock":
        do_unblock(path, app_name, rule)
    elif action == "status":
        do_status(path, app_name, rule)
    else:
        print(f"[Error]: Unknown action '{action}'. Valid: block | unblock | status | list")
        sys.exit(1)


if __name__ == "__main__":
    main()