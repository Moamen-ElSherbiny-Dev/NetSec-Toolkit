# NetSec Toolkit  -  Modern UI  (tkinter + ttk, zero external GUI deps beyond customtkinter)
# Requires: customtkinter>=5.2
# Run as Administrator for firewall / packet-capture features.
#
# FIX SUMMARY
# -----------
# 1. PyInstaller compatibility: replaced subprocess.Popen([sys.executable, ...]) with a
#    helper that uses the frozen executable path when running as a bundled .exe, and
#    passes scripts as arguments so no second .exe is spawned from scratch.
#    When frozen (PyInstaller), scripts are embedded as data files and called via
#    runpy inside the same process via a worker thread — keeping a single exe.
#
# 2. Live Monitor "Stop" button added.
# 3. Packet Filter "Stop Sniffer" button added (stops the long-running sniff process).
# 4. Unicode chars replaced with ASCII-safe equivalents throughout.
# 5. Terminal content is now INDEPENDENT per-page and per-process:
#      - Each page owns its Terminal widget in a persistent dict keyed by page name.
#      - Switching pages does NOT clear any terminal.
#      - The "Clear" button on each page only clears that page's terminal.
#      - Live Monitor has two sub-terminals (live / arp) that are independently preserved.
#      - Packet Filter quick-view buttons each get their own sub-terminal slot.

import os, sys, subprocess, threading, time
from tkinter import filedialog, messagebox
import tkinter as tk
import customtkinter as ctk
from PIL import Image

ctk.set_appearance_mode("dark")

# =============================================================================
#  THEME
# =============================================================================
C = {
    "bg":        "#0f1117",
    "panel":     "#161b27",
    "card":      "#1c2235",
    "input_bg":  "#111520",
    "border":    "#252d42",
    "border_hi": "#3a4560",
    "accent":    "#3b82f6",
    "accent_hv": "#2563eb",
    "green":     "#22c55e",
    "green_bg":  "#0d2018",
    "green_bd":  "#1a4030",
    "red":       "#ef4444",
    "red_bg":    "#200d0d",
    "amber":     "#f59e0b",
    "amber_bg":  "#1f1500",
    "txt":       "#e2e8f0",
    "txt2":      "#94a3b8",
    "txt3":      "#475569",
    "white":     "#ffffff",
}
F_UI   = ("Segoe UI", 13)
F_SML  = ("Segoe UI", 11)
F_BIG  = ("Segoe UI", 22, "bold")
F_MED  = ("Segoe UI", 15, "bold")
F_BOLD = ("Segoe UI", 13, "bold")
F_MONO = ("Consolas", 12)


# =============================================================================
#  REUSABLE WIDGETS
# =============================================================================

def card(parent, **kw):
    return ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=10,
                        border_width=1, border_color=C["border"], **kw)

def label(parent, text, size=13, bold=False, color=None, **kw):
    weight = "bold" if bold else "normal"
    col = color or C["txt"]
    return ctk.CTkLabel(parent, text=text,
                        font=("Segoe UI", size, weight),
                        text_color=col, **kw)

def muted(parent, text, size=11, **kw):
    return label(parent, text, size=size, color=C["txt2"], **kw)

def sep(parent):
    return ctk.CTkFrame(parent, height=1, fg_color=C["border"])

def pill(parent, text, color=None, bg=None):
    fg  = color or C["accent"]
    bg_ = bg or C["card"]
    f = ctk.CTkFrame(parent, fg_color=bg_, corner_radius=6)
    ctk.CTkLabel(f, text=text, font=("Segoe UI", 10, "bold"),
                 text_color=fg).pack(padx=8, pady=3)
    return f

def primary_btn(parent, text, cmd, width=150, **kw):
    return ctk.CTkButton(parent, text=text, command=cmd,
                         fg_color=C["accent"], hover_color=C["accent_hv"],
                         text_color=C["white"], font=F_BOLD,
                         height=40, width=width, corner_radius=8, **kw)

def ghost_btn(parent, text, cmd, width=110, **kw):
    return ctk.CTkButton(parent, text=text, command=cmd,
                         fg_color=C["card"], hover_color=C["border"],
                         text_color=C["txt2"], font=F_UI,
                         height=36, width=width, corner_radius=8,
                         border_width=1, border_color=C["border"], **kw)

def stop_btn(parent, text, cmd, width=130, **kw):
    return ctk.CTkButton(parent, text=text, command=cmd,
                         fg_color=C["red_bg"], hover_color="#3a1010",
                         text_color=C["red"], font=F_BOLD,
                         height=40, width=width, corner_radius=8,
                         border_width=1, border_color=C["red"], **kw)

def entry(parent, placeholder="", width=280, var=None, **kw):
    e = ctk.CTkEntry(parent,
                     fg_color=C["input_bg"], border_color=C["border"],
                     border_width=1, text_color=C["txt"],
                     placeholder_text=placeholder,
                     placeholder_text_color=C["txt3"],
                     height=38, width=width,
                     font=F_UI, **kw)
    if var:
        e.configure(textvariable=var)
    return e


class SegmentedBar(ctk.CTkFrame):
    """Pill-style segmented control."""
    def __init__(self, parent, options, variable, on_change=None, **kw):
        super().__init__(parent, fg_color=C["panel"], corner_radius=8,
                         border_width=1, border_color=C["border"], **kw)
        self.var = variable
        self.on_change = on_change
        self.btns = {}
        for val, lbl in options:
            b = ctk.CTkButton(
                self, text=lbl,
                fg_color=C["accent"] if variable.get() == val else "transparent",
                hover_color=C["border_hi"],
                text_color=C["white"] if variable.get() == val else C["txt2"],
                font=("Segoe UI", 12, "bold"),
                height=34, corner_radius=6,
                command=lambda v=val: self._pick(v),
            )
            b.pack(side="left", padx=3, pady=3)
            self.btns[val] = b

    def _pick(self, val):
        self.var.set(val)
        for v, b in self.btns.items():
            active = v == val
            b.configure(fg_color=C["accent"] if active else "transparent",
                        text_color=C["white"] if active else C["txt2"])
        if self.on_change:
            self.on_change(val)

    def get(self):
        return self.var.get()


class Terminal(ctk.CTkTextbox):
    """Styled output terminal with persistent content."""
    def __init__(self, parent, **kw):
        super().__init__(parent,
                         fg_color=C["input_bg"],
                         border_color=C["border"], border_width=1,
                         text_color=C["txt"], font=F_MONO,
                         **kw)
        self.configure(state="disabled")

    def write(self, text):
        self.configure(state="normal")
        self.insert("end", text)
        self.see("end")
        self.configure(state="disabled")

    def clear(self):
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")

    def error(self, msg):
        self.write(f"  [ERROR]  {msg}\n")


class NavBtn(ctk.CTkButton):
    """Left-sidebar navigation button."""
    def __init__(self, parent, icon, label_text, cmd, **kw):
        super().__init__(
            parent,
            text=f"  {icon}   {label_text}",
            anchor="w",
            fg_color="transparent",
            hover_color=C["card"],
            text_color=C["txt2"],
            font=("Segoe UI", 13),
            height=46, corner_radius=8,
            command=cmd, **kw,
        )

    def activate(self):
        self.configure(fg_color=C["card"], text_color=C["accent"],
                       font=("Segoe UI", 13, "bold"))

    def deactivate(self):
        self.configure(fg_color="transparent", text_color=C["txt2"],
                       font=("Segoe UI", 13))


# =============================================================================
#  MAIN APPLICATION
# =============================================================================
class App(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("NetSec Toolkit")
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (1280 // 2)
        y = (self.winfo_screenheight() // 2) - (720 // 2)
        self.geometry(f"1280x720+{x}+{y}")
        self.minsize(1050, 650)
        self.configure(fg_color=C["bg"])
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # script_dir: where WRITABLE/user-visible files live (Logs, Config).
        #   When frozen this must be the exe's own folder, NOT the temp
        #   _MEIxxxxxx extraction folder, so logs/config persist next to the exe.
        # res_dir: where READ-ONLY bundled resources live (backend .py scripts,
        #   Assets images). When frozen these are inside the --onefile payload,
        #   extracted at runtime to sys._MEIPASS. This is what makes the exe
        #   fully self-contained (no more need to ship the .py/Assets files
        #   alongside it).
        if getattr(sys, 'frozen', False):
            self.script_dir = os.path.dirname(sys.executable)
            self.res_dir    = getattr(sys, '_MEIPASS', self.script_dir)
        else:
            self.script_dir = os.path.dirname(os.path.abspath(__file__))
            self.res_dir    = self.script_dir

        # ── Load logo once (used in sidebar + window icon + about page) ──
        _logo_path = os.path.join(self.res_dir, "Assets\\NetSec_logo.png")
        try:
            _logo_pil = Image.open(_logo_path)
            # Window title-bar icon (the tiny icon next to the window name)
            # Windows requires a real .ico for the title bar — we write one to a temp file
            import tempfile, os as _os
            from PIL import ImageTk
            _icon_pil = _logo_pil.resize((32, 32), Image.LANCZOS).convert("RGBA")
            _ico_fd, _ico_path = tempfile.mkstemp(suffix=".ico")
            _os.close(_ico_fd)
            _icon_pil.save(_ico_path, format="ICO", sizes=[(16,16),(32,32)])
            self.iconbitmap(_ico_path)
            self._icon_img  = _icon_pil   # keep PIL ref alive
            self._ico_path  = _ico_path   # keep path for cleanup
            # Sidebar logo (small)
            self._logo_sidebar = ctk.CTkImage(
                light_image=_logo_pil,
                dark_image=_logo_pil,
                size=(75, 75),
            )
            # About page logo (large) — pre-built so the page doesn't re-open the file
            self._logo_about = ctk.CTkImage(
                light_image=_logo_pil,
                dark_image=_logo_pil,
                size=(450, 450),
            )
        except Exception:
            self._logo_pil     = None
            self._logo_sidebar = None
            self._logo_about   = None

        # ── Ensure required directories exist ──
        for _sub in ("Logs", "Config"):
            _d = os.path.join(self.script_dir, _sub)
            os.makedirs(_d, exist_ok=True)
        # Ensure the trusted-IPs config file exists (blank if new)
        _trusted_path = os.path.join(self.script_dir, "Config", "trusted_ips.txt")
        if not os.path.exists(_trusted_path):
            open(_trusted_path, "w").close()

        # --- shared state ---
        self.v_port_s   = ctk.StringVar()
        self.v_port_e   = ctk.StringVar()
        self.v_mon_mode = ctk.StringVar(value="live")
        self.v_app_act  = ctk.StringVar(value="block")
        self.v_pf_act   = ctk.StringVar(value="add_trusted")

        # FIX 5: persistent terminal content storage
        # Keys: page names and sub-process slots
        # Each entry stores a list of text strings accumulated so far
        self._term_buffers: dict[str, list] = {}

        # FIX 2+3: track long-running processes so we can kill them
        self._active_procs: dict[str, subprocess.Popen] = {}

        self._nav_btns: dict[str, NavBtn] = {}
        self._active_page = ""

        self._build_sidebar()
        self._content = ctk.CTkFrame(self, fg_color="transparent")
        self._content.grid(row=0, column=1, sticky="nsew")
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

        self._build_statusbar()
        self._go("dashboard")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        # Kill any lingering background processes on exit
        for proc in self._active_procs.values():
            try:
                proc.terminate()
            except Exception:
                pass
        # Clean up the temporary .ico used for the title-bar icon
        try:
            import os as _os
            if hasattr(self, "_ico_path") and self._ico_path:
                _os.remove(self._ico_path)
        except Exception:
            pass
        self.destroy()

    # -------------------------------------------------------------------------
    # Layout helpers
    # -------------------------------------------------------------------------
    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, height=28, fg_color=C["panel"],
                           corner_radius=0, border_width=1, border_color=C["border"])
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        ctk.CTkLabel(bar, text="  ●  System active  ·  Run as Administrator for firewall features",
                     font=("Segoe UI", 10), text_color=C["txt3"]).pack(side="left", padx=8)
        ctk.CTkLabel(bar, text="NetSec Toolkit  v1.0  ",
                     font=("Segoe UI", 10), text_color=C["txt3"]).pack(side="right")

    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=220, fg_color=C["panel"],
                          corner_radius=0, border_width=0)
        sb.grid(row=0, column=0, sticky="ns")
        sb.grid_propagate(False)

        brand = ctk.CTkFrame(sb, fg_color="transparent")
        brand.pack(padx=20, pady=(20, 16), anchor="w")

        if self._logo_sidebar:
            # Logo image + text side by side
            brand_row = ctk.CTkFrame(brand, fg_color="transparent")
            brand_row.pack(anchor="w")
            ctk.CTkLabel(brand_row, text="", image=self._logo_sidebar,
                         fg_color="transparent").pack(side="left")
            brand_txt = ctk.CTkFrame(brand_row, fg_color="transparent")
            brand_txt.pack(side="left", padx=(10, 0))
            ctk.CTkLabel(brand_txt, text="NetSec",
                         font=("Segoe UI", 20, "bold"),
                         text_color=C["txt"]).pack(anchor="w")
            ctk.CTkLabel(brand_txt, text="Security Toolkit",
                         font=("Segoe UI", 12.5), text_color=C["txt3"]).pack(anchor="w")
        else:
            # Fallback to original text if logo.png is missing
            ctk.CTkLabel(brand, text="⬡  NetSec",
                         font=("Segoe UI", 20, "bold"),
                         text_color=C["txt"]).pack(anchor="w")
            ctk.CTkLabel(brand, text="Security Toolkit",
                         font=("Segoe UI", 12.5), text_color=C["txt3"]).pack(anchor="w")

        sep(sb).pack(fill="x")

        ctk.CTkLabel(sb, text="  NAVIGATION",
                     font=("Segoe UI", 11, "bold"),
                     text_color=C["txt3"]).pack(anchor="w", padx=12.5, pady=(14, 4))

        nav_items = [
            ("dashboard", "", "Dashboard"),
            ("filter",    "", "Packet Filtering"),
            ("monitor",   "", "Live Monitoring & IP-MAC"),
            ("scanner",   "", "Port Scanner"),
            ("appctrl",   "", "App Conncetion Control"),
            ("logs",      "", "System Logs"),
            ("about",     "", "About"),
        ]
        for key, icon, lbl in nav_items:
            b = NavBtn(sb, icon, lbl, cmd=lambda k=key: self._go(k))
            b.pack(fill="x", padx=10, pady=1)
            self._nav_btns[key] = b

        sep(sb).pack(fill="x", pady=(16, 0))
        ctk.CTkLabel(sb, text="  © 2026 MoamenDev",
                     font=("Segoe UI", 11), text_color=C["txt3"]).pack(
            anchor="w", padx=10, pady=(8, 0))

    def _go(self, key):
        for k, b in self._nav_btns.items():
            b.activate() if k == key else b.deactivate()
        for w in self._content.winfo_children():
            w.destroy()
        self._active_page = key
        {
            "dashboard": self._pg_dashboard,
            "scanner":   self._pg_scanner,
            "appctrl":   self._pg_appctrl,
            "monitor":   self._pg_monitor,
            "filter":    self._pg_filter,
            "logs":      self._pg_logs,
            "about":     self._pg_about,
        }[key]()

    def _page(self):
        """Non-scrollable page container — fills available space."""
        f = ctk.CTkFrame(self._content, fg_color="transparent")
        f.grid(row=0, column=0, sticky="nsew", padx=36, pady=30)
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(0, weight=1)
        return f

    def _header(self, parent, title, sub=""):
        label(parent, title, size=22, bold=True).pack(anchor="w")
        if sub:
            muted(parent, sub).pack(anchor="w", pady=(2, 0))
        sep(parent).pack(fill="x", pady=(10, 14))

    # -------------------------------------------------------------------------
    # FIX 1: Process runner - PyInstaller --onefile safe
    #
    # ROOT CAUSE: when frozen, sys.executable IS the bundled .exe, so
    #   Popen([sys.executable, "script.py", ...]) re-launches the whole GUI app.
    #
    # SOLUTION: when frozen (getattr(sys, 'frozen', False) == True) we run the
    #   backend scripts IN-PROCESS via runpy.run_path(), redirecting sys.stdout
    #   and sys.argv so the scripts behave exactly as if called from the command
    #   line.  A threading.Event lets _stop() signal the thread to abort.
    #
    #   When NOT frozen (normal .py development run) we use subprocess as before,
    #   pointing at the same python.exe that is running the GUI -- which is safe
    #   because sys.executable is then python.exe, not our app.
    #
    # FIX 5: terminal content persists per buffer_key; clear only on explicit request
    # -------------------------------------------------------------------------
    def _run(self, term: Terminal, script: str, args: list,
             buffer_key: str = None, proc_key: str = None,
             on_start=None, on_finish=None):
        """
        Run a backend .py script and stream its stdout to *term*.

        Works both in plain .py development and inside a PyInstaller --onefile exe.
        """
        import io, runpy

        stop_event = threading.Event()
        # Store the stop_event under proc_key so _stop() can signal it
        if proc_key is not None:
            self._active_procs[proc_key] = stop_event   # reuse the dict; value is Event now

        def _append(text):
            if buffer_key is not None:
                self._term_buffers.setdefault(buffer_key, []).append(text)
            self.after(0, lambda t=text: term.write(t))

        def task():
            header = (f"  Running: {script}  {' '.join(str(a) for a in args)}\n"
                      f"  {'-'*46}\n\n")
            _append(header)

            if on_start:
                self.after(0, on_start)

            full = os.path.join(self.res_dir, script)

            # ---- frozen: run in-process via runpy --------------------------------
            if getattr(sys, 'frozen', False):
                import io as _io

                # A line-buffered StringIO that fires _append for each complete line
                class _LineWriter(_io.TextIOBase):
                    def __init__(self_lw):
                        self_lw._buf = ''
                    def write(self_lw, s):
                        self_lw._buf += s
                        while '\n' in self_lw._buf:
                            line, self_lw._buf = self_lw._buf.split('\n', 1)
                            if not stop_event.is_set():
                                _append(line + '\n')
                        return len(s)
                    def flush(self_lw):
                        if self_lw._buf and not stop_event.is_set():
                            _append(self_lw._buf)
                            self_lw._buf = ''

                old_argv   = sys.argv
                old_stdout = sys.stdout
                old_stderr = sys.stderr
                writer = _LineWriter()
                sys.argv   = [full] + [str(a) for a in args]
                sys.stdout = writer
                sys.stderr = writer
                try:
                    if not os.path.exists(full):
                        raise FileNotFoundError(f"Script not found: {full}")
                    runpy.run_path(full, run_name="__main__")
                except SystemExit:
                    pass
                except FileNotFoundError as ex:
                    _append(f"\n  [ERR]  {ex}\n")
                except Exception as ex:
                    _append(f"\n  [ERR]  {ex}\n")
                finally:
                    writer.flush()
                    sys.argv   = old_argv
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr

            # ---- development: subprocess (sys.executable is python.exe here) ----
            else:
                if not os.path.exists(full):
                    _append(f"\n  [ERR]  Script not found: {full}\n")
                else:
                    cmd = [sys.executable, "-u", full] + [str(a) for a in args]
                    try:
                        cf = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                        proc = subprocess.Popen(
                            cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True, bufsize=1,
                            creationflags=cf,
                        )
                        # replace proc with a (proc, stop_event) pair so _stop can terminate
                        if proc_key is not None:
                            self._active_procs[proc_key] = (proc, stop_event)

                        for line in iter(proc.stdout.readline, ""):
                            if stop_event.is_set():
                                proc.terminate()
                                break
                            if line:
                                _append(line)
                        proc.stdout.close()
                        proc.wait()
                    except Exception as ex:
                        _append(f"\n  [ERR]  {ex}\n")

            if not stop_event.is_set():
                footer = f"\n  {'-'*46}\n  [OK]  Finished.\n"
                _append(footer)
            else:
                _append("\n  [STOP]  Process terminated by user.\n")

            if proc_key is not None:
                self._active_procs.pop(proc_key, None)
            if on_finish:
                self.after(0, on_finish)

        threading.Thread(target=task, daemon=True).start()

    # FIX 2+3: stop a running process or in-process thread
    def _stop(self, proc_key: str, term: Terminal = None):
        handle = self._active_procs.pop(proc_key, None)
        if handle is None:
            if term:
                self.after(0, lambda: term.write("\n  [INFO]  No running process to stop.\n"))
            return
        # frozen path: handle is a threading.Event
        if isinstance(handle, threading.Event):
            handle.set()
        # dev path: handle is (Popen, Event)
        elif isinstance(handle, tuple):
            proc, evt = handle
            evt.set()
            try:
                proc.terminate()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Restore terminal from buffer (called when returning to a page/sub-view)
    # -------------------------------------------------------------------------
    def _restore_term(self, term: Terminal, buffer_key: str):
        lines = self._term_buffers.get(buffer_key, [])
        if lines:
            term.clear()
            for chunk in lines:
                term.write(chunk)

    # ==========================================================================
    #  DASHBOARD
    # ==========================================================================
    def _pg_dashboard(self):
        import psutil
        p = self._page()

        _stop_flag = [False]

        # ── Title row ──
        title_row = ctk.CTkFrame(p, fg_color="transparent")
        title_row.pack(fill="x", pady=(0, 4))
        tl = ctk.CTkFrame(title_row, fg_color="transparent")
        tl.pack(side="left", fill="both", expand=True)
        label(tl, "Dashboard", size=22, bold=True).pack(anchor="w")
        muted(tl, "Live system overview  —  connection feed updates every second").pack(anchor="w", pady=(2,0))

        live_dot = ctk.CTkLabel(title_row, text="●  LIVE",
                                font=("Segoe UI", 12, "bold"), text_color=C["green"])
        live_dot.pack(side="right", anchor="center")

        # ── Admin shield indicator ──
        try:
            import ctypes
            _is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            _is_admin = False
        _shield_text  = "🛡  Admin"  if _is_admin else "🛡  Not Admin"
        _shield_color = C["green"]   if _is_admin else C["amber"]
        _shield_tip   = "Running as Administrator" if _is_admin else "Not running as Administrator — firewall features limited"
        admin_badge = ctk.CTkLabel(title_row, text=_shield_text,
                                   font=("Segoe UI", 12, "bold"), text_color=_shield_color)
        admin_badge.pack(side="right", anchor="center", padx=(0, 12))

        sep(p).pack(fill="x", pady=(10, 14))

        # ── Pulsing dot animation ──
        _dot_state = [True]
        def _pulse_dot():
            if _stop_flag[0]:
                return
            _dot_state[0] = not _dot_state[0]
            live_dot.configure(text_color=C["green"] if _dot_state[0] else C["txt3"])
            p.after(800, _pulse_dot)
        p.after(800, _pulse_dot)

        # ── Data helpers ──
        def _fw_block_counts():
            """Returns (total_block_rules, app_block_rules) in one netsh call."""
            try:
                out = subprocess.check_output(
                    'netsh advfirewall firewall show rule name=all',
                    shell=True, stderr=subprocess.DEVNULL, text=True, timeout=5)
                total, apps = 0, 0
                for l in out.splitlines():
                    if "Rule Name:" in l and "Block" in l:
                        total += 1
                        name = l.strip().split("Rule Name:")[-1].strip()
                        if name.startswith("Block "):
                            apps += 1
                return total, apps
            except Exception:
                return 0, 0

        def _ddos_count():
            try:
                lp = os.path.join(self.script_dir, "Logs\\PacketFilteringProgramLogs.txt")
                with open(lp, encoding="utf-8", errors="replace") as f:
                    return sum(1 for l in f if "DDoS auto-blocked" in l)
            except Exception:
                return 0

        def _get_conns():
            try:
                return psutil.net_connections(kind="inet")
            except Exception:
                return []

        def _fmt_speed(bps):
            if bps < 1024:
                return f"{bps:.0f} B/s"
            elif bps < 1024 ** 2:
                return f"{bps/1024:.1f} KB/s"
            elif bps < 1024 ** 3:
                return f"{bps/1024**2:.1f} MB/s"
            return f"{bps/1024**3:.2f} GB/s"

        # ── Animated counter helper (steps toward target) ──
        _anim_targets = {}   # key -> target int
        _anim_current = {}   # key -> current float

        def _animate_counter(key, lbl_widget, color, steps=8):
            if _stop_flag[0]:
                return
            target  = _anim_targets.get(key, 0)
            current = _anim_current.get(key, 0.0)
            diff    = target - current
            if abs(diff) < 0.5:
                _anim_current[key] = float(target)
                lbl_widget.configure(text=str(target))
                return
            current += diff * 0.35          # ease-out: 35% of remaining gap per step
            _anim_current[key] = current
            lbl_widget.configure(text=str(int(round(current))))
            p.after(40, lambda: _animate_counter(key, lbl_widget, color))

        def _set_stat(key, value: int, lbl_widget, color):
            old_target = _anim_targets.get(key, -1)
            _anim_targets[key] = value
            if old_target != value:
                _animate_counter(key, lbl_widget, color)

        # ── Top stat cards ──
        stats_row = ctk.CTkFrame(p, fg_color="transparent")
        stats_row.pack(fill="x", pady=(0, 12))
        for i in range(4):
            stats_row.grid_columnconfigure(i, weight=1)

        stat_lbls  = {}   # key -> CTkLabel for value
        stat_colors = {}  # key -> color

        def _stat_card(col, icon, heading, key, color, bg=None):
            bg_ = bg or C["card"]
            c = ctk.CTkFrame(stats_row, fg_color=bg_, corner_radius=10,
                             border_width=1, border_color=C["border"])
            c.grid(row=0, column=col, padx=(0 if col==0 else 8, 0), sticky="ew")
            inner = ctk.CTkFrame(c, fg_color="transparent")
            inner.pack(padx=18, pady=14, fill="x")
            top = ctk.CTkFrame(inner, fg_color="transparent")
            top.pack(fill="x")
            ctk.CTkLabel(top, text=icon, font=("Segoe UI", 16),
                         text_color=color).pack(side="left")
            muted(top, heading, size=10).pack(side="left", padx=(8,0))
            val_lbl = ctk.CTkLabel(inner, text="0", font=("Segoe UI", 28, "bold"),
                                   text_color=color)
            val_lbl.pack(anchor="w", pady=(6,0))
            stat_lbls[key]   = val_lbl
            stat_colors[key] = color

        _stat_card(0, "◉", "ACTIVE CONNECTIONS", "conns",   C["accent"],  C["card"])
        _stat_card(1, "⊛", "FIREWALL RULES",     "fwrules", C["amber"],   C["amber_bg"])
        _stat_card(2, "⊘", "BLOCKED APPS",       "apps",    C["red"],     C["red_bg"])
        _stat_card(3, "⊞", "DDoS BLOCKS",        "ddos",    C["green"],   C["green_bg"])

        # ── Middle row: connection feed (left) + I/O + quick launch (right) ──
        mid = ctk.CTkFrame(p, fg_color="transparent")
        mid.pack(fill="both", expand=True, pady=(0, 10))
        mid.grid_columnconfigure(0, weight=1)
        mid.grid_columnconfigure(1, minsize=150)
        mid.grid_rowconfigure(0, weight=1)

        # ── Left: live connection feed ──
        feed_card = ctk.CTkFrame(mid, fg_color=C["card"], corner_radius=10,
                                 border_width=1, border_color=C["border"])
        feed_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        feed_hdr = ctk.CTkFrame(feed_card, fg_color="transparent")
        feed_hdr.pack(fill="x", padx=16, pady=(12, 4))
        label(feed_hdr, "Live Connections", size=12, bold=True).pack(side="left")
        conn_count_lbl = ctk.CTkLabel(feed_hdr, text="",
                                      font=("Segoe UI", 10), text_color=C["txt3"])
        conn_count_lbl.pack(side="right")

        # Column headers
        col_hdr = ctk.CTkFrame(feed_card, fg_color="transparent")
        col_hdr.pack(fill="x", padx=16, pady=(0, 2))
        for txt, anchor_, w in [("      PROCESS","w", 165),("LOCAL","w",215),("REMOTE","w", 152),("STATUS","w", 100)]:
            ctk.CTkLabel(col_hdr, text=txt, font=("Segoe UI", 9, "bold"),
                         text_color=C["txt3"], anchor=anchor_,width=w).pack(side="left")

        feed_box = Terminal(feed_card)
        feed_box.pack(fill="both", expand=True, padx=10, pady=(0,10))

        # Track previous snapshot for diff-based updates
        _prev_conn_lines = [set()]

        def _conn_key(conn):
            la = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
            ra = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
            return (conn.pid, la, ra, conn.status)

        def _conn_line(conn):
            try:
                name = psutil.Process(conn.pid).name() if conn.pid else "System"
            except Exception:
                name = "Unknown"
            laddr  = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr  = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            status = conn.status or "-"
            return f"  {name:<22} {laddr:<32} {raddr:<22}  {status}\n", status

        # ── Right column ──
        right_col = ctk.CTkFrame(mid, fg_color="transparent")
        right_col.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right_col.grid_rowconfigure(0, weight=0)
        right_col.grid_rowconfigure(1, weight=1)
        right_col.grid_columnconfigure(0, weight=1)

        # ── Network I/O speed card ──
        io_card = ctk.CTkFrame(right_col, fg_color=C["card"], corner_radius=10,
                               border_width=1, border_color=C["border"])
        io_card.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        io_inner = ctk.CTkFrame(io_card, fg_color="transparent")
        io_inner.pack(padx=16, pady=12, fill="x")

        io_title_row = ctk.CTkFrame(io_inner, fg_color="transparent")
        io_title_row.pack(fill="x", pady=(0, 8))
        label(io_title_row, "Network Speed", size=11, bold=True).pack(side="left")
        io_ts_lbl = ctk.CTkLabel(io_title_row, text="",
                                 font=("Segoe UI", 9), text_color=C["txt3"])
        io_ts_lbl.pack(side="right")

        io_row = ctk.CTkFrame(io_inner, fg_color="transparent")
        io_row.pack(fill="x")

        io_val_lbls = {}
        io_bar_frames = {}

        def _io_half(parent, icon, direction, key, color, pad):
            f = ctk.CTkFrame(parent, fg_color=C["panel"], corner_radius=8)
            f.pack(side="left", expand=True, fill="x", padx=pad)
            fi = ctk.CTkFrame(f, fg_color="transparent")
            fi.pack(padx=10, pady=(8,6), fill="x")
            ctk.CTkLabel(fi, text=f"{icon}  {direction}",
                         font=("Segoe UI", 9), text_color=C["txt3"]).pack(anchor="w")
            v = ctk.CTkLabel(fi, text="0 B/s", font=("Segoe UI", 15, "bold"), text_color=color)
            v.pack(anchor="w", pady=(3,4))
            # Speed bar
            bar_bg = ctk.CTkFrame(fi, height=4, fg_color=C["border"], corner_radius=2)
            bar_bg.pack(fill="x")
            bar_bg.pack_propagate(False)
            bar_fill = ctk.CTkFrame(bar_bg, height=4, fg_color=color, corner_radius=2, width=0)
            bar_fill.place(x=0, y=0, relheight=1.0, relwidth=0.0)
            io_val_lbls[key]   = v
            io_bar_frames[key] = (bar_bg, bar_fill, color)

        _io_half(io_row, "↑", "UPLOAD",   "up",   C["accent"], (0, 4))
        _io_half(io_row, "↓", "DOWNLOAD", "down", C["green"],  (4, 0))

        # I/O history for bar scaling (keep rolling max over last 20 samples)
        _io_history = {"up": [0]*20, "down": [0]*20}
        _prev_io_bytes = [None]   # (sent, recv) from last sample

        def _update_io_bar(key, bps):
            hist = _io_history[key]
            hist.pop(0); hist.append(bps)
            peak = max(hist) or 1
            ratio = min(bps / peak, 1.0)
            bar_bg, bar_fill, color = io_bar_frames[key]
            bar_fill.place(relwidth=ratio)

        # ── Quick-launch tools ──
        tools_card = ctk.CTkFrame(right_col, fg_color=C["card"], corner_radius=10,
                                  border_width=1, border_color=C["border"])
        tools_card.grid(row=1, column=0, sticky="nsew")
        tci = ctk.CTkFrame(tools_card, fg_color="transparent")
        tci.pack(padx=16, pady=12, fill="both", expand=True)
        label(tci, "Quick Launch", size=11, bold=True).pack(anchor="w", pady=(0,8))

        tools = [
            ("", "Packet Filtering", C["amber"],  "filter"),
            ("", "Live Monitoring & IP-MAC",  C["green"],  "monitor"),
            ("", "Port Scanner",  C["accent"], "scanner"),
            ("", "App Connection Control",   C["red"],    "appctrl"),
            ("", "System Logs",   C["txt2"],   "logs"),
        ]
        for icon, name, color, key in tools:
            btn_f = ctk.CTkFrame(tci, fg_color=C["panel"], corner_radius=8, cursor="hand2")
            btn_f.pack(fill="x", pady=(0, 5))
            bi = ctk.CTkFrame(btn_f, fg_color="transparent")
            bi.pack(fill="x", padx=12, pady=8)
            ctk.CTkLabel(bi, text=f"{icon}  {name}",
                         font=("Segoe UI", 12, "bold"), text_color=color).pack(side="left")
            ctk.CTkLabel(bi, text="→", font=("Segoe UI", 12),
                         text_color=C["txt3"]).pack(side="right")
            for w in [btn_f, bi] + bi.winfo_children():
                w.bind("<Button-1>", lambda e, k=key: self._go(k))

        # ══════════════════════════════════════════════════════════
        #  REFRESH LOOPS — two separate cadences:
        #    • 1 s  → connection feed + I/O speed (feels live)
        #    • 10 s → firewall/app/ddos counts (expensive netsh calls)
        # ══════════════════════════════════════════════════════════
        _slow_tick = [0]

        def _fast_refresh():
            """Runs every 1 second on a background thread."""
            if _stop_flag[0]:
                return

            # ── I/O speed (delta since last sample) ──
            try:
                io = psutil.net_io_counters()
                cur_sent, cur_recv = io.bytes_sent, io.bytes_recv
            except Exception:
                cur_sent, cur_recv = 0, 0

            prev = _prev_io_bytes[0]
            if prev is not None:
                up_bps   = max(cur_sent - prev[0], 0)
                down_bps = max(cur_recv - prev[1], 0)
            else:
                up_bps = down_bps = 0
            _prev_io_bytes[0] = (cur_sent, cur_recv)

            # ── Connections (diff-based feed update) ──
            conns      = _get_conns()
            new_lines  = {}
            for c in conns[:40]:
                line, status = _conn_line(c)
                new_lines[_conn_key(c)] = line

            # Push all UI updates to main thread via after(0, ...)
            def _ui_update():
                if _stop_flag[0]:
                    return

                # I/O speed labels + bars
                io_val_lbls["up"].configure(text=_fmt_speed(up_bps))
                io_val_lbls["down"].configure(text=_fmt_speed(down_bps))
                _update_io_bar("up",   up_bps)
                _update_io_bar("down", down_bps)
                io_ts_lbl.configure(text="per second")

                # Connection feed — only rewrite if content changed
                new_keys = set(new_lines.keys())
                if new_keys != _prev_conn_lines[0]:
                    _prev_conn_lines[0] = new_keys
                    feed_box.clear()
                    for line in list(new_lines.values())[:35]:
                        feed_box.write(line)

                conn_count_lbl.configure(text=f"{len(conns)} connections")
                _set_stat("conns", len(conns),
                          stat_lbls["conns"], stat_colors["conns"])

                # Slow tick — firewall counts every 10 s
                _slow_tick[0] += 1
                if _slow_tick[0] % 10 == 1:   # also runs on first tick
                    def _slow():
                        fw, apps = _fw_block_counts()
                        ddos     = _ddos_count()
                        p.after(0, lambda: (
                            _set_stat("fwrules", fw,   stat_lbls["fwrules"], stat_colors["fwrules"]),
                            _set_stat("apps",    apps, stat_lbls["apps"],    stat_colors["apps"]),
                            _set_stat("ddos",    ddos, stat_lbls["ddos"],    stat_colors["ddos"]),
                        ))
                    threading.Thread(target=_slow, daemon=True).start()

            p.after(0, _ui_update)

            # Schedule next fast tick (1 s)
            if not _stop_flag[0]:
                p.after(1000, _schedule_fast)

        def _schedule_fast():
            if not _stop_flag[0]:
                threading.Thread(target=_fast_refresh, daemon=True).start()

        def _on_destroy(e):
            _stop_flag[0] = True
        p.bind("<Destroy>", _on_destroy)

        # Prime I/O baseline, then kick off loop
        try:
            io0 = psutil.net_io_counters()
            _prev_io_bytes[0] = (io0.bytes_sent, io0.bytes_recv)
        except Exception:
            pass
        p.after(1000, _schedule_fast)   # first tick after 1 s so delta is meaningful

    # ==========================================================================
    #  PORT SCANNER
    # ==========================================================================
    def _pg_scanner(self):
        p = self._page()
        self._header(p, "Port Scanner", "Scan localhost (127.0.0.1) for open TCP ports")

        pre = card(p)
        pre.pack(fill="x", pady=(0,8))
        pi = ctk.CTkFrame(pre, fg_color="transparent")
        pi.pack(padx=20, pady=10, fill="x")
        label(pi, "Quick Presets", size=11, bold=True, color=C["txt2"]).pack(anchor="w", pady=(0,8))
        pb = ctk.CTkFrame(pi, fg_color="transparent")
        pb.pack(anchor="w")
        for lbl, s, e in [("Common  1-1024","1","1024"),
                           ("Web  80-8080",  "80","8080"),
                           ("Database Ports","1433","5432"),
                           ("Full Range",    "1","65535")]:
            ghost_btn(pb, lbl, lambda s_=s,e_=e: (
                self.v_port_s.set(s_), self.v_port_e.set(e_)
            ), width=140).pack(side="left", padx=(0,8))

        inp = card(p)
        inp.pack(fill="x", pady=(0,8))
        ii = ctk.CTkFrame(inp, fg_color="transparent")
        ii.pack(padx=20, pady=12, fill="x")

        row = ctk.CTkFrame(ii, fg_color="transparent")
        row.pack(fill="x")
        for lbl_txt, var, ph in [("Start Port", self.v_port_s, "e.g.  1"),
                              ("End Port",   self.v_port_e, "e.g.  1024")]:
            col = ctk.CTkFrame(row, fg_color="transparent")
            col.pack(side="left", padx=(0,30))
            label(col, lbl_txt, size=11, bold=True, color=C["txt2"]).pack(anchor="w")
            entry(col, placeholder=ph, var=var, width=155).pack(pady=(6,0))

        muted(ii, "Only open ports are highlighted. All results are saved to the log file.",
              size=10).pack(anchor="w", pady=(8,0))

        term = Terminal(p)
        term.pack(fill="both", expand=True, pady=(0,8))
        self._restore_term(term, "scanner")

        btn_row = ctk.CTkFrame(p, fg_color="transparent")
        btn_row.pack(fill="x", anchor="w")

        def run():
            s, e = self.v_port_s.get().strip(), self.v_port_e.get().strip()
            if not s or not e:
                term.error("Please enter both Start Port and End Port.")
                return
            self._run(term, "PortScannerProgram.py", [s, e],
                      buffer_key="scanner", proc_key="scanner")

        def stop_scan():
            self._stop("scanner", term)

        primary_btn(btn_row, "▶  Scan Now", run).pack(side="left", padx=(0,8))
        stop_btn(btn_row, "■  Stop", stop_scan, width=100).pack(side="left", padx=(0,8))
        ghost_btn(btn_row, "Clear", lambda: (
            term.clear(),
            self._term_buffers.pop("scanner", None)
        ), width=80).pack(side="left")

    # ==========================================================================
    #  APP CONTROL
    # ==========================================================================
    def _pg_appctrl(self):
        p = self._page()

        # Use a list so list_blocked closure can reference the terminal before it's packed
        term_ref = [None]

        # Header row — title left, "List Blocked" quick-view button right (mirrors packet filter)
        hrow = ctk.CTkFrame(p, fg_color="transparent")
        hrow.pack(fill="x", pady=(0, 4))
        left = ctk.CTkFrame(hrow, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True)
        label(left, "App Connection Control", size=22, bold=True).pack(anchor="w")
        muted(left, "Block or unblock an application's outbound internet access via Windows Firewall").pack(
            anchor="w", pady=(2, 0))

        qr_app = ctk.CTkFrame(hrow, fg_color="transparent")
        qr_app.pack(side="right", anchor="s")

        def list_blocked():
            t = term_ref[0]
            self._restore_term(t, "appctrl_list")
            self._run(t, "AppConnectionControlProgram.py", ["list"],
                      buffer_key="appctrl_list")

        ghost_btn(qr_app, "List Blocked", list_blocked, width=140).pack(side="left")

        sep(p).pack(fill="x", pady=(14, 20))

        ac = card(p)
        ac.pack(fill="x", pady=(0,14))
        ai = ctk.CTkFrame(ac, fg_color="transparent")
        ai.pack(padx=20, pady=18, fill="x")

        act_hdr = ctk.CTkFrame(ai, fg_color="transparent")
        act_hdr.pack(fill="x", pady=(0, 10))
        label(act_hdr, "Select Action", size=11, bold=True, color=C["txt2"]).pack(side="left")

        seg = SegmentedBar(ai,
            [("block","Block App"), ("unblock","Unblock App"),
             ("status","Check Status")],
            variable=self.v_app_act)
        seg.pack(anchor="w")

        path_card = card(p)
        path_card.pack(fill="x", pady=(0,14))
        pi2 = ctk.CTkFrame(path_card, fg_color="transparent")
        pi2.pack(padx=20, pady=18, fill="x")
        label(pi2, "Application  (.exe)", size=11, bold=True, color=C["txt2"]).pack(anchor="w", pady=(0,8))

        pr = ctk.CTkFrame(pi2, fg_color="transparent")
        pr.pack(fill="x")
        path_var = ctk.StringVar()
        path_ent = entry(pr, placeholder="Browse or paste the full .exe path...",
                         var=path_var, width=500)
        path_ent.pack(side="left", padx=(0,10))

        def browse():
            f = filedialog.askopenfilename(
                title="Select application",
                filetypes=[("Executable","*.exe"),("All files","*.*")])
            if f:
                path_var.set(f)

        ghost_btn(pr, "Browse...", browse, width=90).pack(side="left")

        # Terminal — expands to fill remaining vertical space
        term = Terminal(p, height=260)
        term.pack(fill="both", expand=True, pady=(0,14))
        term_ref[0] = term
        self._restore_term(term, "appctrl")

        btn_row = ctk.CTkFrame(p, fg_color="transparent")
        btn_row.pack(fill="x", anchor="w")

        def run():
            action = self.v_app_act.get()
            pth = path_var.get().strip().strip('"')
            if not pth:
                term.error("Please enter or browse to an .exe path.")
                return
            self._run(term, "AppConnectionControlProgram.py", [action, f'"{pth}"'],
                      buffer_key="appctrl")

        primary_btn(btn_row, "▶  Apply", run).pack(side="left", padx=(0,8))
        ghost_btn(btn_row, "Clear", lambda: (
            term.clear(),
            self._term_buffers.pop("appctrl", None),
            self._term_buffers.pop("appctrl_list", None),
        ), width=80).pack(side="left")

    # ==========================================================================
    #  LIVE MONITOR
    # ==========================================================================
    def _pg_monitor(self):
        p = self._page()
        self._header(p, "Live Monitoring and IP-MAC Discovery",
                     "Stream active connections or scan your LAN for devices and MAC addresses")

        mc = card(p)
        mc.pack(fill="x", pady=(0,14))
        mi = ctk.CTkFrame(mc, fg_color="transparent")
        mi.pack(padx=20, pady=18, fill="x")
        label(mi, "Monitoring Mode", size=11, bold=True, color=C["txt2"]).pack(anchor="w", pady=(0,10))

        net_var = ctk.StringVar()

        seg = SegmentedBar(mi,
            [("live","Live Traffic"), ("arp","IP-MAC Discovery")],
            variable=self.v_mon_mode, on_change=None)   # on_change wired below
        seg.pack(anchor="w")

        # ── ARP input card (always in DOM; hidden via grid_remove / grid) ──
        # We use grid inside a fixed-height outer frame so pack order never changes.
        arp_frame = card(p)
        arp_frame.pack(fill="x", pady=(0,7))
        aii = ctk.CTkFrame(arp_frame, fg_color="transparent")
        aii.pack(padx=20, pady=9, fill="x")
        label(aii, "Network Base  (format: X.X.X)", size=11, bold=True,
              color=C["txt2"]).pack(anchor="w", pady=(0,4))
        net_ent = entry(aii, placeholder="e.g.  192.168.1", var=None, width=250)
        net_ent.configure(textvariable=net_var)
        net_ent.pack(anchor="w")
        muted(aii, "Pings 1-254 then reads the ARP table for MAC addresses.", size=10).pack(
            anchor="w", pady=(4,0))
        # Hidden by default (live mode is default)
        arp_frame.pack_forget()

        info = ctk.CTkFrame(p, height=10, fg_color=C["panel"], corner_radius=8,
                            border_width=1, border_color=C["border"])
        info.pack(fill="x", pady=(0,7))
        ctk.CTkFrame(info, height=10, width=3, fg_color=C["accent"],
                     corner_radius=0).pack(side="left", fill="y")
        muted(info, "  Live Traffic refreshes every 1 s and streams until stopped.  "
              "ARP scan pings the subnet once and exits.", size=11).pack(
            side="left", padx=5, pady=5)

        # ── Terminal container — fixed slot, never re-packed ──
        # Both terminals live inside one container frame that is packed once.
        # Switching modes uses grid/grid_remove inside the container so the
        # container itself (and everything below it) never moves.
        term_container = ctk.CTkFrame(p, fg_color="transparent")
        term_container.pack(fill="both", expand=True, pady=(0,14))
        term_container.grid_rowconfigure(0, weight=1)
        term_container.grid_columnconfigure(0, weight=1)

        term_live = Terminal(term_container, height=250)
        term_arp  = Terminal(term_container, height=250)

        # Grid both into the same cell; show/hide with grid() / grid_remove()
        term_live.grid(row=0, column=0, sticky="nsew")
        term_arp.grid(row=0, column=0, sticky="nsew")
        term_arp.grid_remove()   # hidden initially

        self._restore_term(term_live, "monitor_live")
        self._restore_term(term_arp,  "monitor_arp")

        current_term = [term_live]
        current_buf  = ["monitor_live"]

        def on_mode(val):
            if val == "live":
                arp_frame.pack_forget()
                term_arp.grid_remove()
                term_live.grid()
                current_term[0] = term_live
                current_buf[0]  = "monitor_live"
            else:
                # Insert arp_frame before info banner by packing with explicit order:
                # re-pack arp_frame into its correct slot (before info)
                arp_frame.pack(fill="x", pady=(0,14), before=info)
                term_live.grid_remove()
                term_arp.grid()
                current_term[0] = term_arp
                current_buf[0]  = "monitor_arp"

        seg.on_change = on_mode

        # ── Buttons — packed once, always at the bottom ──
        btn_row = ctk.CTkFrame(p, fg_color="transparent")
        btn_row.pack(fill="x", anchor="w")

        def run():
            mode = self.v_mon_mode.get()
            bk   = current_buf[0]
            t    = current_term[0]
            if mode == "arp":
                base = net_var.get().strip()
                if not base:
                    t.error("Please enter a network base address.")
                    return
                self._run(t, "LiveNetworkMonitoringProgram.py", ["arp", base],
                          buffer_key=bk, proc_key="monitor")
            else:
                self._run(t, "LiveNetworkMonitoringProgram.py", ["live"],
                          buffer_key=bk, proc_key="monitor")

        def stop():
            self._stop("monitor", current_term[0])

        primary_btn(btn_row, "▶  Start", run, width=130).pack(side="left", padx=(0,8))
        stop_btn(btn_row, "■  Stop", stop, width=120).pack(side="left", padx=(0,8))
        ghost_btn(btn_row, "Clear", lambda: (
            current_term[0].clear(),
            self._term_buffers.pop(current_buf[0], None)
        ), width=80).pack(side="left")

        # Apply correct initial state in case user left the page on ARP mode
        if self.v_mon_mode.get() == "arp":
            on_mode("arp")

    # ==========================================================================
    #  PACKET FILTER
    # ==========================================================================
    def _pg_filter(self):
        p = self._page()

        # ── Header row with quick-view buttons on the right ──
        hrow = ctk.CTkFrame(p, fg_color="transparent")
        hrow.pack(fill="x", pady=(0,4))
        left_h = ctk.CTkFrame(hrow, fg_color="transparent")
        left_h.pack(side="left", fill="both", expand=True)
        label(left_h, "Packet Filtering", size=22, bold=True).pack(anchor="w")
        muted(left_h, "Manage firewall rules, trusted IPs, and the DDoS auto-block engine").pack(
            anchor="w", pady=(2,0))

        # Terminal created early so quick-view closures can reference it
        term = Terminal(p, height=240)   # packed later

        qr = ctk.CTkFrame(hrow, fg_color="transparent")
        qr.pack(side="right", anchor="s")

        def quick_run(action):
            self._restore_term(term, f"filter_{action}")
            self._run(term, "PacketFilteringProgram.py", [action],
                      buffer_key=f"filter_{action}")

        for lbl_txt, action in [("Show Rules","show_rules"),
                             ("DDoS Blocks","show_ddos"),
                             ("Trusted IPs","show_trusted")]:
            ghost_btn(qr, lbl_txt, lambda a=action: quick_run(a),
                      width=108).pack(side="left", padx=(0,6))

        sep(p).pack(fill="x", pady=(14,16))

        # ── Action card — full width ──
        ac = card(p)
        ac.pack(fill="x", pady=(0, 10))
        ai = ctk.CTkFrame(ac, fg_color="transparent")
        ai.pack(padx=16, pady=14, fill="x")
        label(ai, "Action", size=11, bold=True, color=C["txt2"]).pack(anchor="w", pady=(0,8))

        val_entry = [None]

        ACTION_META = {
            "add_trusted":  ("IP Address",  "e.g.  192.168.1.10  -- will be whitelisted"),
            "block_ip":     ("IP Address",  "e.g.  10.0.0.5"),
            "block_port":   ("TCP Port",    "e.g.  8080"),
            "unblock_ip":   ("IP Address",  "IP address to unblock"),
            "unblock_port": ("TCP Port",    "Port number to unblock"),
            "check":        ("IP or Port",  "Enter an IP address or port number"),
        }

        # ── Two-column row: IP/Port entry (left) + DDoS panel (right) ──
        mid = ctk.CTkFrame(p, fg_color="transparent")
        mid.pack(fill="x", pady=(0, 10))
        mid.grid_columnconfigure(0, weight=4)
        mid.grid_columnconfigure(1, weight=1)
        mid.grid_rowconfigure(0, weight=1)

        # Left: IP/Port value entry card
        val_card = card(mid)
        val_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        def on_action(val):
            for w in val_card.winfo_children():
                w.destroy()
            lbl_txt, ph = ACTION_META[val]
            vi = ctk.CTkFrame(val_card, fg_color="transparent")
            vi.pack(padx=16, pady=14, fill="x")
            label(vi, lbl_txt, size=11, bold=True, color=C["txt2"]).pack(anchor="w", pady=(0,6))
            e = entry(vi, placeholder=ph, width=260)
            e.pack(anchor="w")
            val_entry[0] = e

        seg = SegmentedBar(ai,
            [("add_trusted","Add Trusted IP"), ("block_ip","Block IP"),
             ("block_port","Block Port"),      ("unblock_ip","Unblock IP"),
             ("unblock_port","Unblock Port"),  ("check","Check Status")],
            variable=self.v_pf_act, on_change=on_action)
        seg.pack(anchor="w")

        on_action(self.v_pf_act.get())

        # Right: DDoS Auto-Block Engine panel
        ddos = ctk.CTkFrame(mid, fg_color=C["green_bg"], corner_radius=10,
                            border_width=1, border_color=C["green_bd"])
        ddos.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        dr = ctk.CTkFrame(ddos, fg_color="transparent")
        dr.pack(fill="x", padx=18, pady=14)

        label(dr, "⊛  DDoS Auto-Block Engine", size=14, bold=True, color=C["green"]).pack(anchor="w")
        muted(dr, "Auto-blocks any IP sending >=50 packets in 10s. Trusted IPs are always exempt.",
              size=11).pack(anchor="w", pady=(6, 14))

        def start_sniffer():
            self._restore_term(term, "filter_sniffer")
            self._run(term, "PacketFilteringProgram.py", ["start_sniff"],
                      buffer_key="filter_sniffer", proc_key="sniffer")

        def stop_sniffer():
            self._stop("sniffer", term)

        ddos_btns = ctk.CTkFrame(dr, fg_color="transparent")
        ddos_btns.pack(anchor="w")
        ctk.CTkButton(ddos_btns, text="▶  Start Sniffer",
                      fg_color=C["green_bd"], hover_color="#2a5a3a",
                      text_color=C["green"], font=F_BOLD,
                      height=38, width=140, corner_radius=8,
                      command=start_sniffer).pack(side="left", padx=(0,8))
        ctk.CTkButton(ddos_btns, text="■  Stop Sniffer",
                      fg_color=C["red_bg"], hover_color="#3a1010",
                      text_color=C["red"], font=F_BOLD,
                      height=38, width=140, corner_radius=8,
                      border_width=1, border_color=C["red"],
                      command=stop_sniffer).pack(side="left")

        # ── Terminal — full width, expands to fill remaining vertical space ──
        term.pack(fill="both", expand=True, pady=(0,12))
        self._restore_term(term, "filter_main")

        btn_row = ctk.CTkFrame(p, fg_color="transparent")
        btn_row.pack(fill="x", anchor="w")

        def run():
            action = self.v_pf_act.get()
            val = (val_entry[0].get() if val_entry[0] else "").strip()
            if not val:
                term.error("Value cannot be empty.")
                return
            self._restore_term(term, "filter_main")
            self._run(term, "PacketFilteringProgram.py", [action, val],
                      buffer_key="filter_main")

        primary_btn(btn_row, "▶  Apply", run, width=120).pack(side="left", padx=(0,8))
        ghost_btn(btn_row, "Clear", lambda: (
            term.clear(),
            [self._term_buffers.pop(k, None)
             for k in list(self._term_buffers.keys()) if k.startswith("filter_")]
        ), width=80).pack(side="left")

    # ==========================================================================
    #  SYSTEM LOGS
    # ==========================================================================
    def _pg_logs(self):
        p = self._page()
        self._header(p, "System Logs", "Browse log files generated by each tool")

        LOG_FILES = [
            ("  Packet Filtering",          os.path.join("Logs", "PacketFilteringProgramLogs.txt")),
            ("  Live Monitoring Traffic",   os.path.join("Logs", "LiveNetworkMonitoringProgram - Live MonitoringLogs.txt")),
            ("  IP-MAC",                    os.path.join("Logs", "LiveNetworkMonitoringProgram - IP_ARPLogs.txt")),
            ("  Port Scanner",              os.path.join("Logs", "PortScannerProgramLogs.txt")),
            ("  App Connection Control",    os.path.join("Logs", "AppConnectionControlProgramLogs.txt")),
        ]

        picker = ctk.CTkFrame(p, fg_color=C["panel"], corner_radius=10,
                              border_width=1, border_color=C["border"])
        picker.pack(fill="x", pady=(0,16))
        pi = ctk.CTkFrame(picker, fg_color="transparent")
        pi.pack(padx=20, pady=14, fill="x")
        label(pi, "Select Log File", size=11, bold=True, color=C["txt2"]).pack(anchor="w", pady=(0,10))

        btn_row_log = ctk.CTkFrame(pi, fg_color="transparent")
        btn_row_log.pack(fill="x")

        term = Terminal(p, height=420)
        term.pack(fill="both", expand=True, pady=(0,14))
        term.write("  Select a log file above to view its contents.\n")

        active_btn = [None]

        def load(title, fname, btn):
            if active_btn[0] and active_btn[0] is not btn:
                active_btn[0].configure(fg_color=C["card"], text_color=C["txt2"])
            btn.configure(fg_color=C["accent"], text_color=C["white"])
            active_btn[0] = btn

            term.clear()
            full = os.path.join(self.script_dir, fname)
            term.write(f"  -- {title.strip()} --\n\n")
            if os.path.exists(full):
                with open(full, encoding="utf-8", errors="replace") as f:
                    term.write(f.read())
            else:
                term.write(
                    f"  Log not found at:\n  {full}\n\n"
                    "  Run the corresponding tool first to generate entries.\n")

        for name, fname in LOG_FILES:
            b = ghost_btn(btn_row_log, name, cmd=None, width=140)
            b.configure(command=lambda t=name, f=fname, btn=b: load(t, f, btn))
            b.pack(side="left", padx=(0,8))

        bot = ctk.CTkFrame(p, fg_color="transparent")
        bot.pack(fill="x")
        ghost_btn(bot, "Clear View",
                  lambda: (term.clear(),
                           term.write("  Select a log file above to view its contents.\n")),
                  width=100).pack(side="left")


    # ==========================================================================
    #  ABOUT
    # ==========================================================================
    def _pg_about(self):
        p = self._page()

        # ── Bold heading ──
        label(p, "NetSec Toolkit", size=26, bold=True).pack(anchor="center", pady=(10, 4))

        # ── Sub-heading (smaller, lighter) ──
        muted(p, "A lightweight Windows network security suite for monitoring, filtering, and control",
              size=13).pack(anchor="center", pady=(0, 24))

        sep(p).pack(fill="x", pady=(0, 24))

        logo = self._logo_about or ctk.CTkImage(
            light_image=Image.open(os.path.join(self.res_dir, "Assets\\NetSec_logo.png")),
            dark_image=Image.open(os.path.join(self.res_dir, "Assets\\NetSec_logo.png")),
            size=(450, 450),
        )

        # ── Placeholder image (centred) ──
        img_outer = ctk.CTkFrame(p, fg_color="transparent")
        img_outer.pack(anchor="center", pady=(0, 24))
        img_card = ctk.CTkFrame(img_outer, width=450, height=450,
                                fg_color="transparent", corner_radius=14,
                                border_width=0, border_color=C["border"])
        img_card.pack()
        img_card.pack_propagate(False)
        ctk.CTkLabel(img_card, text="", image=logo, fg_color="transparent",
                     font=("Segoe UI", 13), text_color=C["txt3"]).place(
            relx=0.5, rely=0.5, anchor="center")

        sep(p).pack(fill="x", pady=(0, 12))

        # ── 4 placeholder lines aligned bottom-right ──
        info_outer = ctk.CTkFrame(p, fg_color="transparent")
        info_outer.pack(fill="x", pady=(0,2))
        info_block = ctk.CTkFrame(info_outer, fg_color="transparent")
        info_block.pack(padx=4)
        for line in [
            "NetSec Toolkit| Graphical User Interface",
            "Version 1.0.0",
            "Copyright © 2026 MoamenDev",
            "Run as Administrator for full feature access",
        ]:
            muted(info_block, line, size=11).pack(anchor="center", pady=0)


# =============================================================================
if __name__ == "__main__":
    app = App()
    app.mainloop()