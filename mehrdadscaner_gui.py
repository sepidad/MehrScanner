#!/usr/bin/env python3
"""Windows desktop interface for MehrScanner."""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from datetime import date
from pathlib import Path
from tkinter import messagebox

try:
    import ttkbootstrap as ttk

    HAS_BOOTSTRAP = True
except ImportError:
    from tkinter import ttk

    HAS_BOOTSTRAP = False

WINDOW_BASE: type = ttk.Window if HAS_BOOTSTRAP else tk.Tk

import mehrdadscaner as scanner


PROJECT_DIR = Path(__file__).resolve().parent
SCANNER_PATH = PROJECT_DIR / "mehrdadscaner.py"
OUT_DIR = PROJECT_DIR / "out"
SCANS_DIR = OUT_DIR / "scans"
SETTINGS_PATH = PROJECT_DIR / "mehrdadscaner_gui_settings.json"
DEFAULT_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=100000"
DEFAULT_UPLOAD_URL = "https://speed.cloudflare.com/__up"
HIDDEN_PROCESS_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)
NEW_PROCESS_GROUP_FLAG = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
THEMES = [
    "flatly",
    "cosmo",
    "minty",
    "darkly",
    "superhero",
    "vapor",
    "solar",
    "cyborg",
]
DARK_THEMES = {"darkly", "superhero", "vapor", "solar", "cyborg"}


def parse_specific_targets(raw: str) -> list[str]:
    """Validate and normalize comma-separated IPv4 addresses or networks."""
    targets: list[str] = []
    for item in raw.split(","):
        value = item.strip()
        if not value:
            continue
        try:
            if "/" in value:
                targets.append(str(ipaddress.IPv4Network(value, strict=False)))
            else:
                targets.append(str(ipaddress.IPv4Address(value)))
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 address or CIDR: {value}") from exc
    return targets


class ScannerApp(WINDOW_BASE):
    def __init__(self) -> None:
        super().__init__()
        self.settings = self._load_settings()
        self.title("MehrScanner")
        self.minsize(1080, 760)
        self.geometry("1280x860")
        self.process: subprocess.Popen[str] | None = None
        self.log_queue: queue.Queue[str | None] = queue.Queue()
        self.active_output_dir = OUT_DIR
        self.control_dir = OUT_DIR / ".mehrdadscaner-control"
        self._last_auto_remark = ""
        self.scan_history: list[Path] = []
        self.phase1_rows: list[dict[str, str]] = []
        self.stage2_rows: list[dict[str, str]] = []
        self._stage2_iids: list[str] = []
        self.selected_scan = tk.StringVar()
        self.config_text = tk.StringVar(value=self.settings.get("last_config", ""))
        self.theme_name = tk.StringVar(value=self.settings.get("theme", "flatly"))
        self.concurrency = tk.StringVar(value="64")
        self.candidate_limit = tk.StringVar(value="200")
        self.stop_after_hits = tk.StringVar(value="10000")
        self.timeout = tk.StringVar(value="2.5")
        self.neighbor_radius = tk.StringVar(value="1")
        self.neighbor_limit = tk.StringVar(value="128")
        self.ports = tk.StringVar()
        self.candidates_path = tk.StringVar()
        self.specific_targets = tk.StringVar()
        self.seed = tk.StringVar(value="20260522")
        self.delay = tk.StringVar(value="0")
        self.jitter = tk.StringVar(value="0")
        self.min_score = tk.StringVar(value="3")
        self.progress_every = tk.StringVar(value="200")
        self.top_results = tk.StringVar(value="20")
        self.config_count = tk.StringVar(value="20")
        self.config_remark = tk.StringVar()
        self.output_dir = tk.StringVar(value=str(OUT_DIR))
        self.expected_egress_ip = tk.StringVar()
        self.blocked_egress_ips = tk.StringVar()
        self.xray_path = tk.StringVar()
        self.run_stage2 = tk.BooleanVar(value=True)
        self.stage2_during_scan = tk.BooleanVar(value=False)
        self.stage2_count = tk.StringVar(value="3000")
        self.xray_concurrency = tk.StringVar(value="4")
        self.xray_timeout = tk.StringVar(value="10")
        self.test_url = tk.StringVar(value="http://cp.cloudflare.com/generate_204")
        self.download_url = tk.StringVar(value=DEFAULT_DOWNLOAD_URL)
        self.download_kb = tk.StringVar(value="100")
        self.upload_url = tk.StringVar(value=DEFAULT_UPLOAD_URL)
        self.upload_kb = tk.StringVar(value="50")
        self.phase1_latency = tk.StringVar(value="700")
        self.direct_egress = tk.BooleanVar(value=True)
        self.skip_websocket = tk.BooleanVar(value=False)
        self.reuse_clean = tk.BooleanVar(value=True)
        self.continuous = tk.BooleanVar(value=False)
        self.local_fast = tk.BooleanVar(value=False)
        self.safe_mode = tk.BooleanVar(value=False)
        self.show_failures = tk.BooleanVar(value=False)
        self.use_system_proxy = tk.BooleanVar(value=False)
        self.check_tun = tk.BooleanVar(value=True)
        self.auto_install_xray = tk.BooleanVar(value=True)
        self.status_text = tk.StringVar(value="Ready. Paste a VLESS config and start the scan.")
        self._build_ui()
        self.config_text.trace_add("write", self._on_config_changed)
        self.selected_scan.trace_add("write", self._on_scan_selected)
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self.after(120, self._drain_log_queue)
        self._apply_default_remark()
        self._refresh_scan_history()
        self._load_results()

    def _build_ui(self) -> None:
        self.app_style = ttk.Style()
        if HAS_BOOTSTRAP:
            self.app_style.theme_use(self._validated_theme())
        else:
            self.app_style.theme_use("clam")
        self.app_style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        self.app_style.configure("Run.TButton", font=("Segoe UI", 10, "bold"))
        self._apply_muted_color()
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        header = ttk.Frame(self, padding=(18, 6, 18, 4))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="MehrScanner", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Stage 1 finds candidates. Stage 2 validates the tunnel and measures download/upload.",
            style="Muted.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))
        self.theme_selector = ttk.Combobox(
            header,
            textvariable=self.theme_name,
            state="readonly",
            values=THEMES,
            width=16,
        )
        self.theme_selector.grid(row=0, column=1, sticky="e")
        self.theme_selector.bind("<<ComboboxSelected>>", self._on_theme_selected)
        if not HAS_BOOTSTRAP:
            self.theme_selector.configure(state="disabled")

        config_frame = ttk.LabelFrame(self, text="VLESS configuration", padding=12)
        config_frame.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 10))
        config_frame.columnconfigure(0, weight=1)
        ttk.Entry(config_frame, textvariable=self.config_text).grid(row=0, column=0, sticky="ew")
        history_row = ttk.Frame(config_frame)
        history_row.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        history_row.columnconfigure(1, weight=1)
        ttk.Label(history_row, text="Previous scans").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.scan_selector = ttk.Combobox(
            history_row,
            textvariable=self.selected_scan,
            state="readonly",
        )
        self.scan_selector.grid(row=0, column=1, sticky="ew")
        ttk.Button(history_row, text="Rescan", command=self.rescan_selected_scan).grid(row=0, column=2, padx=(8, 0))
        ttk.Button(history_row, text="Refresh", command=self._refresh_scan_history).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(history_row, text="Delete", command=self.delete_selected_scan).grid(row=0, column=4, padx=(8, 0))

        controls = ttk.Frame(self, padding=(18, 0, 18, 10))
        controls.grid(row=2, column=0, sticky="ew")
        controls.columnconfigure(0, weight=1)
        controls.columnconfigure(1, weight=1)

        phase1 = ttk.LabelFrame(controls, text="Stage 1 candidate scan", padding=12)
        phase1.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        phase1.columnconfigure(1, weight=1)
        phase2 = ttk.LabelFrame(controls, text="Stage 2 validation and speed", padding=12)
        phase2.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        ttk.Label(phase1, text="Specific IPs/CIDRs (comma-separated, optional)").grid(
            row=0, column=0, sticky="w", padx=(0, 10), pady=3
        )
        ttk.Entry(phase1, textvariable=self.specific_targets).grid(
            row=0, column=1, sticky="ew", pady=3
        )
        ttk.Button(phase1, text="Start Target Test", command=self.start_target_test).grid(
            row=0, column=2, sticky="w", padx=(8, 0), pady=3
        )
        self._add_grid_fields(
            phase1,
            [
                ("Parallel checks", self.concurrency),
                ("Candidates per batch", self.candidate_limit),
                ("Stop after clean hits", self.stop_after_hits),
                ("Timeout (seconds)", self.timeout),
                ("Neighbor /24 radius", self.neighbor_radius),
                ("Max latency for clean (ms)", self.phase1_latency),
            ],
            start_row=1,
        )
        ttk.Checkbutton(
            phase1,
            text="Check that traffic is not exiting from a known VPN/server IP",
            variable=self.direct_egress,
        ).grid(row=7, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Checkbutton(
            phase1,
            text="Fast local mode (use only when not on VPN/TUN/proxy)",
            variable=self.local_fast,
        ).grid(row=8, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Button(phase1, text="Advanced Settings", command=self.open_advanced_settings).grid(
            row=9, column=0, columnspan=2, sticky="w", pady=(8, 0)
        )

        ttk.Checkbutton(
            phase2, text="Run Stage 2 validation", variable=self.run_stage2
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 7))
        ttk.Checkbutton(
            phase2,
            text="Fast mode: validate early clean IPs while Stage 1 scans",
            variable=self.stage2_during_scan,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 7))
        self._add_grid_fields(
            phase2,
            [
                ("IPs to validate", self.stage2_count),
                ("Parallel validations", self.xray_concurrency),
                ("Per-test timeout (seconds)", self.xray_timeout),
                ("Download URL", self.download_url),
                ("Download KB per IP", self.download_kb),
                ("Upload URL", self.upload_url),
                ("Upload KB per IP", self.upload_kb),
                ("Validation URL", self.test_url),
            ],
            start_row=2,
        )

        results_pane = ttk.Panedwindow(self, orient="horizontal")
        results_pane.grid(row=3, column=0, sticky="nsew", padx=18, pady=(0, 10))

        phase1_results_frame = ttk.LabelFrame(results_pane, text="Phase 1 clean IPs", padding=10)
        phase1_results_frame.columnconfigure(0, weight=1)
        phase1_results_frame.rowconfigure(0, weight=1)
        phase1_columns = ("index", "ip", "port", "latency", "tls", "note")
        self.phase1_results = ttk.Treeview(
            phase1_results_frame,
            columns=phase1_columns,
            show="headings",
            selectmode="extended",
        )
        phase1_headings = {
            "index": ("#", 45),
            "ip": ("IP address", 165),
            "port": ("Port", 65),
            "latency": ("Best latency", 110),
            "tls": ("TLS", 80),
            "note": ("Details", 520),
        }
        for column, (label, width) in phase1_headings.items():
            self.phase1_results.heading(
                column,
                text=label,
                command=lambda key=column: self.sort_tree(self.phase1_results, key, "phase1"),
            )
            self.phase1_results.column(column, width=width, anchor="w", stretch=column == "note")
        phase1_scrollbar = ttk.Scrollbar(phase1_results_frame, orient="vertical", command=self.phase1_results.yview)
        self.phase1_results.configure(yscrollcommand=phase1_scrollbar.set)
        self.phase1_results.grid(row=0, column=0, sticky="nsew")
        phase1_scrollbar.grid(row=0, column=1, sticky="ns")
        phase1_buttons = ttk.Frame(phase1_results_frame)
        phase1_buttons.grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Button(phase1_buttons, text="Copy Selected IPs", command=self.copy_selected_phase1).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(phase1_buttons, text="Copy All Clean IPs", command=self.copy_all_phase1).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(phase1_buttons, text="Copy Selected Configs", command=lambda: self.copy_configs("phase1", selected_only=True)).grid(row=0, column=2, padx=(0, 8))
        ttk.Button(phase1_buttons, text="Copy All Configs", command=lambda: self.copy_configs("phase1", selected_only=False)).grid(row=0, column=3)

        results_frame = ttk.LabelFrame(results_pane, text="Validated candidates", padding=10)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        columns = ("index", "ip", "port", "status", "latency", "download", "upload", "details")
        self.results = ttk.Treeview(
            results_frame,
            columns=columns,
            show="headings",
            selectmode="extended",
        )
        headings = {
            "index": ("#", 45),
            "ip": ("IP address", 155),
            "port": ("Port", 65),
            "status": ("Validated", 80),
            "latency": ("Latency", 90),
            "download": ("Download", 105),
            "upload": ("Upload", 105),
            "details": ("Details", 480),
        }
        for column, (label, width) in headings.items():
            self.results.heading(
                column,
                text=label,
                command=lambda key=column: self.sort_tree(self.results, key, "stage2"),
            )
            self.results.column(column, width=width, anchor="w", stretch=column == "details")
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results.yview)
        self.results.configure(yscrollcommand=scrollbar.set)
        self.results.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        stage2_buttons = ttk.Frame(results_frame)
        stage2_buttons.grid(row=1, column=0, sticky="w", pady=(8, 0))
        self._styled_button(
            stage2_buttons, "Select Top 20 Best", command=self.select_top_stage2, bootstyle="primary"
        ).grid(row=0, column=0, padx=(0, 8))
        self.rerun_stage2_button = self._styled_button(
            stage2_buttons, "Re-run Stage 2", command=self.rerun_stage2, bootstyle="info"
        )
        self.rerun_stage2_button.grid(row=0, column=1, padx=(0, 8))
        ttk.Button(stage2_buttons, text="Copy Selected IPs", command=self.copy_selected_stage2).grid(row=0, column=2, padx=(0, 8))
        ttk.Button(stage2_buttons, text="Copy All Validated IPs", command=self.copy_all_stage2).grid(row=0, column=3, padx=(0, 8))
        ttk.Button(stage2_buttons, text="Copy Selected Configs", command=lambda: self.copy_configs("stage2", selected_only=True)).grid(row=0, column=4, padx=(0, 8))
        ttk.Button(stage2_buttons, text="Copy All Configs", command=lambda: self.copy_configs("stage2", selected_only=False)).grid(row=0, column=5)

        self._configure_tree_stripes()
        results_pane.add(phase1_results_frame, weight=1)
        results_pane.add(results_frame, weight=1)

        bottom = ttk.Frame(self, padding=(18, 0, 18, 14))
        bottom.grid(row=4, column=0, sticky="ew")
        bottom.columnconfigure(6, weight=1)
        self.run_button = self._styled_button(
            bottom, "Start Scan", command=self.start_scan, bootstyle="success"
        )
        self.run_button.grid(row=0, column=0, padx=(0, 7))
        self.stop_stage1_button = self._styled_button(
            bottom,
            "Stop Stage 1",
            command=lambda: self.stop_stage("stage1"),
            bootstyle="warning",
            state="disabled",
        )
        self.stop_stage1_button.grid(row=0, column=1, padx=(0, 7))
        self.stop_stage2_button = self._styled_button(
            bottom,
            "Stop Stage 2",
            command=lambda: self.stop_stage("stage2"),
            bootstyle="danger",
            state="disabled",
        )
        self.stop_stage2_button.grid(row=0, column=2, padx=(0, 7))
        self.stop_all_button = self._styled_button(
            bottom,
            "Stop Both",
            command=self.stop_both,
            bootstyle="danger-outline",
            state="disabled",
        )
        self.stop_all_button.grid(row=0, column=3, padx=(0, 7))
        self._styled_button(
            bottom, "Open Results Folder", command=self.open_output_folder, bootstyle="secondary-outline"
        ).grid(row=0, column=4)
        self._styled_button(
            bottom, "Reset Results", command=self.reset_results, bootstyle="danger-outline"
        ).grid(row=0, column=5, padx=(7, 0))
        ttk.Label(bottom, textvariable=self.status_text, style="Muted.TLabel").grid(row=0, column=6, sticky="e")

        log_frame = ttk.LabelFrame(self, text="Live scanner log", padding=8)
        log_frame.grid(row=5, column=0, sticky="ew", padx=18, pady=(0, 18))
        log_frame.columnconfigure(0, weight=1)
        self.log = tk.Text(log_frame, height=8, wrap="word", state="disabled", font=("Cascadia Mono", 9))
        self.log.grid(row=0, column=0, sticky="ew")

    def _add_grid_fields(
        self,
        parent: ttk.LabelFrame,
        fields: list[tuple[str, tk.StringVar]],
        start_row: int = 0,
    ) -> None:
        parent.columnconfigure(1, weight=1)
        for index, (label, variable) in enumerate(fields, start=start_row):
            ttk.Label(parent, text=label).grid(row=index, column=0, sticky="w", padx=(0, 10), pady=3)
            ttk.Entry(parent, textvariable=variable).grid(row=index, column=1, sticky="ew", pady=3)

    def open_advanced_settings(self) -> None:
        window = tk.Toplevel(self)
        window.title("MehrScanner Advanced Settings")
        window.transient(self)
        window.grab_set()
        window.resizable(True, True)
        window.columnconfigure(0, weight=1)
        tabs = ttk.Notebook(window)
        tabs.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        window.rowconfigure(0, weight=1)

        scan_tab = ttk.Frame(tabs, padding=12)
        safety_tab = ttk.Frame(tabs, padding=12)
        xray_tab = ttk.Frame(tabs, padding=12)
        tabs.add(scan_tab, text="Scan")
        tabs.add(safety_tab, text="Safety and Output")
        tabs.add(xray_tab, text="Xray")
        self._add_grid_fields(
            scan_tab,
            [
                ("Ports (blank = config port)", self.ports),
                ("Candidate file path", self.candidates_path),
                ("Specific IPs/CIDRs (comma-separated)", self.specific_targets),
                ("Random seed", self.seed),
                ("Neighbor IP limit", self.neighbor_limit),
                ("Delay seconds", self.delay),
                ("Random jitter seconds", self.jitter),
                ("Minimum score", self.min_score),
                ("Progress every endpoints", self.progress_every),
                ("Print top results", self.top_results),
                ("Generated config count", self.config_count),
                ("Generated config remark", self.config_remark),
            ],
        )
        ttk.Checkbutton(scan_tab, text="Skip WebSocket check", variable=self.skip_websocket).grid(
            row=12, column=0, columnspan=2, sticky="w", pady=(8, 0)
        )
        ttk.Checkbutton(
            scan_tab,
            text="Use system proxy (V2rayN) for control traffic. UNCHECKED = use pure direct internet",
            variable=self.use_system_proxy,
        ).grid(row=13, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(
            scan_tab,
            text="Refuse to scan if TUN/VPN routing is active (recommended)",
            variable=self.check_tun,
        ).grid(row=17, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(scan_tab, text="Keep scanning until stopped", variable=self.continuous).grid(
            row=14, column=0, columnspan=2, sticky="w", pady=3
        )
        ttk.Checkbutton(scan_tab, text="Reuse clean IPs from the last run", variable=self.reuse_clean).grid(
            row=15, column=0, columnspan=2, sticky="w", pady=3
        )
        ttk.Checkbutton(scan_tab, text="Show failed checks in the live log", variable=self.show_failures).grid(
            row=16, column=0, columnspan=2, sticky="w", pady=3
        )

        self._add_grid_fields(
            safety_tab,
            [
                ("Output folder", self.output_dir),
                ("Blocked egress IPs", self.blocked_egress_ips),
                ("Expected public egress IP", self.expected_egress_ip),
            ],
        )
        ttk.Checkbutton(safety_tab, text="Slow protective defaults", variable=self.safe_mode).grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(8, 0)
        )

        self._add_grid_fields(xray_tab, [("Path to xray.exe (blank = automatic)", self.xray_path)])
        ttk.Checkbutton(xray_tab, text="Allow automatic Xray download", variable=self.auto_install_xray).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(8, 0)
        )
        ttk.Button(xray_tab, text="Update Xray Core", command=self.update_xray_core).grid(
            row=2, column=0, sticky="w", pady=(12, 0)
        )
        ttk.Button(window, text="Close", command=window.destroy).grid(row=1, column=0, sticky="e", padx=12, pady=(0, 12))

    @staticmethod
    def _load_settings() -> dict[str, str]:
        if not SETTINGS_PATH.exists():
            return {}
        try:
            data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save_settings(self) -> None:
        data = {
            "last_config": self.config_text.get().strip(),
            "theme": self._validated_theme(),
        }
        try:
            SETTINGS_PATH.write_text(json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _styled_button(
        self,
        parent: ttk.Frame,
        text: str,
        command: object | None = None,
        bootstyle: str | None = None,
        **kwargs: object,
    ) -> ttk.Button:
        if command is not None:
            kwargs["command"] = command
        if HAS_BOOTSTRAP and bootstyle:
            kwargs["bootstyle"] = bootstyle
        return ttk.Button(parent, text=text, **kwargs)

    def _validated_theme(self) -> str:
        theme = self.theme_name.get()
        return theme if theme in THEMES else THEMES[0]

    def _theme_is_dark(self) -> bool:
        return self._validated_theme() in DARK_THEMES

    def _apply_muted_color(self) -> None:
        self.app_style.configure(
            "Muted.TLabel",
            foreground="#8b96a5" if self._theme_is_dark() else "#4b5563",
        )

    def _on_theme_selected(self, _event: object = None) -> None:
        if not HAS_BOOTSTRAP:
            return
        self.app_style.theme_use(self._validated_theme())
        self._apply_muted_color()
        self._configure_tree_stripes()
        self._save_settings()

    def _configure_tree_stripes(self) -> None:
        if not HAS_BOOTSTRAP:
            return
        alt = self.app_style.colors.get("light") or self.app_style.colors.get("bg") or "#f0f0f0"
        self.phase1_results.tag_configure("oddrow", background=alt)
        self.results.tag_configure("oddrow", background=alt)

    @staticmethod
    def _today_stamp() -> str:
        return date.today().isoformat()

    def _default_remark_for_config(self, config: str) -> str:
        transport = "ws"
        try:
            profile = scanner.parse_vless_url(config)
            transport = (profile.transport or "ws").strip().lower()
        except Exception:
            pass
        label = "xhttp" if transport == "xhttp" else "ws"
        return f"{label}-{self._today_stamp()}"

    def _apply_default_remark(self) -> None:
        current = self.config_remark.get().strip()
        default_remark = self._default_remark_for_config(self.config_text.get().strip())
        if current and current != self._last_auto_remark:
            return
        self.config_remark.set(default_remark)
        self._last_auto_remark = default_remark

    def _on_config_changed(self, *_args: object) -> None:
        self._save_settings()
        self._apply_default_remark()

    def start_scan(self) -> None:
        if self.process is not None:
            return
        config = self.config_text.get().strip()
        if not config.startswith("vless://"):
            messagebox.showerror("Missing configuration", "Paste a complete vless:// configuration first.")
            return
        self.active_output_dir = self._new_scan_output_dir()
        self.control_dir = self.active_output_dir / ".mehrdadscaner-control"
        self._clear_control_flags()
        try:
            args = self._build_command(config)
        except ValueError as exc:
            messagebox.showerror("Invalid setting", str(exc))
            return
        self._launch_scan(args, f"Scanning into {self.active_output_dir.name}...")

    def start_target_test(self) -> None:
        if not self.specific_targets.get().strip():
            messagebox.showinfo(
                "Target required",
                "Enter one IPv4 address or CIDR, or several separated by commas.",
            )
            return
        self.start_scan()

    def update_xray_core(self) -> None:
        """Download the latest official Xray core without freezing the GUI."""
        def worker() -> None:
            try:
                path = scanner.install_xray(PROJECT_DIR, force=True)
            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("Xray update failed", str(exc)))
                return
            self.after(0, lambda: messagebox.showinfo("Xray updated", f"Xray core is ready:\n{path}"))

        threading.Thread(target=worker, daemon=True).start()

    def rescan_selected_scan(self) -> None:
        if self.process is not None:
            return
        config = self.config_text.get().strip()
        if not config.startswith("vless://"):
            messagebox.showerror("Missing configuration", "Paste a complete vless:// configuration first.")
            return
        selected_name = self.selected_scan.get().strip()
        if not selected_name:
            messagebox.showinfo("No scan selected", "Choose a previous scan to rescan.")
            return
        source_dir = SCANS_DIR / selected_name
        ips = self._scan_ips_from_directory(source_dir)
        if not ips:
            messagebox.showinfo("No IPs found", "That scan does not contain any saved IPs to rescan.")
            return
        self.active_output_dir = self._new_scan_output_dir()
        self.control_dir = self.active_output_dir / ".mehrdadscaner-control"
        self._clear_control_flags()
        candidates_path = self.active_output_dir / "rescan_candidates.txt"
        candidates_path.write_text("\n".join(ips) + "\n", encoding="utf-8")
        try:
            args = self._build_rescan_command(config, candidates_path, len(ips))
        except ValueError as exc:
            messagebox.showerror("Invalid setting", str(exc))
            return
        self._launch_scan(
            args,
            f"Rescanning {len(ips)} IPs from {selected_name} into {self.active_output_dir.name}...",
        )

    def _launch_scan(self, args: list[str], status: str) -> None:
        self._clear_log()
        self._append_log("Starting scanner...\n")
        self._refresh_scan_history(select_path=self.active_output_dir)
        self.status_text.set(status)
        self.run_button.configure(state="disabled")
        # Keep treeview selection enabled so user can select IPs during scanning
        self.stop_stage1_button.configure(state="normal")
        self.stop_stage2_button.configure(state="normal" if self.run_stage2.get() else "disabled")
        self.stop_all_button.configure(state="normal")
        self._stage1_stopped = False  # Track Stage 1 completion
        python_executable = self._scanner_python()
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        self.process = subprocess.Popen(
            args,
            cwd=PROJECT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=HIDDEN_PROCESS_FLAGS | NEW_PROCESS_GROUP_FLAG,
            executable=str(python_executable),
            env=env,
        )
        threading.Thread(target=self._read_process_output, daemon=True).start()

    def _build_command(self, config: str) -> list[str]:
        def positive_int(value: str, label: str, allow_zero: bool = False) -> int:
            try:
                number = int(value)
            except ValueError as exc:
                raise ValueError(f"{label} must be a whole number.") from exc
            if number < 0 or (number == 0 and not allow_zero):
                raise ValueError(f"{label} must be {'zero or positive' if allow_zero else 'greater than zero'}.")
            return number

        def positive_float(value: str, label: str) -> float:
            try:
                number = float(value)
            except ValueError as exc:
                raise ValueError(f"{label} must be a number.") from exc
            if number <= 0:
                raise ValueError(f"{label} must be greater than zero.")
            return number

        def positive_float_or_zero(value: str, label: str) -> float:
            try:
                number = float(value)
            except ValueError as exc:
                raise ValueError(f"{label} must be a number.") from exc
            if number < 0:
                raise ValueError(f"{label} must be zero or positive.")
            return number

        def integer_in_range(value: str, label: str, minimum: int, maximum: int) -> int:
            number = positive_int(value, label)
            if number < minimum or number > maximum:
                raise ValueError(f"{label} must be between {minimum} and {maximum}.")
            return number

        specific_targets = parse_specific_targets(self.specific_targets.get())
        if specific_targets and self.candidates_path.get().strip():
            raise ValueError("Use either Specific IPs/CIDRs or Candidate file path, not both.")
        neighbor_radius = "0" if specific_targets else str(
            positive_int(self.neighbor_radius.get(), "Neighbor radius", allow_zero=True)
        )
        command = [
            str(self._scanner_python()),
            "-u",
            str(SCANNER_PATH),
            "--config", config,
            "--concurrency", str(integer_in_range(self.concurrency.get(), "Parallel checks", 1, 256)),
            "--limit", str(positive_int(self.candidate_limit.get(), "Candidates per batch")),
            "--stop-after-hits", str(positive_int(self.stop_after_hits.get(), "Stop after clean hits")),
            "--timeout", str(positive_float(self.timeout.get(), "Stage 1 timeout")),
            "--neighbor-radius", neighbor_radius,
            "--neighbor-limit", str(positive_int(self.neighbor_limit.get(), "Neighbor IP limit")),
            "--seed", str(positive_int(self.seed.get(), "Random seed", allow_zero=True)),
            "--delay", str(positive_float_or_zero(self.delay.get(), "Delay seconds")),
            "--jitter", str(positive_float_or_zero(self.jitter.get(), "Random jitter seconds")),
            "--min-score", str(integer_in_range(self.min_score.get(), "Minimum score", 1, 3)),
            "--phase1-latency-ms", str(positive_int(self.phase1_latency.get(), "Max latency for clean (ms)", allow_zero=True)),
            "--progress-every", str(positive_int(self.progress_every.get(), "Progress interval")),
            "--top", str(positive_int(self.top_results.get(), "Top results")),
            "--config-count", str(positive_int(self.config_count.get(), "Generated config count")),
            "--out", str(self.active_output_dir),
            "--control-dir", str(self.control_dir),
        ]
        if self.ports.get().strip():
            command.extend(["--ports", self.ports.get().strip()])
        if specific_targets:
            specific_path = self.active_output_dir / "specific_targets.txt"
            specific_path.write_text("\n".join(specific_targets) + "\n", encoding="utf-8")
            command.extend(["--candidates", str(specific_path), "--no-reuse-clean-candidates"])
        elif self.candidates_path.get().strip():
            command.extend(["--candidates", self.candidates_path.get().strip()])
        if self.config_remark.get().strip():
            command.extend(["--config-remark", self.config_remark.get().strip()])
        if self.direct_egress.get():
            command.extend(["--require-direct-egress", "--blocked-egress-ips", self.blocked_egress_ips.get().strip()])
            if self.expected_egress_ip.get().strip():
                command.extend(["--expected-egress-ip", self.expected_egress_ip.get().strip()])
        if self.skip_websocket.get():
            command.append("--no-ws")
        if not self.reuse_clean.get():
            command.append("--no-reuse-clean-candidates")
        if self.continuous.get():
            command.append("--continuous")
        if self.local_fast.get():
            command.append("--local-fast")
        if self.safe_mode.get():
            command.append("--safe")
        if self.show_failures.get():
            command.append("--show-failures")
        if self.use_system_proxy.get():
            command.append("--use-system-proxy")
        if self.check_tun.get():
            command.append("--check-tun")
        if self.run_stage2.get():
            download_bytes = int(positive_float_or_zero(self.download_kb.get(), "Download KB") * 1024)
            upload_bytes = int(positive_float_or_zero(self.upload_kb.get(), "Upload KB") * 1024)
            command.extend(
                [
                    "--xray",
                    *( ["--xray-during-scan"] if self.stage2_during_scan.get() else [] ),
                    "--stage2-count", str(positive_int(self.stage2_count.get(), "IPs to validate")),
                    "--xray-concurrency", str(integer_in_range(self.xray_concurrency.get(), "Parallel validations", 1, 7)),
                    "--xray-timeout", str(positive_float(self.xray_timeout.get(), "Stage 2 timeout")),
                    "--xray-test-url", self.test_url.get().strip(),
                    "--download-url", self.download_url.get().strip(),
                    "--download-bytes", str(download_bytes),
                    "--upload-url", self.upload_url.get().strip(),
                    "--upload-bytes", str(upload_bytes),
                ]
            )
            if self.xray_path.get().strip():
                command.extend(["--xray-path", self.xray_path.get().strip()])
            if not self.auto_install_xray.get():
                command.append("--no-install-xray")
        return command

    def _build_rescan_command(self, config: str, candidates_path: Path, candidate_count: int) -> list[str]:
        command = self._build_command(config)
        filtered: list[str] = []
        skip_next = False
        replace_next: str | None = None
        remove_value_options = {
            "--candidates",
            "--limit",
            "--stop-after-hits",
            "--neighbor-radius",
            "--neighbor-limit",
            "--stage2-count",
        }
        for item in command:
            if skip_next:
                skip_next = False
                continue
            if replace_next is not None:
                filtered.extend([replace_next, item])
                replace_next = None
                continue
            if item in remove_value_options:
                skip_next = True
                continue
            if item == "--control-dir":
                replace_next = item
                continue
            if item == "--out":
                replace_next = item
                continue
            if item == "--xray-during-scan":
                continue
            filtered.append(item)
        command = filtered
        command.extend(["--candidates", str(candidates_path),
                    "--limit", str(candidate_count),
                    "--stop-after-hits", str(candidate_count),
                    "--neighbor-radius", "0",
                    "--neighbor-limit", str(candidate_count),
                    "--no-reuse-clean-candidates",
                    "--skip-stage1",
                    "--xray",
                ])
        return command

    def _scan_ips_from_directory(self, directory: Path) -> list[str]:
        ips: list[str] = []
        seen: set[str] = set()
        for filename in ("xray_validated.csv", "hits.csv", "results.csv", "clean_candidates.txt"):
            path = directory / filename
            if not path.exists():
                continue
            try:
                if path.suffix == ".csv":
                    with path.open("r", encoding="utf-8", newline="") as handle:
                        for row in csv.DictReader(handle):
                            ip = (row.get("ip") or "").strip()
                            if ip and ip not in seen:
                                seen.add(ip)
                                ips.append(ip)
                else:
                    for line in path.read_text(encoding="utf-8").splitlines():
                        ip = line.strip()
                        if ip and ip not in seen:
                            seen.add(ip)
                            ips.append(ip)
            except OSError:
                continue
        return ips

    @staticmethod
    def _scanner_python() -> Path:
        current = Path(sys.executable)
        if current.name.lower() == "pythonw.exe":
            candidate = current.with_name("python.exe")
            if candidate.exists():
                return candidate
        return current

    def rerun_stage2(self) -> None:
        """Re-run Stage 2 validation using the current clean IPs and settings."""
        try:
            if self.process is not None:
                messagebox.showinfo("Scan running", "Stop the current scan first.")
                return
            ips = self._scan_ips_from_directory(self.active_output_dir)
            if not ips:
                # Fallback: use the IPs already shown in the Phase 1 table
                ips = [row.get("ip", "") for row in self.phase1_rows if row.get("ip")]
            if not ips:
                messagebox.showinfo("No IPs", "No clean IPs found in the current scan folder.")
                return
            self._clear_control_flags()
            self.active_output_dir.mkdir(parents=True, exist_ok=True)
            # Clear previous stage 2 results
            for fname in ("xray_validated.csv", "xray_validated.json", "xray_validated_ips.txt", "vless_xray_validated_configs.txt"):
                path = self.active_output_dir / fname
                if path.exists():
                    path.unlink()
            self.stage2_rows = []
            self._render_stage2_rows(self.stage2_rows)
            candidate_path = self.active_output_dir / "rerun_candidates.txt"
            candidate_path.write_text("\n".join(ips) + "\n", encoding="utf-8")
            command = self._build_rescan_command(self.config_text.get().strip(), candidate_path, len(ips))
            self._append_log(f"Re-run Stage 2 command: {' '.join(command)}\n")
            self._start_process(command)
            self.rerun_stage2_button.configure(state="disabled")
            self.status_text.set(f"Re-running Stage 2 on {len(ips)} IPs...")
        except Exception as exc:
            import traceback
            traceback.print_exc()
            self._append_log(f"Re-run Stage 2 error: {exc}\n")
            messagebox.showerror("Error", f"Failed to start Stage 2 re-run:\n{exc}")

    def _start_process(self, command: list[str]) -> None:
        self.process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=HIDDEN_PROCESS_FLAGS,
        )
        self.run_button.configure(state="disabled")
        self.stop_stage1_button.configure(state="disabled")
        self.stop_stage2_button.configure(state="normal")
        self.stop_all_button.configure(state="normal")
        self.rerun_stage2_button.configure(state="disabled")
        threading.Thread(target=self._read_process_output, daemon=True).start()
        self.status_text.set("Scanner started...")

    def _read_process_output(self) -> None:
        assert self.process is not None
        process = self.process
        if process.stdout:
            for line in process.stdout:
                self.log_queue.put(line)
        code = process.wait()
        self.log_queue.put(f"\nScanner finished with exit code {code}.\n")
        self.log_queue.put(None)

    def _drain_log_queue(self) -> None:
        try:
            while True:
                line = self.log_queue.get_nowait()
                if line is None:
                    self.process = None
                    self.run_button.configure(state="normal")
                    self.stop_stage1_button.configure(state="disabled")
                    self.stop_stage2_button.configure(state="disabled")
                    self.stop_all_button.configure(state="disabled")
                    self.rerun_stage2_button.configure(state="normal")
                    self._refresh_scan_history(select_path=self.active_output_dir)
                    self.status_text.set(f"Finished. Results loaded from {self.active_output_dir.name}.")
                    self._load_results()
                else:
                    self._append_log(line)
                    # Detect Stage 1 completion from stdout
                    if not getattr(self, "_stage1_stopped", False):
                        if ("Stage 1 stop requested" in line or 
                            "Reached requested hit limit" in line or
                            ("next=0" in line and "round" in line and "scanned=" in line)):
                            self._stage1_stopped = True
                            self.stop_stage1_button.configure(state="disabled")
                            self.status_text.set("Stage 1 complete. Stage 2 running...")
        except queue.Empty:
            pass
        if self.process is not None:
            self._load_results()
        self.after(1000, self._drain_log_queue)

    def stop_stage(self, stage: str) -> None:
        if self.process is None:
            return
        self.control_dir.mkdir(parents=True, exist_ok=True)
        (self.control_dir / f"stop_{stage}.flag").touch()
        if stage == "stage1":
            self.stop_stage1_button.configure(state="disabled")
            self.status_text.set("Stopping Stage 1. Keeping clean IPs found so far.")
        else:
            self.stop_stage2_button.configure(state="disabled")
            self.status_text.set("Stopping Stage 2. Keeping completed validations.")

    def stop_both(self) -> None:
        self.stop_stage("stage1")
        self.stop_stage("stage2")
        self.stop_all_button.configure(state="disabled")

    def close_app(self) -> None:
        self._save_settings()
        if self.process is not None:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    creationflags=HIDDEN_PROCESS_FLAGS,
                    timeout=5,
                )
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self.process.kill()
                except OSError:
                    pass
            self.process = None
        self.destroy()

    def _clear_control_flags(self) -> None:
        self.control_dir.mkdir(parents=True, exist_ok=True)
        for name in ("stop_stage1.flag", "stop_stage2.flag"):
            path = self.control_dir / name
            if path.exists():
                path.unlink()

    def _new_scan_output_dir(self) -> Path:
        SCANS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = date.today().isoformat()
        time_part = __import__("time").strftime("%H%M%S")
        base = SCANS_DIR / f"scan-{stamp}-{time_part}"
        candidate = base
        index = 2
        while candidate.exists():
            candidate = SCANS_DIR / f"{base.name}-{index}"
            index += 1
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate

    def _refresh_scan_history(self, select_path: Path | None = None) -> None:
        SCANS_DIR.mkdir(parents=True, exist_ok=True)
        scans = sorted(
            [path for path in SCANS_DIR.iterdir() if path.is_dir()],
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        self.scan_history = scans
        names = [path.name for path in scans]
        self.scan_selector["values"] = names
        if select_path is not None:
            self.active_output_dir = select_path
            self.selected_scan.set(select_path.name)
            return
        if self.active_output_dir in scans:
            self.selected_scan.set(self.active_output_dir.name)
        elif names:
            self.active_output_dir = scans[0]
            self.selected_scan.set(names[0])

    def _on_scan_selected(self, *_args: object) -> None:
        if self.process is not None:
            return
        selected_name = self.selected_scan.get().strip()
        if not selected_name:
            return
        path = SCANS_DIR / selected_name
        if not path.exists():
            return
        self.active_output_dir = path
        self.control_dir = self.active_output_dir / ".mehrdadscaner-control"
        self._load_results()
        self.status_text.set(f"Loaded previous scan: {selected_name}")

    def _load_results(self) -> None:
        self._load_phase1_results()
        self._load_stage2_results()

    def _load_phase1_results(self) -> None:
        # Preserve current selection by IP
        selected_ips = {self.phase1_results.item(item, "values")[1] for item in self.phase1_results.selection()}
        
        self.phase1_rows = []
        for row in self.phase1_results.get_children():
            self.phase1_results.delete(row)
        path = self.active_output_dir / "hits.csv"
        fallback = self.active_output_dir / "results.csv"
        if not path.exists() and fallback.exists():
            path = fallback
        if not path.exists():
            return
        try:
            min_score_value = self._int_or_zero(self.min_score.get()) or 3
            best_by_ip: dict[str, dict[str, str]] = {}
            with path.open("r", encoding="utf-8", newline="") as handle:
                for row in csv.DictReader(handle):
                    if self._int_or_zero(row.get("score", "0")) < min_score_value:
                        continue
                    ip = row.get("ip", "")
                    if not ip:
                        continue
                    current = best_by_ip.get(ip)
                    if current is None or self._phase1_latency(row) < self._phase1_latency(current):
                        best_by_ip[ip] = row
            self.phase1_rows = sorted(
                best_by_ip.values(),
                key=self._phase1_latency,
            )
            self._render_phase1_rows(self.phase1_rows)
            
            # Restore selection
            if selected_ips:
                for item in self.phase1_results.get_children():
                    if self.phase1_results.item(item, "values")[1] in selected_ips:
                        self.phase1_results.selection_add(item)
        except OSError as exc:
            self._append_log(f"Could not load phase 1 results: {exc}\n")

    def _load_stage2_results(self) -> None:
        # Preserve current selection by IP
        selected_ips = {self.results.item(item, "values")[1] for item in self.results.selection()}
        
        self.stage2_rows = []
        for row in self.results.get_children():
            self.results.delete(row)
        path = self.active_output_dir / "xray_validated.csv"
        if not path.exists():
            return
        try:
            with path.open("r", encoding="utf-8", newline="") as handle:
                for row in csv.DictReader(handle):
                    self.stage2_rows.append(row)
            self._render_stage2_rows(self.stage2_rows)
            
            # Restore selection
            if selected_ips:
                for item in self.results.get_children():
                    if self.results.item(item, "values")[1] in selected_ips:
                        self.results.selection_add(item)
        except OSError as exc:
            self._append_log(f"Could not load results: {exc}\n")

    def _render_phase1_rows(self, rows: list[dict[str, str]]) -> None:
        for row in self.phase1_results.get_children():
            self.phase1_results.delete(row)
        for index, row in enumerate(rows, start=1):
            self.phase1_results.insert(
                "",
                "end",
                tags=("oddrow",) if index % 2 == 0 else (),
                values=(
                    index,
                    row.get("ip", ""),
                    row.get("port", ""),
                    self._format_latency(row.get("ws_ms") or row.get("tls_ms") or row.get("tcp_ms", "")),
                    "Yes" if row.get("tls_ok") == "True" else "No",
                    row.get("error", ""),
                ),
            )

    def _render_stage2_rows(self, rows: list[dict[str, str]]) -> None:
        for row in self.results.get_children():
            self.results.delete(row)
        self._stage2_iids = []
        for index, row in enumerate(rows, start=1):
            iid = f"stage2-{index}"
            self._stage2_iids.append(iid)
            self.results.insert(
                "",
                "end",
                iid=iid,
                tags=("oddrow",) if index % 2 == 0 else (),
                values=(
                    index,
                    row.get("ip", ""),
                    row.get("port", ""),
                    "Yes" if row.get("ok") == "True" else "No",
                    self._format_latency(row.get("latency_ms", "")),
                    self._format_speed(row.get("download_mbps", "")),
                    self._format_speed(row.get("upload_mbps", "")),
                    self._format_stage2_details(row.get("error", "")),
                ),
            )

    def copy_selected_phase1(self) -> None:
        items = self.phase1_results.selection()
        if not items:
            messagebox.showinfo("No selection", "Select one or more clean IPs first.")
            return
        ips = [self.phase1_results.item(item, "values")[1] for item in items]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.status_text.set(f"Copied {len(ips)} Phase 1 IPs.")

    def copy_all_phase1(self) -> None:
        if not self.phase1_rows:
            messagebox.showinfo("No results", "There are no clean IPs to copy yet.")
            return
        ips = [row.get("ip", "") for row in self.phase1_rows if row.get("ip")]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.status_text.set(f"Copied all {len(ips)} clean IPs.")

    def copy_selected_stage2(self) -> None:
        items = self.results.selection()
        if not items:
            messagebox.showinfo("No selection", "Select one or more validated IPs first.")
            return
        ips = [self.results.item(item, "values")[1] for item in items]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.status_text.set(f"Copied {len(ips)} validated IPs.")

    def copy_all_stage2(self) -> None:
        if not self.stage2_rows:
            messagebox.showinfo("No results", "There are no validated IPs to copy yet.")
            return
        ips = [row.get("ip", "") for row in self.stage2_rows if row.get("ip")]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.status_text.set(f"Copied all {len(ips)} validated IPs.")

    def copy_configs(self, section: str, selected_only: bool) -> None:
        config = self.config_text.get().strip()
        try:
            profile = scanner.parse_vless_url(config)
        except Exception as exc:
            messagebox.showerror("Invalid configuration", f"Cannot generate configs:\n{exc}")
            return
        if section == "phase1":
            rows = self._selected_phase1_rows() if selected_only else self.phase1_rows
        else:
            rows = self._selected_stage2_rows() if selected_only else self.stage2_rows
        if not rows:
            messagebox.showinfo("No results", "There are no rows to generate configs from.")
            return
        remark = self.config_remark.get().strip() or None
        configs = [
            scanner.build_vless_url(
                profile,
                row.get("ip", ""),
                int(row.get("port", profile.port) or profile.port),
                remark=remark,
            )
            for row in rows
            if row.get("ip")
        ]
        self.clipboard_clear()
        self.clipboard_append("\n\n".join(configs))
        self.status_text.set(f"Copied {len(configs)} generated configs.")

    def _selected_phase1_rows(self) -> list[dict[str, str]]:
        selected = {self.phase1_results.item(item, "values")[1] for item in self.phase1_results.selection()}
        return [row for row in self.phase1_rows if row.get("ip") in selected]

    def _selected_stage2_rows(self) -> list[dict[str, str]]:
        selected = {self.results.item(item, "values")[1] for item in self.results.selection()}
        return [row for row in self.stage2_rows if row.get("ip") in selected]

    def select_top_stage2(self) -> None:
        count = self._int_or_zero(self.top_results.get()) or 20
        top_indices = self._top_stage2_indices(count)
        if not top_indices:
            messagebox.showinfo("No results", "There are no validated IPs to rank yet.")
            return
        iids = [self._stage2_iids[i] for i in top_indices if i < len(self._stage2_iids)]
        if not iids:
            return
        self.results.selection_set(*iids)
        self.results.focus(iids[0])
        self.results.see(iids[0])
        self.status_text.set(
            f"Selected top {len(iids)} validated IPs by the scanner's weighted latency/upload/download rank."
        )

    def _top_stage2_indices(self, count: int) -> list[int]:
        # Reuse the same composite ranking the scanner writes to the results
        # files, so "Select Top 20 Best" always matches vless_xray_validated_configs.txt.
        validations: list[scanner.XrayValidationResult] = []
        index_by_key: dict[tuple[str, str], int] = {}
        for index, row in enumerate(self.stage2_rows):
            if row.get("ok") != "True":
                continue
            ip = (row.get("ip") or "").strip()
            if not ip:
                continue
            port = self._int_or_zero(row.get("port", "0"))
            index_by_key[(ip, str(port))] = index
            validations.append(
                scanner.XrayValidationResult(
                    ip=ip,
                    port=port,
                    ok=True,
                    latency_ms=self._optional_float(row.get("latency_ms")),
                    download_mbps=self._optional_float(row.get("download_mbps")),
                    upload_mbps=self._optional_float(row.get("upload_mbps")),
                    download_bytes=self._int_or_zero(row.get("download_bytes", "0")),
                    upload_bytes=self._int_or_zero(row.get("upload_bytes", "0")),
                    error=row.get("error", ""),
                )
            )
        if not validations:
            return []
        ordered = scanner.sort_xray_results(validations)
        indices: list[int] = []
        for validation in ordered[:count]:
            index = index_by_key.get((validation.ip, str(validation.port)))
            if index is not None and index not in indices:
                indices.append(index)
        return indices

    @staticmethod
    def _optional_float(value: str) -> float | None:
        try:
            if value is None or value == "":
                return None
            number = float(value)
            return None if number != number else number
        except (TypeError, ValueError):
            return None

    def sort_tree(self, tree: ttk.Treeview, column: str, section: str) -> None:
        descending = getattr(tree, "_descending", {}).get(column, False)
        rows = self.phase1_rows if section == "phase1" else self.stage2_rows
        rows.sort(key=lambda row: self._sort_value(section, column, row), reverse=not descending)
        if section == "phase1":
            self._render_phase1_rows(rows)
        else:
            self._render_stage2_rows(rows)
        flags = getattr(tree, "_descending", {})
        flags[column] = not descending
        tree._descending = flags

    def _sort_value(self, section: str, column: str, row: dict[str, str]) -> object:
        if section == "phase1":
            if column == "latency":
                return self._phase1_latency(row)
            if column == "index":
                return self._phase1_latency(row)
            if column == "port":
                return self._int_or_zero(row.get("port", "0"))
            return row.get(column if column != "tls" else "tls_ok", "").lower()
        if column == "index":
            return self._float_or_inf(row.get("latency_ms", ""))
        if column == "latency":
            return self._float_or_inf(row.get("latency_ms", ""))
        if column == "download":
            return self._float_or_inf(row.get("download_mbps", ""))
        if column == "upload":
            return self._float_or_inf(row.get("upload_mbps", ""))
        if column == "port":
            return self._int_or_zero(row.get("port", "0"))
        if column == "status":
            return row.get("ok", "").lower()
        if column == "details":
            return self._format_stage2_details(row.get("error", "")).lower()
        return row.get(column, "").lower()

    def reset_results(self) -> None:
        if self.process is not None:
            messagebox.showwarning("Scan running", "Stop the scan before resetting results.")
            return
        output_dir = self.active_output_dir
        confirmed = messagebox.askyesno(
            "Reset scanner results",
            f"Delete the previous scan results in {output_dir.name}?\n\n"
            "This keeps your scanner program and any custom candidate files.",
        )
        if not confirmed:
            return
        output_files = [
            "results.json",
            "results.csv",
            "clean_candidates.txt",
            "vless_top_configs.txt",
            "hits.csv",
            "hits.jsonl",
            "xray_validated_ips.txt",
            "xray_validated.csv",
            "xray_validated.json",
            "vless_xray_validated_configs.txt",
        ]
        deleted = 0
        for name in output_files:
            path = output_dir / name
            if path.exists():
                path.unlink()
                deleted += 1
        self.active_output_dir = output_dir
        self.control_dir = output_dir / ".mehrdadscaner-control"
        self._clear_control_flags()
        self._refresh_scan_history(select_path=output_dir)
        self._load_results()
        self._clear_log()
        self.status_text.set(f"Reset complete. Removed {deleted} scanner result files.")

    def delete_selected_scan(self) -> None:
        if self.process is not None:
            messagebox.showwarning("Scan running", "Stop the scan before deleting a scan folder.")
            return
        selected_name = self.selected_scan.get().strip()
        if not selected_name:
            messagebox.showinfo("No scan selected", "Choose a previous scan first.")
            return
        target = SCANS_DIR / selected_name
        if not target.exists():
            messagebox.showinfo("Missing scan", "That scan folder no longer exists.")
            self._refresh_scan_history()
            return
        confirmed = messagebox.askyesno(
            "Delete scan",
            f"Delete the scan session '{selected_name}'?\n\nThis removes the whole saved scan folder.",
        )
        if not confirmed:
            return
        try:
            shutil.rmtree(target)
        except OSError as exc:
            messagebox.showerror("Delete failed", f"Could not delete scan folder:\n{exc}")
            return
        self.phase1_rows = []
        self.stage2_rows = []
        self._clear_log()
        self._refresh_scan_history()
        if not self.scan_history:
            self.active_output_dir = OUT_DIR
            self.control_dir = OUT_DIR / ".mehrdadscaner-control"
            for row in self.phase1_results.get_children():
                self.phase1_results.delete(row)
            for row in self.results.get_children():
                self.results.delete(row)
            self.selected_scan.set("")
            self.status_text.set(f"Deleted scan {selected_name}. No saved scans remain.")
            return
        self._load_results()
        self.status_text.set(f"Deleted scan {selected_name}.")

    @staticmethod
    def _format_latency(value: str) -> str:
        return f"{value} ms" if value else "-"

    @staticmethod
    def _format_speed(value: str) -> str:
        return f"{value} Mbps" if value else "-"

    @staticmethod
    def _format_stage2_details(value: str) -> str:
        if not value:
            return "-"
        parts = value.split(";")
        pretty: list[str] = []
        for part in parts:
            if part == "upload_URLError":
                pretty.append("upload unavailable")
            elif part == "download_HTTPError":
                pretty.append("download HTTP error")
            elif part == "upload_HTTPError":
                pretty.append("upload HTTP error")
            elif part.startswith("http_"):
                pretty.append(part.replace("http_", "validate "))
            elif part.startswith("download_http_"):
                pretty.append(part.replace("download_http_", "download "))
            elif part.startswith("upload_http_"):
                pretty.append(part.replace("upload_http_", "upload "))
            else:
                pretty.append(part.replace("_", " "))
        return ", ".join(pretty)

    @staticmethod
    def _phase1_latency(row: dict[str, str]) -> float:
        return ScannerApp._float_or_inf(
            row.get("ws_ms") or row.get("tls_ms") or row.get("tcp_ms", "")
        )

    @staticmethod
    def _float_or_inf(value: str) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return float("inf")

    @staticmethod
    def _int_or_zero(value: str) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _append_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _set_treeview_selection_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.phase1_results.configure(selectmode="extended" if enabled else "none")
        self.results.configure(selectmode="extended" if enabled else "none")

    def open_output_folder(self) -> None:
        self.active_output_dir.mkdir(exist_ok=True)
        os.startfile(self.active_output_dir)


if __name__ == "__main__":
    ScannerApp().mainloop()
