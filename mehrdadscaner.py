#!/usr/bin/env python3
"""
MehrScanner - a small Cloudflare candidate IP scanner.

This tool is intentionally simple:
1. Parse a VLESS URL and keep its SNI/Host/path settings.
2. Generate or load candidate Cloudflare IPs.
3. Test each candidate with TCP, TLS, and optional WebSocket upgrade checks.
4. Print and export the fastest candidates.
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import csv
import ipaddress
import json
import base64
import math
import os
import random
import shutil
import socket
import ssl
import statistics
import subprocess
import tempfile
import threading
import time
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable
from urllib.error import HTTPError
from urllib.parse import parse_qs, quote, unquote, urlparse, urlunparse
from urllib.request import ProxyHandler, Request, build_opener, urlopen


CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
# Cloudflare announces additional service/BYOIP prefixes through AS13335.
# The BGP list includes ranges such as 8.6.112.0/24 that are not in the
# smaller shared-proxy list above.
CLOUDFLARE_BGP_IPV4_URL = (
    "https://stat.ripe.net/data/announced-prefixes/data.json"
    "?resource=AS13335&min_peers_seeing=1"
)
XRAY_LATEST_RELEASE_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
DEFAULT_TIMEOUT = 2.5
DEFAULT_CONCURRENCY = 64
DEFAULT_LIMIT = 1000
DEFAULT_SAMPLE_PER_RANGE = 20
DEFAULT_DELAY = 0.0
DEFAULT_JITTER = 0.0
LOCAL_FAST_CONCURRENCY = 128
LOCAL_FAST_LIMIT = 10000
LOCAL_FAST_DELAY = 0.0
LOCAL_FAST_JITTER = 0.0
SAFE_CONCURRENCY = 2
SAFE_LIMIT = 20
SAFE_SAMPLE_PER_RANGE = 1
SAFE_DELAY = 1.0
SAFE_JITTER = 0.5
DEFAULT_TLS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]
DEFAULT_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]
FALLBACK_CLOUDFLARE_IPV4_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]
# Keep machine-specific VPN/server exit addresses out of the public project.
# Supply them at runtime with --blocked-egress-ips when needed.
DEFAULT_BLOCKED_EGRESS_IPS: list[str] = []
EGRESS_IP_URLS_V4 = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://ident.me",
    "https://ipinfo.io/ip",
]
EGRESS_IP_URLS_V6 = [
    "https://api6.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://ident.me",
    "https://ipinfo.io/ip",
]
# Backward compatibility
EGRESS_IP_URLS = EGRESS_IP_URLS_V4
DEFAULT_NEIGHBOR_RADIUS = 0
DEFAULT_NEIGHBOR_LIMIT = 64
DEFAULT_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
DEFAULT_UPLOAD_URL = "https://speed.cloudflare.com/__up"
DEFAULT_TRANSFER_BYTES = 10_000_000
HIDDEN_PROCESS_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Stage 1 re-measurement pass: the top clean hits are probed several more
# times and ranked by their best clean latency, so a single lucky/fast or
# unlucky/slow measurement cannot dominate the final "best IP" ordering.
RECHECK_TOP = 120
RECHECK_REPEATS = 3
RECHECK_CONCURRENCY = 64

# Phase 1 latency threshold (ms). IPs whose best measured latency exceeds this
# are filtered out of the "clean" set. Default 1200ms; set to 0 to disable filter.
PHASE1_LATENCY_MS = 1200

# Composite Stage 2 ranking weights used to order xray-validated candidates.
# Higher weight = more influence. Must sum to 1.0.
RANK_WEIGHT_LATENCY = 0.5
RANK_WEIGHT_DOWNLOAD = 0.3
RANK_WEIGHT_UPLOAD = 0.2
_rank_weights = {
    "latency": RANK_WEIGHT_LATENCY,
    "download": RANK_WEIGHT_DOWNLOAD,
    "upload": RANK_WEIGHT_UPLOAD,
}


def set_rank_weights(latency: float, download: float, upload: float) -> None:
    total = latency + download + upload
    if total <= 0:
        raise ValueError("Ranking weights must sum to a positive number.")
    global _rank_weights
    _rank_weights = {
        "latency": latency / total,
        "download": download / total,
        "upload": upload / total,
    }


# Module-level proxy mode.
# Default: bypass the Windows system proxy so the scanner uses the direct
# internet (pure net) even when a system-wide proxy like V2rayN is active.
_USE_SYSTEM_PROXY = False
_DIRECT_OPENER_CACHE: "callable | None" = None


def set_system_proxy_mode(enabled: bool) -> None:
    """Toggle whether urllib honors the Windows system proxy (V2rayN etc.).

    Default is direct (bypass proxy) so the scanner tests candidates with
    pure internet even while a VPN/proxy is active on the machine.
    """
    global _USE_SYSTEM_PROXY, _DIRECT_OPENER_CACHE
    _USE_SYSTEM_PROXY = enabled
    _DIRECT_OPENER_CACHE = None


def open_url(request: Request, timeout: float):
    """Open a request, optionally bypassing the system proxy."""
    global _DIRECT_OPENER_CACHE
    if _USE_SYSTEM_PROXY:
        return urlopen(request, timeout=timeout)
    if _DIRECT_OPENER_CACHE is None:
        _DIRECT_OPENER_CACHE = build_opener(ProxyHandler({}))
    return _DIRECT_OPENER_CACHE.open(request, timeout=timeout)


@dataclass(frozen=True)
class VlessProfile:
    original_url: str
    uuid: str
    original_address: str
    port: int
    sni: str
    host: str
    path: str
    security: str
    transport: str
    remark: str


@dataclass
class ScanResult:
    ip: str
    port: int
    tcp_ok: bool
    tls_ok: bool
    ws_ok: bool
    http_ok: bool
    tcp_ms: float | None
    tls_ms: float | None
    ws_ms: float | None
    http_ms: float | None
    error: str

    @property
    def score(self) -> int:
        return int(self.tcp_ok) + int(self.tls_ok) + int(self.ws_ok) + int(self.http_ok)

    @property
    def best_ms(self) -> float:
        for value in (self.ws_ms, self.tls_ms, self.http_ms, self.tcp_ms):
            if value is not None:
                return value
        return 999999.0


@dataclass
class XrayValidationResult:
    ip: str
    port: int
    ok: bool
    latency_ms: float | None
    download_mbps: float | None
    upload_mbps: float | None
    download_bytes: int
    upload_bytes: int
    error: str

    @property
    def best_ms(self) -> float:
        return self.latency_ms if self.latency_ms is not None else 999999.0


def parse_vless_url(url: str) -> VlessProfile:
    original_url = url.strip()
    parsed = urlparse(original_url)
    if parsed.scheme.lower() != "vless":
        raise ValueError("The config must start with vless://")
    if not parsed.username or not parsed.hostname:
        raise ValueError("The VLESS URL must include a UUID and server address")

    query = parse_qs(parsed.query)
    sni = first_query_value(query, "sni") or parsed.hostname
    host = first_query_value(query, "host") or sni
    path = unquote(first_query_value(query, "path") or "/")
    transport = first_query_value(query, "type") or ""
    security = first_query_value(query, "security") or ""
    remark = unquote(parsed.fragment or "")

    return VlessProfile(
        original_url=original_url,
        uuid=parsed.username,
        original_address=parsed.hostname,
        port=parsed.port or 443,
        sni=sni,
        host=host,
        path=path if path.startswith("/") else f"/{path}",
        security=security,
        transport=transport,
        remark=remark,
    )


def build_vless_url(
    profile: VlessProfile, ip: str, port: int, remark: str | None = None
) -> str:
    parsed = urlparse(profile.original_url)
    netloc = f"{profile.uuid}@{ip}:{port}"
    fragment = parsed.fragment if remark is None else quote(remark, safe="")
    return urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, fragment)
    )


def profile_query(profile: VlessProfile) -> dict[str, list[str]]:
    return parse_qs(urlparse(profile.original_url).query)


def query_value(profile: VlessProfile, key: str, default: str = "") -> str:
    return first_query_value(profile_query(profile), key) or default


def first_query_value(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    return values[0] if values else None


def fetch_cloudflare_ipv4_ranges() -> tuple[list[ipaddress.IPv4Network], str]:
    headers = {
        "User-Agent": "Mozilla/5.0 MehrScanner/1.0",
        "Accept": "application/json,text/plain,*/*",
    }
    official_ranges: list[ipaddress.IPv4Network] = []
    try:
        request = Request(CLOUDFLARE_IPV4_URL, headers=headers)
        with open_url(request, 10) as response:
            text = response.read().decode("utf-8")
        official_ranges = [
            ipaddress.IPv4Network(item.strip()) for item in text.split() if item.strip()
        ]
    except Exception as exc:
        print(
            f"Warning: could not fetch the official Cloudflare list ({type(exc).__name__})."
        )

    # Use current BGP announcements as the broad candidate source. This is
    # intentionally separate from Cloudflare's smaller shared-proxy list:
    # AS13335 announces additional prefixes used by other Cloudflare services
    # and BYOIP customers.
    try:
        request = Request(CLOUDFLARE_BGP_IPV4_URL, headers=headers)
        with open_url(request, 15) as response:
            payload = json.loads(response.read().decode("utf-8"))
        announced = payload.get("data", {}).get("prefixes", [])
        ranges = sorted(
            {
                ipaddress.IPv4Network(item["prefix"], strict=False)
                for item in announced
                if isinstance(item, dict) and ":" not in str(item.get("prefix", ""))
            },
            key=lambda network: (int(network.network_address), network.prefixlen),
        )
        if ranges:
            return ranges, "current AS13335 BGP announcements (RIPE NCC)"
    except Exception as exc:
        print(
            f"Warning: could not fetch current AS13335 announcements ({type(exc).__name__})."
        )

    if official_ranges:
        return official_ranges, CLOUDFLARE_IPV4_URL

    return [
        ipaddress.IPv4Network(item) for item in FALLBACK_CLOUDFLARE_IPV4_RANGES
    ], "built-in Cloudflare IPv4 fallback"


def detect_public_egress_ip(timeout: float = 6.0, prefer_v4: bool = True) -> str:
    """Detect public egress IP. Tries IPv4 first by default, then IPv6."""
    urls_v4 = EGRESS_IP_URLS_V4
    urls_v6 = EGRESS_IP_URLS_V6
    
    def try_urls(urls: list[str]) -> str | None:
        errors: list[str] = []
        for url in urls:
            request = Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 MehrScanner/1.0",
                    "Accept": "text/plain,*/*",
                },
            )
            try:
                with open_url(request, timeout) as response:
                    text = response.read().decode("utf-8", errors="replace").strip()
                ip = text.split()[0]
                ipaddress.ip_address(ip)
                return ip
            except Exception as exc:
                errors.append(f"{url}: {type(exc).__name__}")
        return None

    if prefer_v4:
        ip = try_urls(urls_v4)
        if ip:
            return ip
        # Fallback to IPv6
        ip = try_urls(urls_v6)
        if ip:
            return ip
    else:
        ip = try_urls(urls_v6)
        if ip:
            return ip
        ip = try_urls(urls_v4)
        if ip:
            return ip
    
    all_errors = []
    for url in urls_v4 + urls_v6:
        all_errors.append(f"{url}: failed")
    raise RuntimeError("Could not detect public egress IP: " + "; ".join(all_errors))


def detect_tun_active() -> bool:
    """Detect if a TUN/routing tunnel adapter (V2rayN TUN, sing-box, Wintun,
    Tailscale, etc.) is active on this machine.

    This catches network-level routing that a system proxy bypass cannot
    avoid. Only relevant on Windows.
    """
    if os.name != "nt":
        return False
    keywords = ("wintun", "tun2socks", "tun", "utun", "sing-box", "singbox", "tailscale")
    command = (
        "Get-NetAdapter | Select-Object -ExpandProperty Name; "
        "Get-NetAdapter | Select-Object -ExpandProperty InterfaceDescription"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=HIDDEN_PROCESS_FLAGS,
        )
        text = (result.stdout or "").lower()
    except Exception:
        text = ""
    return any(keyword in text for keyword in keywords)


def ensure_tun_not_active(refuse_on_tun: bool = True) -> int | None:
    """Warn or refuse to continue if a TUN routing adapter is active.

    Returns an exit code when the caller should stop (2), else None.
    """
    if not detect_tun_active():
        return None
    if refuse_on_tun:
        print(
            "\nRefusing to scan: a TUN routing adapter is active (e.g. V2rayN TUN mode, "
            "Wintun/Tailscale). TUN mode routes ALL traffic at the network layer, so the "
            "scanner cannot guarantee it uses the pure internet.\n"
            "Options:\n"
            "  - Turn off TUN mode in V2rayN (keep system-proxy mode instead), or\n"
            "  - Add an exclusion rule in V2rayN TUN settings for this app and pass "
            "--allow-tun to trust that exclusion.\n"
            "Use --allow-tun only when you are certain the scanner is excluded from TUN routing."
        )
        return 2
    print(
        "\nWarning: a TUN routing adapter is active (e.g. V2rayN TUN mode / Wintun / "
        "Tailscale). If this app is not excluded from TUN routing, it will not use the "
        "pure internet. You can pass --allow-tun to suppress this warning."
    )
    return None


def parse_ip_list(raw: str) -> set[str]:
    ips: set[str] = set()
    for item in raw.split(","):
        ip = item.strip()
        if not ip:
            continue
        ipaddress.ip_address(ip)
        ips.add(ip)
    return ips


def stage_stop_requested(control_dir: Path | None, stage: str) -> bool:
    return bool(control_dir and (control_dir / f"stop_{stage}.flag").exists())


def prompt_text(prompt: str, default: str | None = None, required: bool = False) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    while True:
        raw = input(f"{prompt}{suffix}: ").strip()
        if raw:
            return raw
        if default not in (None, ""):
            return default
        if not required:
            return ""
        print("Please enter a value.")


def prompt_yes_no(prompt: str, default: bool = True) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    while True:
        raw = input(f"{prompt}{suffix}: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes", "1", "true"}:
            return True
        if raw in {"n", "no", "0", "false"}:
            return False
        print("Please answer yes or no.")


def prompt_int(
    prompt: str, default: int | None = None, minimum: int | None = None
) -> int | None:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        raw = input(f"{prompt}{suffix}: ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("Please enter a whole number.")
            continue
        if minimum is not None and value < minimum:
            print(f"Please enter a value of at least {minimum}.")
            continue
        return value


def prompt_float(
    prompt: str, default: float | None = None, minimum: float | None = None
) -> float | None:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        raw = input(f"{prompt}{suffix}: ").strip()
        if not raw:
            return default
        try:
            value = float(raw)
        except ValueError:
            print("Please enter a number.")
            continue
        if minimum is not None and value < minimum:
            print(f"Please enter a value of at least {minimum}.")
            continue
        return value


def interactive_vless_url(default: str | None = None) -> str:
    while True:
        raw = prompt_text("VLESS URL", default=default, required=True)
        try:
            parse_vless_url(raw)
        except Exception as exc:
            print(f"Invalid VLESS URL: {exc}")
            continue
        return raw


def prompt_config_string(prompt: str, default: str | None = None) -> str | None:
    raw = prompt_text(prompt, default=default, required=False)
    return raw or None


def load_cached_clean_candidates(out_dir: Path) -> list[str]:
    path = out_dir / "clean_candidates.txt"
    if not path.exists():
        return []
    candidates = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    validated: list[str] = []
    for item in candidates:
        try:
            ipaddress.IPv4Address(item)
        except Exception:
            continue
        validated.append(item)
    return unique_in_order(validated)


def neighbor_candidates_from_results(
    results: list[ScanResult],
    radius: int,
    limit: int,
    seen_ips: set[str],
) -> list[str]:
    if radius <= 0 or limit <= 0:
        return []
    output: list[str] = []
    seen_output: set[str] = set()
    max_ip = int(ipaddress.IPv4Address("255.255.255.255"))
    for result in best_result_per_ip(sort_results(results)):
        base_net = ipaddress.IPv4Network(f"{result.ip}/24", strict=False)
        base_net_int = int(base_net.network_address)
        for delta in range(0, radius + 1):
            for network_int in (
                base_net_int - (delta * 256),
                base_net_int + (delta * 256),
            ):
                if network_int < 0 or network_int > max_ip:
                    continue
                neighbor_net = ipaddress.IPv4Network(
                    f"{ipaddress.IPv4Address(network_int)}/24", strict=False
                )
                for host in neighbor_net.hosts():
                    neighbor = str(host)
                    if neighbor in seen_ips or neighbor in seen_output:
                        continue
                    seen_output.add(neighbor)
                    output.append(neighbor)
                    if len(output) >= limit:
                        return output
    return output


def phase1_required_score(profile: VlessProfile, ws_check: bool, min_score: int) -> int:
    transport = profile.transport.lower()
    base = 3 if transport == "ws" and ws_check else 2
    return max(min_score, base)


def is_phase1_clean(
    result: ScanResult, profile: VlessProfile, ws_check: bool, min_score: int,
    phase1_latency_ms: int = PHASE1_LATENCY_MS,
) -> bool:
    required_score = phase1_required_score(profile, ws_check, min_score)
    transport = profile.transport.lower()
    if transport == "ws" and ws_check:
        return (
            result.score >= required_score
            and result.tcp_ok
            and result.tls_ok
            and result.ws_ok
            and (phase1_latency_ms <= 0 or result.best_ms <= phase1_latency_ms)
        )

    if phase1_latency_ms > 0 and result.best_ms > phase1_latency_ms:
        return False
    if transport == "xhttp":
        return result.score >= required_score and result.tcp_ok and result.tls_ok
    if profile.security.lower() == "tls":
        return result.score >= required_score and result.tcp_ok and result.tls_ok
    if ws_check:
        return result.score >= required_score and result.tcp_ok and result.ws_ok
    if profile.security.lower() != "tls":
        return result.score >= required_score and result.tcp_ok and result.http_ok
    return result.score >= required_score and result.tcp_ok


def collect_interactive_args(args: argparse.Namespace) -> argparse.Namespace:
    print("Interactive setup")
    print("Press Enter to keep the value shown in brackets.\n")

    args.config = interactive_vless_url(args.config)

    args.xray = prompt_yes_no("Run xray validation?", default=True)
    if args.xray:
        args.xray_during_scan = prompt_yes_no(
            "Start xray validation as soon as clean IPs are found?", default=True
        )
        xray_path = prompt_config_string(
            "Path to xray.exe (blank = auto-detect/install)",
            default=str(args.xray_path) if getattr(args, "xray_path", None) else None,
        )
        args.xray_path = Path(xray_path) if xray_path else None
        args.no_install_xray = not prompt_yes_no(
            "Allow automatic xray download if it is missing?", default=True
        )
        xray_concurrency = prompt_int(
            "xray concurrency", default=args.xray_concurrency, minimum=2
        )
        if xray_concurrency is not None:
            args.xray_concurrency = xray_concurrency
        stage2_count = prompt_int(
            "How many clean hits should Stage 2 validate?",
            default=args.stage2_count,
            minimum=1,
        )
        if stage2_count is not None:
            args.stage2_count = stage2_count
        xray_timeout = prompt_float(
            "xray timeout in seconds", default=args.xray_timeout, minimum=0.1
        )
        if xray_timeout is not None:
            args.xray_timeout = xray_timeout
        args.xray_test_url = prompt_text(
            "xray test URL", default=args.xray_test_url, required=True
        )
        args.download_url = prompt_config_string(
            "Download test URL (blank = skip)", default=args.download_url
        )
        download_bytes = prompt_int(
            "Download test bytes", default=args.download_bytes, minimum=0
        )
        if download_bytes is not None:
            args.download_bytes = download_bytes
        args.upload_url = prompt_config_string(
            "Upload test URL (blank = skip)", default=args.upload_url
        )
        upload_bytes = prompt_int(
            "Upload test bytes", default=args.upload_bytes, minimum=0
        )
        if upload_bytes is not None:
            args.upload_bytes = upload_bytes

    custom_candidates = prompt_yes_no(
        "Use a custom candidate file instead of Cloudflare ranges?", default=False
    )
    if custom_candidates:
        candidate_path = prompt_text(
            "Candidate file path",
            default=str(args.candidates) if args.candidates else None,
            required=True,
        )
        args.candidates = Path(candidate_path)
    else:
        args.candidates = None

    ports_value = prompt_config_string(
        "Ports to test (blank = port from the VLESS config)",
        default=args.ports,
    )
    args.ports = ports_value

    timeout = prompt_float(
        "Per-step timeout in seconds", default=args.timeout, minimum=0.1
    )
    if timeout is not None:
        args.timeout = timeout
    args.no_ws = prompt_yes_no("Skip the WebSocket upgrade check?", default=args.no_ws)
    seed = prompt_int("Random seed", default=args.seed, minimum=0)
    if seed is not None:
        args.seed = seed
    out_dir = prompt_config_string("Output directory", default=str(args.out))
    if out_dir:
        args.out = Path(out_dir)

    concurrency = prompt_int("Stage 1 concurrency", default=args.concurrency, minimum=1)
    if concurrency is not None:
        args.concurrency = concurrency
    limit = prompt_int("Maximum candidates per batch", default=args.limit, minimum=1)
    if limit is not None:
        args.limit = limit
    sample_per_range = prompt_int(
        "Random IPs sampled per Cloudflare range",
        default=args.sample_per_range,
        minimum=1,
    )
    if sample_per_range is not None:
        args.sample_per_range = sample_per_range
    delay = prompt_float(
        "Delay before each connection attempt", default=args.delay, minimum=0.0
    )
    if delay is not None:
        args.delay = delay
    jitter = prompt_float(
        "Extra random delay before each connection attempt",
        default=args.jitter,
        minimum=0.0,
    )
    if jitter is not None:
        args.jitter = jitter

    args.continuous = prompt_yes_no("Keep scanning until Ctrl+C?", default=True)
    stop_after_hits = prompt_int(
        "Stop after this many clean hits (blank = no limit)",
        default=args.stop_after_hits,
        minimum=1,
    )
    args.stop_after_hits = stop_after_hits

    use_neighbors = prompt_yes_no(
        "Search neighbor /24 blocks around each clean hit?", default=True
    )
    if use_neighbors:
        radius = prompt_int(
            "Neighbor radius in /24 blocks around each clean IP",
            default=0,
            minimum=0,
        )

        if radius is not None:
            args.neighbor_radius = radius

        if radius > 0:
            neighbor_limit = prompt_int(
                "Maximum neighbor IPs per round after expanding /24s",
                default=32,
                minimum=1,
            )

            if neighbor_limit is not None:
                args.neighbor_limit = neighbor_limit
    else:
        args.neighbor_radius = 0
    args.reuse_clean_candidates = prompt_yes_no(
        "Reuse clean IPs from the previous run?", default=args.reuse_clean_candidates
    )
    args.require_direct_egress = prompt_yes_no(
        "Check that the current public egress IP is not a known VPN/server exit?",
        default=args.require_direct_egress or True,
    )
    if args.require_direct_egress:
        blocked = prompt_config_string(
            "Blocked egress IP list (blank = keep default)",
            default=args.blocked_egress_ips,
        )
        if blocked:
            args.blocked_egress_ips = blocked
        expected = prompt_config_string(
            "Expected public egress IP (blank = only block known bad exits)",
            default=args.expected_egress_ip,
        )
        args.expected_egress_ip = expected

    args.safe = prompt_yes_no("Use slow protective mode?", default=args.safe)
    args.local_fast = prompt_yes_no("Enable aggressive local scanning?", default=False)
    args.show_failures = prompt_yes_no(
        "Print failed candidates too?", default=args.show_failures
    )
    min_score = prompt_int(
        "Minimum score to keep as a hit", default=args.min_score, minimum=1
    )
    if min_score is not None:
        args.min_score = min_score
    phase1_latency = prompt_int(
        "Max latency (ms) for a candidate to pass Phase 1 clean (0 = disable)",
        default=args.phase1_latency_ms, minimum=0,
    )
    if phase1_latency is not None:
        args.phase1_latency_ms = phase1_latency
    progress_every = prompt_int(
        "Progress update interval", default=args.progress_every, minimum=1
    )
    if progress_every is not None:
        args.progress_every = progress_every
    top = prompt_int("How many best results to print", default=args.top, minimum=1)
    if top is not None:
        args.top = top
    config_count = prompt_int(
        "How many generated configs to save/print", default=args.config_count, minimum=1
    )
    if config_count is not None:
        args.config_count = config_count
    args.config_remark = prompt_config_string(
        "Custom config remark after #", default=args.config_remark
    )

    return args


def load_candidates(path: Path) -> list[str]:
    candidates: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "/" in line:
            net = ipaddress.IPv4Network(line, strict=False)
            candidates.extend(str(ip) for ip in net.hosts())
        else:
            ipaddress.IPv4Address(line)
            candidates.append(line)
    return dedupe(candidates)


def sample_from_ranges(
    ranges: Iterable[ipaddress.IPv4Network],
    per_range: int,
    limit: int,
    seed: int,
    subnet_weights: dict[str, float] | None = None,
) -> list[str]:
    rng = random.Random(seed)
    output: list[str] = []
    
    # Convert ranges to list to allow weighted sampling
    range_list = list(ranges)
    if not range_list:
        return output
    
    # If no weights provided, use uniform sampling
    if not subnet_weights:
        for net in range_list:
            count = min(per_range, max(1, net.num_addresses - 2))
            for _ in range(count):
                output.append(random_host_from_network(net, rng))
                if len(output) >= limit:
                    return dedupe(output)
        return dedupe(output)
    
    # Weighted sampling: prefer subnets with higher hit rates
    # Group ranges by /24 subnet
    subnet_to_ranges: dict[str, list[ipaddress.IPv4Network]] = {}
    for net in range_list:
        # For each /24 within the range
        for subnet_net in net.subnets(new_prefix=24):
            subnet_key = str(subnet_net)
            if subnet_key not in subnet_to_ranges:
                subnet_to_ranges[subnet_key] = []
            subnet_to_ranges[subnet_key].append(subnet_net)
    
    # Create weight list for subnets
    subnets = list(subnet_to_ranges.keys())
    weights = [subnet_weights.get(s, 1.0) for s in subnets]
    
    # Normalize weights
    total_weight = sum(weights)
    if total_weight == 0:
        weights = [1.0] * len(weights)
        total_weight = len(weights)
    
    # Sample subnets proportionally to weights
    while len(output) < limit and subnets:
        # Choose a subnet based on weights
        chosen_idx = rng.choices(range(len(subnets)), weights=weights, k=1)[0]
        chosen_subnet = subnets[chosen_idx]
        chosen_ranges = subnet_to_ranges[chosen_subnet]
        
        # Pick a random range from this subnet
        net = rng.choice(chosen_ranges)
        output.append(random_host_from_network(net, rng))
        
        # Remove this subnet if we've sampled enough from it
        if len([ip for ip in output if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(chosen_subnet)]) >= per_range:
            subnets.pop(chosen_idx)
            weights.pop(chosen_idx)
    
    return dedupe(output)


def random_host_from_network(net: ipaddress.IPv4Network, rng: random.Random) -> str:
    if net.num_addresses <= 2:
        return str(net.network_address)
    offset = rng.randint(1, net.num_addresses - 2)
    return str(net.network_address + offset)


def dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


async def scan_candidate(
    ip: str,
    port: int,
    profile: VlessProfile,
    timeout: float,
    ws_check: bool,
) -> ScanResult:
    tcp_ok = tls_ok = ws_ok = http_ok = False
    tcp_ms = tls_ms = ws_ms = http_ms = None
    error = ""

    try:
        tcp_ok, tcp_ms = await time_tcp_connect(ip, port, timeout)
        if not tcp_ok:
            return ScanResult(
                ip, port, tcp_ok, tls_ok, ws_ok, http_ok, tcp_ms, tls_ms, ws_ms, http_ms, "tcp_failed"
            )

        uses_tls = profile.security.lower() == "tls"
        transport = profile.transport.lower()
        allow_insecure = query_value(
            profile, "allowInsecure", query_value(profile, "insecure", "0")
        ) in {"1", "true", "True"}

        if ws_check and transport == "ws":
            ws_ok, ws_ms, error = await time_websocket_upgrade(
                ip, port, profile, timeout, use_tls=uses_tls, allow_insecure=allow_insecure
            )
            if ws_ok and uses_tls:
                tls_ok = True
                tls_ms = ws_ms
            elif uses_tls:
                tls_ok, tls_ms = await time_tls_handshake(
                    ip, port, profile.sni, timeout, allow_insecure
                )
                if not tls_ok:
                    return ScanResult(
                        ip,
                        port,
                        tcp_ok,
                        tls_ok,
                        ws_ok,
                        http_ok,
                        tcp_ms,
                        tls_ms,
                        ws_ms,
                        http_ms,
                        "tls_failed",
                    )
        elif transport == "xhttp":
            if uses_tls:
                tls_ok, tls_ms = await time_tls_handshake(
                    ip, port, profile.sni, timeout, allow_insecure
                )
                if not tls_ok:
                    return ScanResult(
                        ip,
                        port,
                        tcp_ok,
                        tls_ok,
                        ws_ok,
                        http_ok,
                        tcp_ms,
                        tls_ms,
                        ws_ms,
                        http_ms,
                        "tls_failed",
                    )
            error = "xhttp_stage1_tcp_tls_only"
        elif uses_tls:
            tls_ok, tls_ms = await time_tls_handshake(ip, port, profile.sni, timeout, allow_insecure)
            if not tls_ok:
                return ScanResult(
                    ip, port, tcp_ok, tls_ok, ws_ok, http_ok, tcp_ms, tls_ms, ws_ms, http_ms, "tls_failed"
                )
            error = "tcp_tls_ok"
        elif not ws_check:
            error = "ws_skipped"
            http_ok, http_ms = await time_http_request(ip, port, profile.host, timeout)
        else:
            error = f"unsupported_transport_{profile.transport or 'empty'}"
    except Exception as exc:
        error = type(exc).__name__

    return ScanResult(ip, port, tcp_ok, tls_ok, ws_ok, http_ok, tcp_ms, tls_ms, ws_ms, http_ms, error)


async def time_tcp_connect(
    ip: str, port: int, timeout: float
) -> tuple[bool, float | None]:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True, elapsed_ms(start)
    except Exception:
        return False, None


async def time_tls_handshake(
    ip: str, port: int, sni: str, timeout: float, allow_insecure: bool = False
) -> tuple[bool, float | None]:
    start = time.perf_counter()
    context = ssl.create_default_context()
    if allow_insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context, server_hostname=sni),
            timeout=timeout,
        )
        # Verify certificate expiry and SAN match
        if not allow_insecure:
            cert = writer.get_extra_info("ssl_object").getpeercert()
            if cert:
                # Check notAfter
                import datetime
                not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if not_after < datetime.datetime.utcnow():
                    writer.close()
                    await writer.wait_closed()
                    return False, None
                # Check SAN matches SNI
                san_list = []
                for san_type, san_value in cert.get("subjectAltName", []):
                    if san_type == "DNS":
                        san_list.append(san_value)
                if san_list and not any(_match_hostname(sni, san) for san in san_list):
                    writer.close()
                    await writer.wait_closed()
                    return False, None
        writer.close()
        await writer.wait_closed()
        return True, elapsed_ms(start)
    except Exception:
        return False, None


def _match_hostname(hostname: str, pattern: str) -> bool:
    """Match hostname against pattern with wildcard support."""
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) or hostname == suffix[1:]
    return hostname == pattern


async def time_websocket_upgrade(
    ip: str,
    port: int,
    profile: VlessProfile,
    timeout: float,
    use_tls: bool,
    allow_insecure: bool = False,
) -> tuple[bool, float | None, str]:
    start = time.perf_counter()
    try:
        if use_tls:
            context = ssl.create_default_context()
            if allow_insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ip, port, ssl=context, server_hostname=profile.sni
                ),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        key = base64.b64encode(random.randbytes(16)).decode("ascii")
        request = (
            f"GET {profile.path} HTTP/1.1\r\n"
            f"Host: {profile.host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "User-Agent: MehrScanner/1.0\r\n"
            "\r\n"
        )
        writer.write(request.encode("ascii"))
        await writer.drain()
        first_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        status_line = first_line.decode("latin-1", errors="replace").strip()
        return (
            status_line.startswith("HTTP/1.1 101")
            or status_line.startswith("HTTP/2 101"),
            elapsed_ms(start),
            status_line,
        )
    except Exception as exc:
        return False, None, type(exc).__name__


async def time_http_request(
    ip: str,
    port: int,
    host: str,
    timeout: float,
) -> tuple[bool, float | None]:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: MehrScanner/1.0\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        writer.write(request.encode("ascii"))
        await writer.drain()
        first_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        status_line = first_line.decode("latin-1", errors="replace").strip()
        ok = status_line.startswith("HTTP/1.") or status_line.startswith("HTTP/2 ")
        return ok, elapsed_ms(start)
    except Exception:
        return False, None


def elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


async def run_scan(
    profile: VlessProfile,
    candidates: list[str],
    ranges: list[ipaddress.IPv4Network] | None,
    sample_per_range: int,
    limit: int,
    seed: int,
    ports: list[int],
    concurrency: int,
    timeout: float,
    ws_check: bool,
    min_score: int,
    neighbor_radius: int,
    neighbor_limit: int,
    show_failures: bool,
    progress_every: int,
    delay: float,
    jitter: float,
    continuous: bool,
    stop_after_hits: int | None,
    out_dir: Path,
    on_clean: Callable[[ScanResult], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    phase1_latency_ms: int = PHASE1_LATENCY_MS,
) -> list[ScanResult]:
    semaphore = asyncio.Semaphore(concurrency)
    prepare_live_outputs(out_dir)

    async def guarded(ip: str, port: int) -> ScanResult:
        async with semaphore:
            pause = delay + (random.random() * jitter if jitter > 0 else 0)
            if pause > 0:
                await asyncio.sleep(pause)
            return await scan_candidate(ip, port, profile, timeout, ws_check)

    results: list[ScanResult] = []
    completed = 0
    hits = 0
    round_number = 0
    frontier = unique_in_order(candidates)
    seen_ips: set[str] = set(frontier)
    # Track hit rates per /24 subnet for weighted sampling
    subnet_hits: dict[str, int] = {}
    subnet_attempts: dict[str, int] = {}
    
    def _get_subnet(ip: str) -> str:
        """Get /24 subnet key for an IP."""
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return str(net)
    
    def _calculate_subnet_weights() -> dict[str, float]:
        """Calculate weights based on hit rate per subnet."""
        weights = {}
        for subnet, hit_count in subnet_hits.items():
            attempts = subnet_attempts.get(subnet, 1)
            # Weight = hit rate * (1 + log(attempts)) to favor explored subnets with good hit rates
            import math
            hit_rate = hit_count / attempts
            weights[subnet] = hit_rate * (1 + math.log(attempts + 1))
        return weights
    while True:
        if should_stop and should_stop():
            print("\nStage 1 stop requested. Keeping results found so far.")
            break
        round_number += 1
        if round_number > 1 and (continuous or stop_after_hits is not None):
            subnet_weights = _calculate_subnet_weights() if subnet_hits else None
            frontier = (
                unique_in_order(
                    frontier
                    + sample_from_ranges(
                        ranges or [], sample_per_range, limit, seed + round_number, subnet_weights
                    )
                )
                if ranges
                else frontier
            )
        frontier = [ip for ip in frontier if ip not in seen_ips or round_number == 1]
        if not frontier:
            break
        tasks = [
            asyncio.create_task(guarded(ip, port)) for ip in frontier for port in ports
        ]
        total = len(tasks)
        round_clean: list[ScanResult] = []
        for task in asyncio.as_completed(tasks):
            if should_stop and should_stop():
                for pending in tasks:
                    if not pending.done():
                        pending.cancel()
                print("\nStage 1 stop requested. Keeping results found so far.")
                return sort_results(results)
            result = await task
            seen_ips.add(result.ip)
            completed += 1
            # Track subnet statistics for weighted sampling
            subnet = _get_subnet(result.ip)
            subnet_attempts[subnet] = subnet_attempts.get(subnet, 0) + 1
            is_hit = is_phase1_clean(
                result, profile, ws_check, min_score, phase1_latency_ms
            )
            if is_hit:
                subnet_hits[subnet] = subnet_hits.get(subnet, 0) + 1
                results.append(result)
                round_clean.append(result)
                hits += 1
                append_live_hit(result, out_dir)
                if on_clean:
                    on_clean(result)
                if stop_after_hits is not None and hits >= stop_after_hits:
                    for pending in tasks:
                        if not pending.done():
                            pending.cancel()
                    print(f"\nReached requested hit limit: {hits}/{stop_after_hits}")
                    return sort_results(results)
            if is_hit or show_failures:
                marker = "OK" if is_hit else "--"
                total_label = "open" if continuous else str(total)
                print(
                    f"[{completed:>7}/{total_label}] scanned={completed} {marker} {result.ip}:{result.port} "
                    f"tcp={fmt_ms(result.tcp_ms)} tls={fmt_ms(result.tls_ms)} "
                    f"ws={fmt_ms(result.ws_ms)} note={result.error}"
                )
            elif progress_every and completed % progress_every == 0:
                print(
                    f"[{completed:>7}/open] scanned={completed} hits={hits} latest_round={round_number}"
                )
        next_frontier: list[str] = []
        if neighbor_radius > 0 and round_clean:
            next_frontier.extend(
                neighbor_candidates_from_results(
                    round_clean, neighbor_radius, neighbor_limit, seen_ips
                )
            )
        if continuous or stop_after_hits is not None:
            if ranges:
                subnet_weights = _calculate_subnet_weights() if subnet_hits else None
                next_frontier.extend(
                    sample_from_ranges(
                        ranges, sample_per_range, limit, seed + round_number + 1, subnet_weights
                    )
                )
        elif neighbor_radius <= 0:
            break
        frontier = unique_in_order(next_frontier)
        print(
            f"[round {round_number}] scanned={completed} clean={hits} next={len(frontier)}"
        )
        if not frontier:
            break
    return sort_results(results)


def fmt_ms(value: float | None) -> str:
    return f"{value:.1f}ms" if value is not None else "-"


def write_outputs(
    results: list[ScanResult],
    out_dir: Path,
    profile: VlessProfile,
    config_count: int,
    config_remark: str | None,
    min_score: int = 2,
) -> None:
    results = sort_results(results)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "results.json"
    csv_path = out_dir / "results.csv"
    clean_path = out_dir / "clean_candidates.txt"
    configs_path = out_dir / "vless_top_configs.txt"

    json_path.write_text(
        json.dumps(
            [asdict(result) | {"score": result.score} for result in results], indent=2
        ),
        encoding="utf-8",
    )
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ip",
                "port",
                "score",
                "tcp_ok",
                "tls_ok",
                "ws_ok",
                "http_ok",
                "tcp_ms",
                "tls_ms",
                "ws_ms",
                "http_ms",
                "error",
            ],
        )
        writer.writeheader()
        for result in results:
            row = asdict(result)
            row["score"] = result.score
            writer.writerow(row)

    clean = unique_in_order([r.ip for r in results if r.score >= min_score])
    clean_path.write_text("\n".join(clean) + ("\n" if clean else ""), encoding="utf-8")
    configs = build_top_vless_configs(
        results, profile, config_count, remark=config_remark, min_score=min_score
    )
    configs_path.write_text(
        "\n\n".join(configs) + ("\n" if configs else ""), encoding="utf-8"
    )


def prepare_live_outputs(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "clean_candidates.txt").write_text("", encoding="utf-8")
    (out_dir / "vless_top_configs.txt").write_text("", encoding="utf-8")
    (out_dir / "hits.jsonl").write_text("", encoding="utf-8")
    with (out_dir / "hits.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ip",
                "port",
                "score",
                "tcp_ok",
                "tls_ok",
                "ws_ok",
                "http_ok",
                "tcp_ms",
                "tls_ms",
                "ws_ms",
                "http_ms",
                "error",
            ],
        )
        writer.writeheader()


def append_live_hit(result: ScanResult, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "clean_candidates.txt").open("a", encoding="utf-8") as handle:
        handle.write(f"{result.ip}\n")
    with (out_dir / "hits.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(result) | {"score": result.score}) + "\n")
    with (out_dir / "hits.csv").open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ip",
                "port",
                "score",
                "tcp_ok",
                "tls_ok",
                "ws_ok",
                "http_ok",
                "tcp_ms",
                "tls_ms",
                "ws_ms",
                "http_ms",
                "error",
            ],
        )
        row = asdict(result)
        row["score"] = result.score
        writer.writerow(row)


def build_top_vless_configs(
    results: list[ScanResult],
    profile: VlessProfile,
    count: int,
    remark: str | None = None,
    min_score: int = 2,
) -> list[str]:
    unique_results = best_result_per_ip(
        sort_results([result for result in results if result.score >= min_score])
    )
    return [
        build_vless_url(profile, result.ip, result.port, remark=remark)
        for result in unique_results[:count]
    ]


def print_generated_configs(
    results: list[ScanResult], profile: VlessProfile, count: int, remark: str | None
) -> None:
    configs = build_top_vless_configs(results, profile, count, remark=remark)
    if not configs:
        return
    print(f"\nTop {len(configs)} generated VLESS configs")
    print("-" * 72)
    for config in configs:
        print(config)
        print()


def sort_results(results: list[ScanResult]) -> list[ScanResult]:
    return sorted(
        results, key=lambda item: (item.best_ms, -item.score, item.ip, item.port)
    )


def unique_in_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output


def load_live_hits(out_dir: Path) -> list[ScanResult]:
    path = out_dir / "hits.jsonl"
    if not path.exists():
        return []
    results: list[ScanResult] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        data.pop("score", None)
        # Backward compatibility: add default values for new fields
        data.setdefault("http_ok", False)
        data.setdefault("http_ms", None)
        results.append(ScanResult(**data))
    return sort_results(results)


def find_free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def find_xray(project_dir: Path, xray_path: Path | None) -> Path | None:
    if xray_path and xray_path.exists():
        return xray_path
    local_xray = project_dir / "tools" / "xray" / "xray.exe"
    if local_xray.exists():
        return local_xray
    found = shutil.which("xray")
    return Path(found) if found else None


def install_xray(project_dir: Path) -> Path:
    target_dir = project_dir / "tools" / "xray"
    target_dir.mkdir(parents=True, exist_ok=True)
    xray_exe = target_dir / "xray.exe"
    if xray_exe.exists():
        return xray_exe

    print("Xray not found. Downloading official Xray-core Windows 64-bit release...")
    release = read_json_url(XRAY_LATEST_RELEASE_API)
    asset_url = ""
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if name == "Xray-windows-64.zip":
            asset_url = asset.get("browser_download_url", "")
            break
    if not asset_url:
        raise RuntimeError(
            "Could not find Xray-windows-64.zip in the latest Xray-core release."
        )

    zip_path = target_dir / "Xray-windows-64.zip"
    download_file(asset_url, zip_path)
    with zipfile.ZipFile(zip_path) as archive:
        archive.extractall(target_dir)
    if not xray_exe.exists():
        raise RuntimeError("Downloaded Xray archive did not contain xray.exe.")
    return xray_exe


def read_json_url(url: str) -> dict:
    request = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 MehrScanner/1.0",
            "Accept": "application/json",
        },
    )
    with open_url(request, 20) as response:
        return json.loads(response.read().decode("utf-8"))


def download_file(url: str, target: Path) -> None:
    request = Request(url, headers={"User-Agent": "Mozilla/5.0 MehrScanner/1.0"})
    with open_url(request, 60) as response, target.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def xray_outbound_for(profile: VlessProfile, result: ScanResult) -> dict:
    encryption = query_value(profile, "encryption", "none")
    flow = query_value(profile, "flow", "")
    fp = query_value(profile, "fp", "")
    alpn_raw = query_value(profile, "alpn", "")
    allow_insecure = query_value(
        profile, "allowInsecure", query_value(profile, "insecure", "0")
    ) in {"1", "true", "True"}

    user = {"id": profile.uuid, "encryption": encryption}
    if flow:
        user["flow"] = flow

    stream_settings: dict = {
        "network": profile.transport or "tcp",
        "security": profile.security or "none",
    }
    if profile.security.lower() == "tls":
        tls_settings: dict = {
            "serverName": profile.sni,
            "allowInsecure": allow_insecure,
        }
        if fp:
            tls_settings["fingerprint"] = fp
        if alpn_raw:
            tls_settings["alpn"] = [
                item.strip() for item in alpn_raw.split(",") if item.strip()
            ]
        stream_settings["tlsSettings"] = tls_settings
    if profile.transport.lower() == "ws":
        stream_settings["wsSettings"] = {
            "path": profile.path,
            "headers": {"Host": profile.host},
        }
    if profile.transport.lower() == "xhttp":
        xhttp_settings: dict = {"path": profile.path, "host": profile.host}
        mode = query_value(profile, "mode", "")
        extra_raw = query_value(profile, "extra", "")
        if mode:
            xhttp_settings["mode"] = mode
        if extra_raw:
            try:
                xhttp_settings["extra"] = json.loads(extra_raw)
            except json.JSONDecodeError:
                xhttp_settings["extra"] = extra_raw
        stream_settings["xhttpSettings"] = xhttp_settings

    return {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": result.ip,
                    "port": result.port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": stream_settings,
    }


def build_xray_config(
    profile: VlessProfile, result: ScanResult, local_port: int
) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "local-http",
                "listen": "127.0.0.1",
                "port": local_port,
                "protocol": "http",
                "settings": {"timeout": 0},
            }
        ],
        "outbounds": [xray_outbound_for(profile, result)],
    }


def validate_with_xray(
    xray_path: Path,
    profile: VlessProfile,
    result: ScanResult,
    test_url: str,
    timeout: float,
    download_url: str | None = None,
    download_bytes: int = 0,
    upload_url: str | None = None,
    upload_bytes: int = 0,
    should_stop: Callable[[], bool] | None = None,
) -> XrayValidationResult:
    local_port = find_free_local_port()
    config = build_xray_config(profile, result, local_port)
    with tempfile.TemporaryDirectory(prefix="mehrdadscaner-xray-") as tmp:
        config_path = Path(tmp) / "config.json"
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        proc = subprocess.Popen(
            [str(xray_path), "run", "-config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=HIDDEN_PROCESS_FLAGS,
        )
        try:
            for _ in range(16):
                if should_stop and should_stop():
                    return XrayValidationResult(
                        result.ip, result.port, False, None, None, None, 0, 0, "stage2_stopped"
                    )
                time.sleep(0.05)
            if proc.poll() is not None:
                stderr = (proc.stderr.read() if proc.stderr else "").strip()
                return XrayValidationResult(
                    result.ip, result.port, False, None, None, None, 0, 0,
                    stderr or "xray_exited"
                )
            if should_stop and should_stop():
                return XrayValidationResult(
                    result.ip, result.port, False, None, None, None, 0, 0, "stage2_stopped"
                )
            latency_ms, code = fetch_through_http_proxy(local_port, test_url, timeout)
            ok = code in {200, 204, 301, 302}
            measured_download_mbps = None
            measured_upload_mbps = None
            measured_download_bytes = 0
            measured_upload_bytes = 0
            notes = [f"http_{code}"]
            if ok and download_url and download_bytes > 0:
                if should_stop and should_stop():
                    return XrayValidationResult(
                        result.ip, result.port, False, None, None, None, 0, 0, "stage2_stopped"
                    )
                try:
                    (
                        measured_download_mbps,
                        measured_download_bytes,
                        download_code,
                    ) = download_through_http_proxy(
                        local_port, download_url, timeout, download_bytes
                    )
                    notes.append(f"download_http_{download_code}")
                except Exception as exc:
                    notes.append(f"download_{type(exc).__name__}")
            if ok and upload_url and upload_bytes > 0:
                if should_stop and should_stop():
                    return XrayValidationResult(
                        result.ip, result.port, False, None, None, None, 0, 0, "stage2_stopped"
                    )
                try:
                    (
                        measured_upload_mbps,
                        measured_upload_bytes,
                        upload_code,
                    ) = upload_through_http_proxy(
                        local_port, upload_url, timeout, upload_bytes
                    )
                    notes.append(f"upload_http_{upload_code}")
                except Exception as exc:
                    if type(exc).__name__ == "URLError":
                        notes.append("upload_unavailable")
                    else:
                        notes.append(f"upload_{type(exc).__name__}")
            return XrayValidationResult(
                result.ip,
                result.port,
                ok,
                latency_ms if ok else None,
                measured_download_mbps,
                measured_upload_mbps,
                measured_download_bytes,
                measured_upload_bytes,
                ";".join(notes),
            )
        except Exception as exc:
            return XrayValidationResult(
                result.ip, result.port, False, None, None, None, 0, 0,
                type(exc).__name__
            )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


def fetch_through_http_proxy(
    local_port: int, test_url: str, timeout: float
) -> tuple[float, int]:
    proxy_url = f"http://127.0.0.1:{local_port}"
    opener = build_opener(ProxyHandler({"http": proxy_url, "https": proxy_url}))
    request = Request(test_url, headers={"User-Agent": "Mozilla/5.0 MehrScanner/1.0"})
    start = time.perf_counter()
    with opener.open(request, timeout=timeout) as response:
        code = int(response.getcode())
        response.read(256)
    return elapsed_ms(start), code


def download_through_http_proxy(
    local_port: int, url: str, timeout: float, max_bytes: int
) -> tuple[float | None, int, int]:
    proxy_url = f"http://127.0.0.1:{local_port}"
    opener = build_opener(ProxyHandler({"http": proxy_url, "https": proxy_url}))
    request = Request(url, headers={"User-Agent": "Mozilla/5.0 MehrScanner/1.0"})
    start = time.perf_counter()
    received = 0
    try:
        with opener.open(request, timeout=timeout) as response:
            code = int(response.getcode())
            if code == 429:
                return None, 0, 429
            while received < max_bytes:
                chunk = response.read(min(64 * 1024, max_bytes - received))
                if not chunk:
                    break
                received += len(chunk)
    except HTTPError as exc:
        return None, 0, int(exc.code)
    elapsed = time.perf_counter() - start
    mbps = round((received * 8) / (elapsed * 1_000_000), 2) if elapsed > 0 else None
    return mbps, received, code


def upload_through_http_proxy(
    local_port: int, url: str, timeout: float, payload_bytes: int
) -> tuple[float | None, int, int]:
    proxy_url = f"http://127.0.0.1:{local_port}"
    opener = build_opener(ProxyHandler({"http": proxy_url, "https": proxy_url}))
    payload = b"0" * payload_bytes
    request = Request(
        url,
        data=payload,
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 MehrScanner/1.0",
            "Content-Type": "application/octet-stream",
        },
    )
    start = time.perf_counter()
    try:
        with opener.open(request, timeout=timeout) as response:
            code = int(response.getcode())
            response.read(256)
    except HTTPError as exc:
        return None, 0, int(exc.code)
    elapsed = time.perf_counter() - start
    mbps = round((payload_bytes * 8) / (elapsed * 1_000_000), 2) if elapsed > 0 else None
    return mbps, payload_bytes, code


def run_xray_stage2(
    results: list[ScanResult],
    profile: VlessProfile,
    xray_path: Path,
    stage2_count: int,
    xray_concurrency: int,
    test_url: str,
    timeout: float,
    out_dir: Path,
    config_count: int,
    config_remark: str | None,
    download_url: str | None = None,
    download_bytes: int = 0,
    upload_url: str | None = None,
    upload_bytes: int = 0,
    should_stop: Callable[[], bool] | None = None,
    min_score: int = 2,
) -> list[XrayValidationResult]:
    candidates = best_result_per_ip(
        sort_results([result for result in results if result.score >= min_score])
    )[:stage2_count]
    if not candidates:
        print("\nStage 2 skipped: no Stage 1 hits to validate.")
        return []

    print(f"\nStage 2: validating top {len(candidates)} candidates with xray-core")
    print("-" * 72)
    validated: list[XrayValidationResult] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=xray_concurrency
    ) as executor:
        futures = {}
        for candidate in candidates:
            if should_stop and should_stop():
                print("\nStage 2 stop requested. Keeping completed validations.")
                break
            future = executor.submit(
                validate_with_xray,
                xray_path,
                profile,
                candidate,
                test_url,
                timeout,
                download_url,
                download_bytes,
                upload_url,
                upload_bytes,
                should_stop,
            )
            futures[future] = candidate
        for index, future in enumerate(
            concurrent.futures.as_completed(futures), start=1
        ):
            candidate = futures[future]
            try:
                validation = future.result()
            except Exception as exc:
                validation = XrayValidationResult(
                    candidate.ip,
                    candidate.port,
                    False,
                    None,
                    None,
                    None,
                    0,
                    0,
                    type(exc).__name__,
                )
            validated.append(validation)
            marker = "OK" if validation.ok else "--"
            print(
                f"[{index:>3}/{len(candidates)}] {marker} {candidate.ip}:{candidate.port} "
                f"xray={fmt_ms(validation.latency_ms)} "
                f"down={fmt_mbps(validation.download_mbps)} "
                f"up={fmt_mbps(validation.upload_mbps)} note={validation.error}"
            )
            persist_xray_progress(
                validated, profile, out_dir, config_count, config_remark
            )

    write_xray_outputs(validated, profile, out_dir, config_count, config_remark)
    return sort_xray_results(validated)


class XrayStage2Pipeline:
    def __init__(
        self,
        profile: VlessProfile,
        xray_path: Path,
        stage2_count: int,
        xray_concurrency: int,
        test_url: str,
        timeout: float,
        out_dir: Path,
        config_count: int,
        config_remark: str | None,
        download_url: str | None,
        download_bytes: int,
        upload_url: str | None,
        upload_bytes: int,
        should_stop: Callable[[], bool] | None = None,
    ) -> None:
        self.profile = profile
        self.xray_path = xray_path
        self.stage2_count = stage2_count
        self.test_url = test_url
        self.timeout = timeout
        self.out_dir = out_dir
        self.config_count = config_count
        self.config_remark = config_remark
        self.download_url = download_url
        self.download_bytes = download_bytes
        self.upload_url = upload_url
        self.upload_bytes = upload_bytes
        self.should_stop = should_stop
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=xray_concurrency
        )
        self.lock = threading.Lock()
        self.submitted_ips: set[str] = set()
        self.futures: dict[concurrent.futures.Future[XrayValidationResult], ScanResult] = {}
        self.validations: list[XrayValidationResult] = []
        print(
            f"\nStage 2 streaming: validating up to {stage2_count} candidates while Stage 1 continues"
        )

    def submit(self, candidate: ScanResult) -> None:
        with self.lock:
            if (
                (self.should_stop and self.should_stop())
                or
                len(self.submitted_ips) >= self.stage2_count
                or candidate.ip in self.submitted_ips
            ):
                return
            self.submitted_ips.add(candidate.ip)
            future = self.executor.submit(
                validate_with_xray,
                self.xray_path,
                self.profile,
                candidate,
                self.test_url,
                self.timeout,
                self.download_url,
                self.download_bytes,
                self.upload_url,
                self.upload_bytes,
                self.should_stop,
            )
            self.futures[future] = candidate
        future.add_done_callback(self._collect)

    def _collect(self, future: concurrent.futures.Future[XrayValidationResult]) -> None:
        candidate = self.futures[future]
        try:
            validation = future.result()
        except Exception as exc:
            validation = XrayValidationResult(
                candidate.ip,
                candidate.port,
                False,
                None,
                None,
                None,
                0,
                0,
                type(exc).__name__,
            )
        with self.lock:
            self.validations.append(validation)
            snapshot = list(self.validations)
        marker = "OK" if validation.ok else "--"
        print(
            f"[Stage 2] {marker} {validation.ip}:{validation.port} "
            f"xray={fmt_ms(validation.latency_ms)} "
            f"down={fmt_mbps(validation.download_mbps)} "
            f"up={fmt_mbps(validation.upload_mbps)} note={validation.error}"
        )
        persist_xray_progress(
            snapshot,
            self.profile,
            self.out_dir,
            self.config_count,
            self.config_remark,
        )

    def finish(self) -> list[XrayValidationResult]:
        self.executor.shutdown(wait=True)
        with self.lock:
            validations = sort_xray_results(self.validations)
        write_xray_outputs(
            validations,
            self.profile,
            self.out_dir,
            self.config_count,
            self.config_remark,
        )
        return validations


def _better_ranks(values: list[float | None]) -> list[float]:
    """Fractional 'larger is better' ranks in [0,1]; missing values are neutral.

    The best value gets 1.0, the worst gets 1/n, and unmeasured values get 0.5
    so a candidate is neither punished nor rewarded for a missing speed test.
    """
    n = len(values)
    if n == 0:
        return []
    present = [
        (index, value)
        for index, value in enumerate(values)
        if value is not None and math.isfinite(value)
    ]
    ordered = sorted(present, key=lambda pair: pair[1], reverse=True)
    ranks: list[float | None] = [None] * n
    for position, (index, _) in enumerate(ordered, start=1):
        ranks[index] = (n - position + 1) / n
    return [0.5 if rank is None else rank for rank in ranks]


def composite_rank_score(item: XrayValidationResult, index: int, good: list) -> float:
    """Combine latency, download and upload into one higher-is-better score."""
    latency = [-(r.latency_ms if r.latency_ms is not None else math.nan) for r in good]
    download = [r.download_mbps for r in good]
    upload = [r.upload_mbps for r in good]
    latency_ranks = _better_ranks(latency)
    download_ranks = _better_ranks(download)
    upload_ranks = _better_ranks(upload)
    return (
        _rank_weights["latency"] * latency_ranks[index]
        + _rank_weights["download"] * download_ranks[index]
        + _rank_weights["upload"] * upload_ranks[index]
    )


def sort_xray_results(
    results: list[XrayValidationResult],
) -> list[XrayValidationResult]:
    """Order validated results by a robust composite rank.

    Working candidates are ranked by weighted latency, download and upload
    (rank-based so outliers and missing measurements cannot distort the
    ordering); failed candidates always come after the working ones.
    """
    good = [item for item in results if item.ok]
    bad = sorted(
        (item for item in results if not item.ok),
        key=lambda item: (item.best_ms, item.ip, item.port),
    )
    if not good:
        return bad
    scored = [
        (composite_rank_score(item, index, good), index, item)
        for index, item in enumerate(good)
    ]
    scored.sort(key=lambda triple: (triple[0], -triple[1]), reverse=True)
    return [item for _, _, item in scored] + bad


def write_xray_outputs(
    validations: list[XrayValidationResult],
    profile: VlessProfile,
    out_dir: Path,
    config_count: int,
    config_remark: str | None,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    validations = sort_xray_results(validations)
    good = [item for item in validations if item.ok]
    (out_dir / "xray_validated_ips.txt").write_text(
        "\n".join(item.ip for item in good) + ("\n" if good else ""), encoding="utf-8"
    )
    (out_dir / "xray_validated.json").write_text(
        json.dumps([asdict(item) for item in validations], indent=2), encoding="utf-8"
    )
    with (out_dir / "xray_validated.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ip",
                "port",
                "ok",
                "latency_ms",
                "download_mbps",
                "upload_mbps",
                "download_bytes",
                "upload_bytes",
                "error",
            ],
        )
        writer.writeheader()
        for item in validations:
            writer.writerow(asdict(item))

    config_results = [
        ScanResult(
            item.ip,
            item.port,
            True,
            True,
            True,
            True,  # http_ok
            item.latency_ms,
            item.latency_ms,
            item.latency_ms,
            item.latency_ms,  # http_ms
            "xray_validated",
        )
        for item in good
    ]
    configs = build_top_vless_configs(
        config_results, profile, config_count, remark=config_remark
    )
    (out_dir / "vless_xray_validated_configs.txt").write_text(
        "\n\n".join(configs) + ("\n" if configs else ""), encoding="utf-8"
    )


def persist_xray_progress(
    validations: list[XrayValidationResult],
    profile: VlessProfile,
    out_dir: Path,
    config_count: int,
    config_remark: str | None,
) -> None:
    if not validations:
        return
    write_xray_outputs(validations, profile, out_dir, config_count, config_remark)


def print_xray_summary(
    validations: list[XrayValidationResult],
    profile: VlessProfile,
    top: int,
    remark: str | None,
) -> None:
    good = [item for item in sort_xray_results(validations) if item.ok]

    if not good:
        print("\nNo xray-validated candidates worked.")
        return

    print(f"\nTop {min(top, len(good))} xray-validated VLESS configs")
    print("-" * 72)

    for item in good[:top]:
        print(
            f"{item.ip}:{item.port} latency={fmt_ms(item.latency_ms)} "
            f"download={fmt_mbps(item.download_mbps)} upload={fmt_mbps(item.upload_mbps)}"
        )
        print(
            build_vless_url(
                profile,
                item.ip,
                item.port,
                remark=remark,
            )
        )
        print()


def print_summary(results: list[ScanResult], top: int, min_score: int = 2) -> None:
    results = best_result_per_ip(sort_results(results))
    print("\nBest candidates")
    print("-" * 72)
    for index, result in enumerate(results[:top], start=1):
        print(
            f"{index:>2}. {result.ip}:{result.port} score={result.score} "
            f"tcp={fmt_ms(result.tcp_ms)} tls={fmt_ms(result.tls_ms)} ws={fmt_ms(result.ws_ms)}"
        )

    latencies = [r.best_ms for r in results if r.score >= min_score and r.best_ms < 999999.0]
    if latencies:
        print(
            f"\nMedian latency among likely-good candidates: {statistics.median(latencies):.1f}ms"
        )


def best_result_per_ip(results: list[ScanResult]) -> list[ScanResult]:
    seen: set[str] = set()
    output: list[ScanResult] = []
    for result in results:
        if result.ip in seen:
            continue
        seen.add(result.ip)
        output.append(result)
    return output


async def recheck_stage1_ranking(
    results: list[ScanResult],
    profile: VlessProfile,
    ws_check: bool,
    timeout: float,
    min_score: int,
    top: int,
    repeats: int,
    concurrency: int,
    phase1_latency_ms: int = PHASE1_LATENCY_MS,
) -> list[ScanResult]:
    """Re-probe the top Stage 1 hits several times to rank them robustly.

    A single-shot Stage 1 measurement is noisy: one lucky fast (or unlucky
    slow) handshake can put an IP on top even though it is average. This pass
    re-tests the top ``top`` candidates ``repeats`` times and keeps, for each,
    the timing of its fastest probe that still passes the phase-1 clean test.

    A candidate is treated as stable when it stays clean on at least a
    majority of probes; unstable ones are pushed to the end so they do not
    shadow genuinely fast, reliable IPs. The full result set is returned with
    its ordering aligned to the re-measured ranking.
    """
    threshold = min(repeats, max(1, repeats // 2 + 1))
    if top <= 0 or repeats <= 0 or not results:
        return results
    semaphore = asyncio.Semaphore(concurrency)

    async def probe(result: ScanResult) -> tuple[ScanResult, int, ScanResult | None]:
        async with semaphore:
            clean_count = 0
            best_clean: ScanResult | None = None
            for _ in range(repeats):
                probe_result = await scan_candidate(
                    result.ip, result.port, profile, timeout, ws_check
                )
                if is_phase1_clean(
                    probe_result, profile, ws_check, min_score, phase1_latency_ms
                ):
                    clean_count += 1
                    if best_clean is None or probe_result.best_ms < best_clean.best_ms:
                        best_clean = probe_result
            return result, clean_count, best_clean

    ranked = best_result_per_ip(sort_results(results))
    top_entries = ranked[:top]
    rest_entries = ranked[top:]

    probed = await asyncio.gather(*(probe(entry) for entry in top_entries))
    stable: list[ScanResult] = []
    unstable: list[ScanResult] = []
    for original, clean_count, best_clean in probed:
        if clean_count >= threshold and best_clean is not None:
            stable.append(best_clean)
        else:
            unstable.append(original)

    ordered_best = (
        sorted(stable, key=lambda item: item.best_ms)
        + sorted(rest_entries, key=lambda item: item.best_ms)
        + sorted(unstable, key=lambda item: item.best_ms)
    )
    print(
        f"Stage 1 recheck: re-measured {len(top_entries)} top hits x{repeats} "
        f"(stable={len(stable)}, unstable={len(unstable)})"
    )

    # Rebuild the full result list following the re-measured per-IP order.
    # The re-measured representative replaces the original single-shot entry
    # so the improved timings propagate to the outputs.
    by_ip: dict[str, list[ScanResult]] = {}
    for result in results:
        by_ip.setdefault(result.ip, []).append(result)
    full: list[ScanResult] = []
    for best in ordered_best:
        entries = sorted(by_ip.pop(best.ip, []), key=lambda item: item.best_ms)
        if entries:
            entries[0] = best
        full.extend(entries)
    leftover = [entry for entries in by_ip.values() for entry in entries]
    return full + leftover


def fmt_mbps(value: float | None) -> str:
    return f"{value:.2f} Mbps" if value is not None else "-"


def parse_ports(raw: str | None, profile_port: int) -> list[int]:
    if not raw:
        return [profile_port]
    if raw.lower() in {"common", "tls"}:
        return DEFAULT_TLS_PORTS
    if raw.lower() in {"http", "plain"}:
        return DEFAULT_HTTP_PORTS
    ports = [int(part.strip()) for part in raw.split(",") if part.strip()]
    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}")
    return ports


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan Cloudflare candidate IPs for a VLESS-over-TLS profile."
    )
    parser.add_argument("--config", help="Your vless:// URL")
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt for the scanner settings step by step instead of using only CLI arguments.",
    )
    parser.add_argument(
        "--candidates", type=Path, help="Optional file with IPs or CIDR ranges to test"
    )
    parser.add_argument(
        "--ports",
        help="Port list such as 443,2083 or 'common'. Default: port from VLESS config",
    )
    parser.add_argument(
        "--sample-per-range",
        type=int,
        default=DEFAULT_SAMPLE_PER_RANGE,
        help="How many random IPs to sample from each CF range",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="Maximum generated candidate IPs",
    )
    parser.add_argument(
        "--seed", type=int, default=20260522, help="Random seed for repeatable samples"
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        choices=range(1, 257),
        metavar="1-256",
        help="Parallel connection attempts",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Per-step timeout in seconds",
    )
    parser.add_argument(
        "--no-ws", action="store_true", help="Skip WebSocket upgrade check"
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Keep scanning generated batches until Ctrl+C. Default scans one small batch and stops.",
    )
    parser.add_argument(
        "--stop-after-hits",
        type=int,
        default=None,
        help="Keep scanning generated batches until this many hits are found, then stop. "
        "Default: stop after the first batch.",
    )
    parser.add_argument(
        "--neighbor-radius",
        type=int,
        default=DEFAULT_NEIGHBOR_RADIUS,
        help="How many /24 blocks around a clean hit to probe next.",
    )
    parser.add_argument(
        "--neighbor-limit",
        type=int,
        default=DEFAULT_NEIGHBOR_LIMIT,
        help="Maximum neighbor IPs to add per round.",
    )
    parser.add_argument(
        "--no-reuse-clean-candidates",
        dest="reuse_clean_candidates",
        action="store_false",
        help="Do not seed the next run with clean IPs saved in out\\clean_candidates.txt.",
    )
    parser.set_defaults(reuse_clean_candidates=True)
    parser.add_argument(
        "--local-fast",
        action="store_true",
        help="Use fast Stage 1 defaults for direct local egress only. This is now the default.",
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Use slow conservative defaults: 20 candidates, concurrency 2, and paced attempts.",
    )
    parser.add_argument(
        "--require-direct-egress",
        action="store_true",
        help="Check public egress IP before scanning and refuse blocked server/VPN exits.",
    )
    parser.add_argument(
        "--blocked-egress-ips",
        default=",".join(DEFAULT_BLOCKED_EGRESS_IPS),
        help="Comma-separated public IPs that must never be used as scan egress.",
    )
    parser.add_argument(
        "--expected-egress-ip",
        help="Optional exact public IP expected before scanning. Refuses to run if different.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Seconds to wait before each connection attempt",
    )
    parser.add_argument(
        "--jitter",
        type=float,
        default=DEFAULT_JITTER,
        help="Extra random delay, in seconds, added before each connection attempt",
    )
    parser.add_argument(
        "--show-failures", action="store_true", help="Print failed candidates too"
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=2,
        choices=range(1, 4),
        metavar="1-3",
        help="Minimum score to print/save as a hit",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=200,
        help="Print quiet progress every N tested endpoints",
    )
    parser.add_argument(
        "--out", type=Path, default=Path("out"), help="Output directory"
    )
    parser.add_argument(
        "--control-dir",
        type=Path,
        help="Optional folder containing stop_stage1.flag and stop_stage2.flag control files.",
    )
    parser.add_argument(
        "--top", type=int, default=20, help="How many best results to print"
    )
    parser.add_argument(
        "--config-count",
        type=int,
        default=10,
        help="How many fastest generated VLESS configs to save/print",
    )
    parser.add_argument(
        "--config-remark",
        help="Optional remark to use after # in generated VLESS configs",
    )
    parser.add_argument(
        "--xray",
        action="store_true",
        help="After Stage 1, validate top candidates with xray-core",
    )
    parser.add_argument(
        "--skip-stage1",
        action="store_true",
        help="Skip Stage 1 scanning. Load clean IPs from the previous run's "
             "results and go straight to Stage 2 validation. "
             "Useful for re-running Stage 2 with different settings.",
    )
    parser.add_argument(
        "--xray-during-scan",
        action="store_true",
        help="Start Stage 2 validation as clean Stage 1 candidates are found.",
    )
    parser.add_argument(
        "--xray-path",
        type=Path,
        help="Path to xray.exe. Default: tools\\xray\\xray.exe or PATH",
    )
    parser.add_argument(
        "--no-install-xray",
        action="store_true",
        help="Do not auto-download xray.exe if missing",
    )
    parser.add_argument(
        "--stage2-count",
        type=int,
        default=100,
        help="How many Stage 1 hits to validate with xray after stopping",
    )
    parser.add_argument(
        "--xray-concurrency",
        type=int,
        default=4,
        choices=range(1, 8),
        metavar="1-7",
        help="How many xray validations to run in parallel",
    )
    parser.add_argument(
        "--recheck",
        action="store_true",
        help="Force the Stage 1 re-measurement ranking pass even in streaming mode.",
    )
    parser.add_argument(
        "--no-recheck",
        dest="recheck",
        action="store_false",
        help="Disable the Stage 1 re-measurement ranking pass.",
    )
    parser.set_defaults(recheck=None)
    parser.add_argument(
        "--recheck-top",
        type=int,
        default=RECHECK_TOP,
        help="How many top Stage 1 hits to re-measure for a robust ranking.",
    )
    parser.add_argument(
        "--recheck-repeats",
        type=int,
        default=RECHECK_REPEATS,
        help="How many times each top hit is re-measured in the ranking pass.",
    )
    parser.add_argument(
        "--recheck-concurrency",
        type=int,
        default=RECHECK_CONCURRENCY,
        help="Parallelism used by the Stage 1 re-measurement ranking pass.",
    )
    parser.add_argument(
        "--phase1-latency-ms",
        type=int,
        default=PHASE1_LATENCY_MS,
        help="Maximum best latency (ms) for a candidate to pass Phase 1 clean test. "
             "Use 0 to disable the latency filter. Default: 1200",
    )
    parser.add_argument(
        "--rank-weight-latency",
        type=float,
        default=RANK_WEIGHT_LATENCY,
        help="Weight of latency when ranking xray-validated candidates.",
    )
    parser.add_argument(
        "--rank-weight-download",
        type=float,
        default=RANK_WEIGHT_DOWNLOAD,
        help="Weight of download speed when ranking xray-validated candidates.",
    )
    parser.add_argument(
        "--rank-weight-upload",
        type=float,
        default=RANK_WEIGHT_UPLOAD,
        help="Weight of upload speed when ranking xray-validated candidates.",
    )
    parser.add_argument(
        "--xray-timeout",
        type=float,
        default=10.0,
        help="Timeout for each xray validation request",
    )
    parser.add_argument(
        "--xray-test-url",
        default="http://cp.cloudflare.com/generate_204",
        help="URL fetched through xray to prove the tunnel works",
    )
    parser.add_argument(
        "--download-url",
        default=DEFAULT_DOWNLOAD_URL,
        help="Optional URL fetched through xray to measure download speed",
    )
    parser.add_argument(
        "--download-bytes",
        type=int,
        default=DEFAULT_TRANSFER_BYTES,
        help="Maximum bytes read for each Stage 2 download measurement (0 = skip)",
    )
    parser.add_argument(
        "--upload-url",
        default=DEFAULT_UPLOAD_URL,
        help="Optional URL that accepts POST data through xray for upload measurement",
    )
    parser.add_argument(
        "--upload-bytes",
        type=int,
        default=DEFAULT_TRANSFER_BYTES,
        help="Bytes posted for each Stage 2 upload measurement (0 = skip)",
    )
    parser.add_argument(
        "--use-system-proxy",
        action="store_true",
        help="Honor the Windows system proxy (e.g. V2rayN). Default: false, so the "
        "scanner uses the direct internet even while a system-wide proxy is active.",
    )
    parser.add_argument(
        "--check-tun",
        action="store_true",
        help="Refuse to scan (exit code 2) if a TUN routing adapter is detected. "
        "Useful to guarantee the scanner never runs while TUN/VPN routing is active.",
    )
    parser.add_argument(
        "--allow-tun",
        action="store_true",
        help="Skip the TUN detection refusal. Only use when the scanner process is "
        "excluded from TUN routing in your VPN client.",
    )
    return parser



def main() -> int:
    args = build_arg_parser().parse_args()
    if args.interactive or not args.config:
        args = collect_interactive_args(args)
    set_system_proxy_mode(getattr(args, "use_system_proxy", False))
    profile = parse_vless_url(args.config)
    ports = parse_ports(args.ports, profile.port)
    if args.safe:
        if args.concurrency == DEFAULT_CONCURRENCY:
            args.concurrency = SAFE_CONCURRENCY
        if args.limit == DEFAULT_LIMIT:
            args.limit = SAFE_LIMIT
        if args.sample_per_range == DEFAULT_SAMPLE_PER_RANGE:
            args.sample_per_range = SAFE_SAMPLE_PER_RANGE
        if args.delay == DEFAULT_DELAY:
            args.delay = SAFE_DELAY
        if args.jitter == DEFAULT_JITTER:
            args.jitter = SAFE_JITTER
    if args.local_fast:
        if args.concurrency == DEFAULT_CONCURRENCY:
            args.concurrency = LOCAL_FAST_CONCURRENCY
        if args.limit == DEFAULT_LIMIT:
            args.limit = LOCAL_FAST_LIMIT
        if args.delay == DEFAULT_DELAY:
            args.delay = LOCAL_FAST_DELAY
        if args.jitter == DEFAULT_JITTER:
            args.jitter = LOCAL_FAST_JITTER
    if args.delay < 0 or args.jitter < 0:
        raise ValueError("--delay and --jitter must be zero or positive")
    if args.timeout <= 0:
        raise ValueError("--timeout must be greater than zero")
    if args.stop_after_hits is not None and args.stop_after_hits < 1:
        raise ValueError("--stop-after-hits must be at least 1")
    if args.neighbor_radius < 0:
        raise ValueError("--neighbor-radius must be zero or positive")
    if args.neighbor_limit < 1:
        raise ValueError("--neighbor-limit must be at least 1")
    if args.xray_timeout <= 0:
        raise ValueError("--xray-timeout must be greater than zero")
    if args.download_bytes < 0 or args.upload_bytes < 0:
        raise ValueError("--download-bytes and --upload-bytes must be zero or positive")
    if args.recheck_top < 1:
        raise ValueError("--recheck-top must be at least 1")
    if args.recheck_repeats < 1:
        raise ValueError("--recheck-repeats must be at least 1")
    if args.recheck_concurrency < 1:
        raise ValueError("--recheck-concurrency must be at least 1")
    if min(
        args.rank_weight_latency, args.rank_weight_download, args.rank_weight_upload
    ) < 0:
        raise ValueError("--rank-weight-* must be zero or positive")
    set_rank_weights(
        args.rank_weight_latency, args.rank_weight_download, args.rank_weight_upload
    )
    if args.phase1_latency_ms < 0:
        raise ValueError("--phase1-latency-ms must be zero or positive")
    # The re-measurement ranking pass is on by default whenever a normal
    # (non-streaming) Stage 2 run will pick the candidates to validate.
    run_recheck = args.recheck if args.recheck is not None else (
        args.xray and not args.xray_during_scan
    )
    if args.control_dir:
        args.control_dir.mkdir(parents=True, exist_ok=True)
    if args.check_tun:
        stop_code = ensure_tun_not_active(refuse_on_tun=True)
        if stop_code is not None:
            return stop_code
    elif not args.allow_tun:
        ensure_tun_not_active(refuse_on_tun=False)
    blocked_egress_ips = parse_ip_list(args.blocked_egress_ips)
    if args.expected_egress_ip:
        ipaddress.ip_address(args.expected_egress_ip)
    egress_ip = None
    if args.require_direct_egress:
        egress_ip = detect_public_egress_ip()
        if egress_ip in blocked_egress_ips:
            print(
                f"Refusing to scan: current public egress IP is blocked ({egress_ip}). "
                "Turn off VPN/TUN/proxy routing or change --blocked-egress-ips."
            )
            return 2
        if args.expected_egress_ip and egress_ip != args.expected_egress_ip:
            print(
                f"Refusing to scan: current public egress IP is {egress_ip}, "
                f"but --expected-egress-ip is {args.expected_egress_ip}."
            )
            return 2
    project_dir = Path(__file__).resolve().parent
    xray_path = None
    if args.xray:
        xray_path = find_xray(project_dir, args.xray_path)
        if not xray_path:
            if args.no_install_xray:
                print(
                    "Xray was requested, but xray.exe was not found. Remove --no-install-xray or pass --xray-path."
                )
                return 2
            xray_path = install_xray(project_dir)

    if args.candidates:
        candidates = load_candidates(args.candidates)
        ranges = None
        source = str(args.candidates)
    else:
        ranges, source = fetch_cloudflare_ipv4_ranges()
        candidates = sample_from_ranges(
            ranges, args.sample_per_range, args.limit, args.seed
        )
    if args.reuse_clean_candidates:
        cached_clean = load_cached_clean_candidates(args.out)
        if cached_clean:
            candidates = unique_in_order(cached_clean + candidates)
            source = f"{source} + cached clean candidates"

    # When --skip-stage1 is given, skip the Stage 1 scan entirely and use the
    # clean IPs already saved in the output folder for Stage 2 validation.
    results: list[ScanResult] = []
    if args.skip_stage1:
        results = load_live_hits(args.out)
        if not results:
            print(
                "Skip Stage 1 was requested, but no clean IPs were found in "
                f"{args.out}. Run a normal Stage 1 scan first."
            )
            return 2
        print(f"Skip Stage 1: using {len(results)} saved clean IPs from {args.out}")

    stage2_pipeline = None
    if args.xray and xray_path and args.xray_during_scan and not args.skip_stage1:
        stage2_pipeline = XrayStage2Pipeline(
            profile=profile,
            xray_path=xray_path,
            stage2_count=args.stage2_count,
            xray_concurrency=args.xray_concurrency,
            test_url=args.xray_test_url,
            timeout=args.xray_timeout,
            out_dir=args.out,
            config_count=args.config_count,
            config_remark=args.config_remark,
            download_url=args.download_url,
            download_bytes=args.download_bytes,
            upload_url=args.upload_url,
            upload_bytes=args.upload_bytes,
            should_stop=lambda: stage_stop_requested(args.control_dir, "stage2"),
        )

    print("MehrScanner")
    print("-" * 72)
    print(f"Original address : {profile.original_address}:{profile.port}")
    print(f"SNI / Host       : {profile.sni} / {profile.host}")
    print(f"Transport/path   : {profile.transport or '-'} {profile.path}")
    if egress_ip:
        print(f"Public egress IP : {egress_ip}")
    print(f"Candidates       : {len(candidates)} from {source}")
    print(f"Ports            : {', '.join(str(port) for port in ports)}")
    keeps_scanning = args.continuous or args.stop_after_hits is not None
    print(
        f"Mode             : {'until hit limit' if args.stop_after_hits is not None else 'continuous until Ctrl+C' if args.continuous else 'one small batch'}"
    )
    if args.stop_after_hits is not None:
        print(f"Hit limit        : {args.stop_after_hits}")
    if args.local_fast:
        print("Local fast       : enabled; use only when VPN/proxy/TUN routing is off")
    print(
        f"Pacing           : concurrency={args.concurrency}, delay={args.delay}s, jitter={args.jitter}s"
    )
    print("Stop key         : Ctrl+C")
    print("-" * 72)

    try:
        if args.skip_stage1:
            # Skip the Stage 1 scan; go straight to Stage 2 validation.
            results = sort_results(results)
        else:
            results = asyncio.run(
                run_scan(
                    profile=profile,
                    candidates=candidates,
                    ranges=ranges,
                    sample_per_range=args.sample_per_range,
                    limit=args.limit,
                    seed=args.seed,
                    ports=ports,
                    concurrency=max(1, args.concurrency),
                    timeout=args.timeout,
                    ws_check=not args.no_ws,
                    min_score=args.min_score,
                    phase1_latency_ms=args.phase1_latency_ms,
                    neighbor_radius=args.neighbor_radius,
                    neighbor_limit=args.neighbor_limit,
                    show_failures=args.show_failures,
                    progress_every=args.progress_every,
                    delay=args.delay,
                    jitter=args.jitter,
                    continuous=keeps_scanning,
                    stop_after_hits=args.stop_after_hits,
                    out_dir=args.out,
                    on_clean=stage2_pipeline.submit if stage2_pipeline else None,
                    should_stop=lambda: stage_stop_requested(args.control_dir, "stage1"),
                )
            )
        if args.recheck and not args.skip_stage1 and results:
            results = asyncio.run(
                recheck_stage1_ranking(
                    results=results,
                    profile=profile,
                    ws_check=not args.no_ws,
                    timeout=args.timeout,
                    min_score=args.min_score,
                    phase1_latency_ms=args.phase1_latency_ms,
                    top=args.recheck_top,
                    repeats=args.recheck_repeats,
                    concurrency=args.recheck_concurrency,
                )
            )

    except KeyboardInterrupt:
        print("\nStopped by user.")
        results = load_live_hits(args.out)
        if results:
            write_outputs(
                results, args.out, profile, args.config_count, args.config_remark,
                min_score=args.min_score,
            )
            print_summary(results, args.top, min_score=args.min_score)
            if stage2_pipeline:
                validations = stage2_pipeline.finish()
                print_xray_summary(
                    validations,
                    profile,
                    args.config_count,
                    args.config_remark,
                )
            elif args.xray and xray_path:
                validations = run_xray_stage2(
                    results=results,
                    profile=profile,
                    xray_path=xray_path,
                    stage2_count=args.stage2_count,
                    xray_concurrency=args.xray_concurrency,
                    test_url=args.xray_test_url,
                    timeout=args.xray_timeout,
                    out_dir=args.out,
                    config_count=args.config_count,
                    config_remark=args.config_remark,
                    download_url=args.download_url,
                    download_bytes=args.download_bytes,
                    upload_url=args.upload_url,
                    upload_bytes=args.upload_bytes,
                    should_stop=lambda: stage_stop_requested(args.control_dir, "stage2"),
                    min_score=args.min_score,
                )
                print_xray_summary(
                    validations,
                    profile,
                    args.config_count,
                    args.config_remark,
                )
            print(f"\nSaved: {args.out.resolve()}")
        else:
            print("No hits were found before stopping.")
        return 130

    write_outputs(
        results, args.out, profile, args.config_count, args.config_remark,
        min_score=args.min_score,
    )
    print_summary(results, args.top, min_score=args.min_score)
    if stage2_pipeline:
        validations = stage2_pipeline.finish()
        print_xray_summary(
            validations,
            profile,
            args.config_count,
            args.config_remark,
        )
    elif args.xray and xray_path:
        validations = run_xray_stage2(
            results=results,
            profile=profile,
            xray_path=xray_path,
            stage2_count=args.stage2_count,
            xray_concurrency=args.xray_concurrency,
            test_url=args.xray_test_url,
            timeout=args.xray_timeout,
            out_dir=args.out,
            config_count=args.config_count,
            config_remark=args.config_remark,
            download_url=args.download_url,
            download_bytes=args.download_bytes,
            upload_url=args.upload_url,
            upload_bytes=args.upload_bytes,
            should_stop=lambda: stage_stop_requested(args.control_dir, "stage2"),
            min_score=args.min_score,
        )
        print_xray_summary(
            validations,
            profile,
            args.config_count,
            args.config_remark,
        )
    print(f"\nSaved: {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
