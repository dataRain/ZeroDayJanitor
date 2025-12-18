#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Tuple

from scanlib import (
    C, Finding, Reporter, any_regex_match, compile_regex_list, fail_threshold_met,
    iter_files, load_toml_config, make_arg_parser, merge_section, is_whitelisted,
    read_text_file, redact_text, now_stamp,
)

# URL-ish schemes + common DB/connectivity schemes
URL_RE = re.compile(
    r"\b("
    r"(?:(?:https?|wss?|ftp|sftp|ssh|git|ldap|ldaps|amqp|amqps|mqtt|nats)://[^\s'\"<>]+)"
    r"|(?:jdbc:(?:mysql|postgresql|sqlserver|oracle):[^\s'\"<>]+)"
    r"|(?:mongodb(?:\+srv)?://[^\s'\"<>]+)"
    r"|(?:redis(?:\+ssl)?://[^\s'\"<>]+)"
    r"|(?:postgres(?:ql)?://[^\s'\"<>]+)"
    r"|(?:mysql://[^\s'\"<>]+)"
    r"|(?:net\.tcp://[^\s'\"<>]+)"
    r")",
    re.IGNORECASE
)

# scp-like git form: git@host:org/repo.git
GIT_SCP_RE = re.compile(r"\bgit@[\w.\-]+:[\w./\-]+", re.IGNORECASE)

# IPv4 (validated-ish)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")

# IPv6 (stricter):
#  - bracketed form: [2001:db8::1]
#  - raw form: 2001:db8::1 or 2001:0db8:85a3:0000:0000:8a2e:0370:7334
#  - avoids empty-groups like ::after because groups require 1-4 hex chars
IPV6_BRACKET_RE = re.compile(r"\[[0-9A-Fa-f:]{2,}\]")
IPV6_RAW_RE = re.compile(
    r"\b("
    r"::1"
    r"|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"           # trailing ::
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"           # leading ::
    r")\b"
)

# UNC shares: \\server\share (and variants)
UNC_RE = re.compile(r"\\\\(?:[A-Za-z0-9._-]+)\\\\(?:[A-Za-z0-9.$_-]+)")

# SMB/NFS file URIs
FILEURI_RE = re.compile(r"\bfile://[^\s'\"<>]+", re.IGNORECASE)
SMB_RE = re.compile(r"\bsmb://[^\s'\"<>]+", re.IGNORECASE)
NFS_RE = re.compile(r"\bnfs://[^\s'\"<>]+", re.IGNORECASE)

REMOTE_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("URL", URL_RE, "MEDIUM"),
    ("GIT_SCP", GIT_SCP_RE, "MEDIUM"),
    ("FILE_URI", FILEURI_RE, "MEDIUM"),
    ("SMB", SMB_RE, "MEDIUM"),
    ("NFS", NFS_RE, "MEDIUM"),
    ("UNC_SHARE", UNC_RE, "MEDIUM"),
    ("IPV4", IPV4_RE, "MEDIUM"),
    # IPV6 is handled separately (because we want extra filtering)
]

# --- Noise suppression helpers (these dramatically reduce false positives) ---

_VERSION_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"contentVersion"
    r"|assemblyversion"
    r"|fileversion"
    r"|informationalversion"
    r"|productversion"
    r"|version\s*=\s*\d+\.\d+\.\d+\.\d+"
    r"|version\s*[:=]\s*\"?\d+\.\d+\.\d+\.\d+\"?"
    r")\b"
)

def ipv4_looks_like_version(line: str) -> bool:
    # If the line declares a version in a context common to .NET/ARM tooling,
    # treat x.x.x.x as a version, not an IP.
    return bool(_VERSION_CONTEXT_RE.search(line))

def ipv6_is_likely_real(s: str) -> bool:
    # s may be bracketed like [2001:db8::1]
    raw = s[1:-1] if (s.startswith("[") and s.endswith("]")) else s

    # Quick rejects for common false positives
    # - timestamps like 14:37:52 => only 2 colons
    # - CSS pseudo elements are prevented by regex, but keep defense-in-depth
    if raw.count(":") < 3 and "::" not in raw and raw != "::1":
        return False
    if raw.lower() in ("::after", "::before"):
        return False

    # If it has '::', it’s very likely intended as IPv6
    if "::" in raw or raw == "::1":
        return True

    # Otherwise require some evidence it's not a time:
    # - any group length >= 3 (times are usually 2-digit groups)
    groups = [g for g in raw.split(":") if g]
    if any(len(g) >= 3 for g in groups):
        return True

    return False

def main() -> int:
    ap = make_arg_parser("scan_remote_refs.py")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    cfg_all = load_toml_config(Path(args.config))
    cfg = merge_section(cfg_all, "remote_refs")
    gen = cfg_all.get("general", {})

    exclude_dirs = gen.get("exclude_dirs", [])
    exclude_globs = gen.get("exclude_globs", [])
    include_exts = gen.get("include_exts", [])
    max_mb = int(gen.get("max_file_size_mb", 5))
    max_bytes = max_mb * 1024 * 1024

    wl_sub = cfg.get("whitelist_substrings", [])
    wl_rx = compile_regex_list(cfg.get("whitelist_regex", []))
    ignore_line_rx = compile_regex_list(cfg.get("ignore_line_regex", []))

    out_path = Path(args.out) if args.out else Path(f"remote_refs_report_{now_stamp()}.txt")
    rep = Reporter(out_path, color=(not args.no_color))

    rep.header(f"Remote Reference Scan — root={root}")
    if not root.exists():
        rep.bad(f"Root path does not exist: {root}")
        rep.close()
        return 2

    findings: List[Finding] = []
    scanned_files = 0

    for p in iter_files(root, exclude_dirs, exclude_globs, include_exts, max_bytes):
        scanned_files += 1
        text = read_text_file(p)

        for i, line in enumerate(text.splitlines(), start=1):
            if any_regex_match(ignore_line_rx, line):
                continue

            # Standard patterns
            for kind, rx, sev in REMOTE_PATTERNS:
                for m in rx.finditer(line):
                    val = m.group(0)

                    # Suppress IPv4 that is clearly a version string in common contexts
                    if kind == "IPV4" and ipv4_looks_like_version(line):
                        continue

                    if is_whitelisted(val, wl_sub, wl_rx):
                        continue
                    findings.append(Finding(sev, p, i, kind, val, line))

            # IPv6 patterns (stricter + post-filter)
            for m in IPV6_BRACKET_RE.finditer(line):
                val = m.group(0)
                if not ipv6_is_likely_real(val):
                    continue
                if is_whitelisted(val, wl_sub, wl_rx):
                    continue
                findings.append(Finding("LOW", p, i, "IPV6", val, line))

            for m in IPV6_RAW_RE.finditer(line):
                val = m.group(0)
                if not ipv6_is_likely_real(val):
                    continue
                if is_whitelisted(val, wl_sub, wl_rx):
                    continue
                findings.append(Finding("LOW", p, i, "IPV6", val, line))

    if not findings:
        rep.ok(f"No non-whitelisted remote references found. Scanned {scanned_files} files.")
    else:
        rep.bad(f"Found {len(findings)} potential remote references in {scanned_files} files.\n")
        for f in findings[:5000]:
            sev_color = C.RED if f.severity == "HIGH" else (C.YELLOW if f.severity == "MEDIUM" else C.MAGENTA)
            rep.emit(f"{sev_color}{f.severity:<6}{C.RESET} {f.kind:<10} {f.file}:{f.line}  match={redact_text(f.match)}")
            rep.emit(f"        {C.DIM}ctx: {redact_text(f.context, max_len=220)}{C.RESET}")
        if len(findings) > 5000:
            rep.warn("Output truncated: showing first 5000 findings.")

    rep.header("Whitelist (remote_refs) used for this run")
    if wl_sub:
        rep.emit(f"{C.CYAN}whitelist_substrings:{C.RESET} {', '.join(wl_sub)}")
    else:
        rep.emit(f"{C.CYAN}whitelist_substrings:{C.RESET} (none)")
    if cfg.get("whitelist_regex", []):
        rep.emit(f"{C.CYAN}whitelist_regex:{C.RESET} {', '.join(cfg.get('whitelist_regex', []))}")
    else:
        rep.emit(f"{C.CYAN}whitelist_regex:{C.RESET} (none)")

    rep.close()

    return 1 if fail_threshold_met(findings, args.fail_on) else 0

if __name__ == "__main__":
    sys.exit(main())
