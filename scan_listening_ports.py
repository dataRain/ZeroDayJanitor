#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

from scanlib import (
    C, Finding, Reporter, any_regex_match, compile_regex_list, fail_threshold_met,
    iter_files, load_toml_config, make_arg_parser, merge_section,
    read_text_file, redact_text, now_stamp
)

# --- comment suppression (reduces noise a lot) ---
LINE_COMMENT_RE = re.compile(r"^\s*//")
XML_COMMENT_RE = re.compile(r"^\s*<!--")
HASH_COMMENT_RE = re.compile(r"^\s*#")
BLOCK_COMMENT_START_RE = re.compile(r"/\*")
BLOCK_COMMENT_END_RE = re.compile(r"\*/")

def is_comment_only_line(line: str, in_block: bool) -> tuple[bool, bool]:
    s = line.strip()
    if in_block:
        if BLOCK_COMMENT_END_RE.search(s):
            return True, False
        return True, True
    if BLOCK_COMMENT_START_RE.search(s) and not BLOCK_COMMENT_END_RE.search(s):
        return True, True
    if LINE_COMMENT_RE.match(s) or XML_COMMENT_RE.match(s) or HASH_COMMENT_RE.match(s):
        return True, False
    return False, False


def _parse_ports_from_line(line: str) -> List[int]:
    ports: Set[int] = set()

    # common patterns: ListenAnyIP(5000), ListenLocalhost(5001), new TcpListener(..., 1234)
    for m in re.finditer(r"\b(?:ListenAnyIP|ListenLocalhost|Listen|TcpListener)\s*\(\s*(?:[^,]+,\s*)?(?P<p>\d{2,5})\s*\)", line):
        p = int(m.group("p"))
        if 1 <= p <= 65535:
            ports.add(p)

    # UseUrls("http://*:5000;https://localhost:5001")
    for m in re.finditer(r":(?P<p>\d{2,5})\b", line):
        p = int(m.group("p"))
        if 1 <= p <= 65535:
            ports.add(p)

    # HttpListener prefixes: "http://*:8080/" or "http://localhost:5000/"
    for m in re.finditer(r"(?i)\bhttp://\*:(?P<p>\d{2,5})\b", line):
        p = int(m.group("p"))
        if 1 <= p <= 65535:
            ports.add(p)

    return sorted(ports)


RULES: List[Dict] = [
    # --- Higher-signal “non-webserver” listeners ---
    {"id": "TCPLISTENER_NEW", "sev": "MEDIUM", "kind": "LISTENER", "rx": r"\bnew\s+TcpListener\s*\("},
    {"id": "TCPLISTENER_START", "sev": "MEDIUM", "kind": "LISTENER", "rx": r"\bTcpListener\b.*\bStart\s*\("},

    {"id": "SOCKET_BIND", "sev": "MEDIUM", "kind": "LISTENER", "rx": r"\bSocket\b.*\bBind\s*\("},
    {"id": "SOCKET_LISTEN", "sev": "MEDIUM", "kind": "LISTENER", "rx": r"\bSocket\b.*\bListen\s*\("},

    {"id": "HTTPLISTENER", "sev": "MEDIUM", "kind": "LISTENER", "rx": r"\bHttpListener\b"},
    {"id": "HTTPLISTENER_PREFIX", "sev": "HIGH", "kind": "LISTENER", "rx": r"(?i)\bHttpListener\b.*\bPrefixes\b|\bPrefixes\.Add\s*\("},

    {"id": "NAMEDPIPE_SERVER", "sev": "MEDIUM", "kind": "IPC_SERVER", "rx": r"\bNamedPipeServerStream\b"},
    {"id": "GRPC_SERVER", "sev": "MEDIUM", "kind": "LISTENER", "rx": r"(?i)\bGrpc\b.*\bServer\b|\bMapGrpcService\b"},

    # --- ASP.NET hosting (usually expected, keep informational by default) ---
    {"id": "KESTREL_CFG", "sev": "LOW", "kind": "WEB_HOSTING", "rx": r"(?i)\bUseKestrel\b|\bConfigureKestrel\b"},
    {"id": "KESTREL_LISTENANYIP", "sev": "LOW", "kind": "WEB_HOSTING", "rx": r"\bListenAnyIP\s*\("},
    {"id": "KESTREL_LISTENLOCALHOST", "sev": "LOW", "kind": "WEB_HOSTING", "rx": r"\bListenLocalhost\s*\("},
    {"id": "USEURLS", "sev": "LOW", "kind": "WEB_HOSTING", "rx": r"\bUseUrls\s*\("},
    {"id": "ASPNETCORE_URLS", "sev": "LOW", "kind": "WEB_HOSTING", "rx": r"(?i)\bASPNETCORE_URLS\b"},
]

def main() -> int:
    ap = make_arg_parser("scan_listening_ports.py")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    cfg_all = load_toml_config(Path(args.config))
    cfg = merge_section(cfg_all, "listening_ports")
    gen = cfg_all.get("general", {})

    exclude_dirs = gen.get("exclude_dirs", [])
    exclude_globs = gen.get("exclude_globs", [])
    include_exts = gen.get("include_exts", [])
    max_mb = int(gen.get("max_file_size_mb", 5))
    max_bytes = max_mb * 1024 * 1024

    allow_line_rx = compile_regex_list(cfg.get("allow_line_regex", []))
    disabled = set(cfg.get("disable_rule_ids", []))
    whitelist_ports = set(int(x) for x in cfg.get("whitelist_ports", []) if str(x).isdigit())

    compiled_rules = []
    for r in RULES:
        if r["id"] in disabled:
            continue
        try:
            compiled_rules.append({**r, "cre": re.compile(r["rx"])})
        except re.error:
            continue

    out_path = Path(args.out) if args.out else Path(f"listening_ports_report_{now_stamp()}.txt")
    rep = Reporter(out_path, color=(not args.no_color))

    rep.header(f"Listening Port / Local Bind Scan — root={root}")
    rep.emit(f"{C.DIM}Rules enabled: {len(compiled_rules)} (disable via [listening_ports].disable_rule_ids){C.RESET}")

    if not root.exists():
        rep.bad(f"Root path does not exist: {root}")
        rep.close()
        return 2

    findings: List[Finding] = []
    scanned_files = 0

    for p in iter_files(root, exclude_dirs, exclude_globs, include_exts, max_bytes):
        scanned_files += 1
        text = read_text_file(p)

        in_block = False
        for i, line in enumerate(text.splitlines(), start=1):
            if any_regex_match(allow_line_rx, line):
                continue

            skip, in_block = is_comment_only_line(line, in_block)
            if skip:
                continue

            for r in compiled_rules:
                if not r["cre"].search(line):
                    continue

                ports = _parse_ports_from_line(line)
                if ports and whitelist_ports and all(pn in whitelist_ports for pn in ports):
                    # If all extracted ports are explicitly allowed, downgrade to LOW and tag
                    sev = "LOW"
                    kind = f"{r['kind']}:{r['id']}:WHITELISTED_PORT"
                else:
                    sev = r["sev"]
                    kind = f"{r['kind']}:{r['id']}"

                match = f"ports={ports}" if ports else r["rx"]
                findings.append(Finding(sev, p, i, kind, match, line))

    if not findings:
        rep.ok(f"No listening/bind patterns matched. Scanned {scanned_files} files.")
    else:
        rep.warn(f"Matched {len(findings)} listening/bind patterns in {scanned_files} files.\n")
        for f in findings[:5000]:
            sev_color = C.RED if f.severity == "HIGH" else (C.YELLOW if f.severity == "MEDIUM" else C.MAGENTA)
            rep.emit(f"{sev_color}{f.severity:<6}{C.RESET} {f.kind:<34} {f.file}:{f.line}")
            rep.emit(f"        {C.DIM}ctx: {redact_text(f.context, max_len=240)}{C.RESET}")
            rep.emit(f"        {C.DIM}match: {redact_text(f.match, max_len=180)}{C.RESET}")
        if len(findings) > 5000:
            rep.warn("Output truncated: showing first 5000 findings.")

    rep.header("Allow-list (listening_ports) used for this run")
    rep.emit(f"{C.CYAN}allow_line_regex:{C.RESET} {', '.join(cfg.get('allow_line_regex', [])) if cfg.get('allow_line_regex', []) else '(none)'}")
    rep.emit(f"{C.CYAN}disable_rule_ids:{C.RESET} {', '.join(cfg.get('disable_rule_ids', [])) if cfg.get('disable_rule_ids', []) else '(none)'}")
    rep.emit(f"{C.CYAN}whitelist_ports:{C.RESET} {', '.join(str(x) for x in sorted(whitelist_ports)) if whitelist_ports else '(none)'}")

    rep.close()
    return 1 if fail_threshold_met(findings, args.fail_on) else 0

if __name__ == "__main__":
    sys.exit(main())
