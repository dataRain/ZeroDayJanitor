#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List

from scanlib import (
    C, Finding, Reporter, any_regex_match, compile_regex_list, fail_threshold_met,
    iter_files, load_toml_config, make_arg_parser, merge_section,
    read_text_file, redact_text, now_stamp
)

# comment suppression
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

# generic request-sources (ASP.NET / ASP.NET Core)
REQUEST_SRC_RE = re.compile(
    r"(?i)\b("
    r"Request\.(QueryString|Form|Headers|Cookies)|"
    r"Request\[\s*\"|Request\[\s*'|"
    r"HttpContext\.Current\.Request|"
    r"HttpContext\.Request|"
    r"context\.Request"
    r")\b"
)

# dangerous sinks
PROCESS_SINK_RE = re.compile(r"(?i)\b(Process\.Start|cmd\.exe|powershell|pwsh)\b")
DYNAMIC_LOAD_RE = re.compile(r"(?i)\b(Assembly\.(Load|LoadFrom|LoadFile)|CodeDomProvider|CSharpCodeProvider|Microsoft\.CodeAnalysis|CSharpCompilation)\b")
FILE_DROP_RE = re.compile(r"(?i)\b(File\.Write(AllText|AllBytes)|FileStream|SaveAs|WriteAllText|WriteAllBytes)\b")
SUSP_EXT_RE = re.compile(r"(?i)\.(aspx|ashx|asmx|cshtml)\b")

# common webshell-ish param keys
DEFAULT_SUSP_PARAM_RX = [
    r"(?i)\b(cmd|command|exec|execute|shell|powershell|pwsh|ps|payload|upload|uploader|file|path)\b"
]

RULES: List[Dict] = [
    # Request -> Process.Start / cmd / powershell (very high signal)
    {"id": "REQ_TO_PROC", "sev": "HIGH", "kind": "WEBSHELL", "rx": r"(?i)\bRequest\b.*\b(Process\.Start|cmd\.exe|powershell|pwsh)\b|\b(Process\.Start|cmd\.exe|powershell|pwsh)\b.*\bRequest\b"},

    # Request -> dynamic compile/load (very high signal)
    {"id": "REQ_TO_DYNLOAD", "sev": "HIGH", "kind": "WEBSHELL", "rx": r"(?i)\bRequest\b.*\b(Assembly\.(Load|LoadFrom|LoadFile)|CodeDomProvider|CSharpCodeProvider|Microsoft\.CodeAnalysis|CSharpCompilation)\b"},

    # File dropper writing .aspx/.ashx/etc (high signal)
    {"id": "DROP_WEB_EXT", "sev": "HIGH", "kind": "WEBSHELL", "rx": r"(?i)\b(File\.Write(AllText|AllBytes)|SaveAs)\b.*\.(aspx|ashx|asmx|cshtml)\b|\.(aspx|ashx|asmx|cshtml)\b.*\b(File\.Write(AllText|AllBytes)|SaveAs)\b"},

    # PowerShell automation in app code (often suspicious in web apps)
    {"id": "POWERSHELL_AUTOMATION", "sev": "HIGH", "kind": "WEBSHELL", "rx": r"(?i)\bSystem\.Management\.Automation\b|\bPowerShell\.Create\s*\("},

    # “plumbing” indicators (MEDIUM/LOW, meant for correlation)
    {"id": "REQUEST_SOURCE", "sev": "LOW", "kind": "WEB_INPUT", "rx": REQUEST_SRC_RE.pattern},
    {"id": "PROCESS_SINK", "sev": "MEDIUM", "kind": "DANGEROUS_SINK", "rx": PROCESS_SINK_RE.pattern},
    {"id": "DYNAMIC_LOAD", "sev": "MEDIUM", "kind": "DANGEROUS_SINK", "rx": DYNAMIC_LOAD_RE.pattern},
    {"id": "FILE_WRITE", "sev": "MEDIUM", "kind": "DANGEROUS_SINK", "rx": FILE_DROP_RE.pattern},
    {"id": "SUSP_WEB_EXT", "sev": "LOW", "kind": "WEB_ARTIFACT", "rx": SUSP_EXT_RE.pattern},
]

def main() -> int:
    ap = make_arg_parser("scan_webshell_indicators.py")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    cfg_all = load_toml_config(Path(args.config))
    cfg = merge_section(cfg_all, "webshells")
    gen = cfg_all.get("general", {})

    exclude_dirs = gen.get("exclude_dirs", [])
    exclude_globs = gen.get("exclude_globs", [])
    include_exts = gen.get("include_exts", [])
    max_mb = int(gen.get("max_file_size_mb", 5))
    max_bytes = max_mb * 1024 * 1024

    allow_line_rx = compile_regex_list(cfg.get("allow_line_regex", []))
    disabled = set(cfg.get("disable_rule_ids", []))

    # Optional extra “suspicious parameter names” regex list from config
    susp_param_rx_list = cfg.get("suspicious_param_name_regex", DEFAULT_SUSP_PARAM_RX)
    susp_param_rx = compile_regex_list(susp_param_rx_list)

    compiled_rules = []
    for r in RULES:
        if r["id"] in disabled:
            continue
        try:
            compiled_rules.append({**r, "cre": re.compile(r["rx"])})
        except re.error:
            continue

    out_path = Path(args.out) if args.out else Path(f"webshell_report_{now_stamp()}.txt")
    rep = Reporter(out_path, color=(not args.no_color), no_banner=args.no_banner)

    rep.header(f"Webshell Indicator Scan — root={root}")
    rep.emit(f"{C.DIM}Rules enabled: {len(compiled_rules)} (disable via [webshells].disable_rule_ids){C.RESET}")

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

            # extra heuristic: suspicious param names on lines that also touch Request
            if REQUEST_SRC_RE.search(line) and any_regex_match(susp_param_rx, line):
                findings.append(Finding("MEDIUM", p, i, "WEB_INPUT:SUSP_PARAM_NAME", "suspicious_param_name_regex", line))

            for r in compiled_rules:
                if r["cre"].search(line):
                    findings.append(Finding(r["sev"], p, i, f"{r['kind']}:{r['id']}", r["rx"], line))

    if not findings:
        rep.ok(f"No webshell indicators matched. Scanned {scanned_files} files.")
    else:
        rep.warn(f"Matched {len(findings)} webshell indicators in {scanned_files} files.\n")
        for f in findings[:5000]:
            sev_color = C.RED if f.severity == "HIGH" else (C.YELLOW if f.severity == "MEDIUM" else C.MAGENTA)
            rep.emit(f"{sev_color}{f.severity:<6}{C.RESET} {f.kind:<30} {f.file}:{f.line}")
            rep.emit(f"        {C.DIM}ctx: {redact_text(f.context, max_len=260)}{C.RESET}")
        if len(findings) > 5000:
            rep.warn("Output truncated: showing first 5000 findings.")

    rep.header("Allow-list (webshells) used for this run")
    rep.emit(f"{C.CYAN}allow_line_regex:{C.RESET} {', '.join(cfg.get('allow_line_regex', [])) if cfg.get('allow_line_regex', []) else '(none)'}")
    rep.emit(f"{C.CYAN}disable_rule_ids:{C.RESET} {', '.join(cfg.get('disable_rule_ids', [])) if cfg.get('disable_rule_ids', []) else '(none)'}")
    rep.emit(f"{C.CYAN}suspicious_param_name_regex:{C.RESET} {', '.join(susp_param_rx_list) if susp_param_rx_list else '(none)'}")

    rep.close()
    return 1 if fail_threshold_met(findings, args.fail_on) else 0

if __name__ == "__main__":
    sys.exit(main())
