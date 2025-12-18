#!/usr/bin/env python3
from __future__ import annotations

import base64
import binascii
import re
import sys
from pathlib import Path
from typing import List

from scanlib import (
    C, Finding, Reporter, any_regex_match, compile_regex_list, fail_threshold_met,
    iter_files, load_toml_config, make_arg_parser, merge_section, is_whitelisted,
    read_text_file, redact_text, sha256_hex, now_stamp
)

# base64 candidates (standard + urlsafe); keep conservative-ish
B64_CANDIDATE_RE = re.compile(r"(?P<b64>[A-Za-z0-9+/=_-]{20,})")

# Reuse remote indicators (simplified) for decoded payloads
URL_IN_TEXT_RE = re.compile(r"\b(?:https?|wss?|ftp|sftp|ssh)://[^\s'\"<>]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")


def looks_printable(b: bytes) -> bool:
    if not b:
        return False
    # Count typical printable + whitespace
    printable = sum((32 <= x <= 126) or x in (9, 10, 13) for x in b)
    return (printable / len(b)) >= 0.85


def safe_b64_decode(s: str) -> bytes | None:
    s2 = s.strip()
    # pad if needed
    s2 += "=" * ((-len(s2)) % 4)

    # Try strict standard base64
    try:
        return base64.b64decode(s2, validate=True)
    except (binascii.Error, ValueError):
        pass

    # Try strict URL-safe base64 (supports '-' and '_' via altchars)
    try:
        return base64.b64decode(s2, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None


def main() -> int:
    ap = make_arg_parser("scan_base64_strings.py")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    cfg_all = load_toml_config(Path(args.config))
    cfg = merge_section(cfg_all, "base64")
    gen = cfg_all.get("general", {})

    exclude_dirs = gen.get("exclude_dirs", [])
    exclude_globs = gen.get("exclude_globs", [])
    include_exts = gen.get("include_exts", [])
    max_mb = int(gen.get("max_file_size_mb", 5))
    max_bytes = max_mb * 1024 * 1024

    min_len = int(cfg.get("min_length", 40))
    max_len = int(cfg.get("max_length", 2000))

    wl_sub = cfg.get("whitelist_substrings", [])
    wl_rx = compile_regex_list(cfg.get("whitelist_regex", []))
    ignore_line_rx = compile_regex_list(cfg.get("ignore_line_regex", []))

    cred_kw_rx = compile_regex_list(cfg.get("credential_keyword_regex", []))

    out_path = Path(args.out) if args.out else Path(f"base64_report_{now_stamp()}.txt")
    rep = Reporter(out_path, color=(not args.no_color))

    rep.header(f"Base64 Decode Scan — root={root}")
    if not root.exists():
        rep.bad(f"Root path does not exist: {root}")
        rep.close()
        return 2

    findings: List[Finding] = []
    scanned_files = 0

    for p in iter_files(root, exclude_dirs, exclude_globs, include_exts, max_bytes):
        scanned_files += 1
        text = read_text_file(p)
        lines = text.splitlines()

        # Search whole file to catch blobs not neatly per-line
        for m in B64_CANDIDATE_RE.finditer(text):
            b64s = m.group("b64")
            if len(b64s) < min_len or len(b64s) > max_len:
                continue

            # determine line for reporting
            line_no = text.count("\n", 0, m.start()) + 1

            # ignore-line rule (apply to the actual line containing the start)
            line_text = lines[line_no - 1] if 0 <= (line_no - 1) < len(lines) else ""
            if any_regex_match(ignore_line_rx, line_text):
                continue

            decoded = safe_b64_decode(b64s)
            if not decoded:
                continue

            # Only meaningfully scan printable decodes (avoid random binary spam)
            if not looks_printable(decoded):
                continue

            decoded_text = decoded.decode("utf-8", errors="replace")

            # Look for indicators
            has_remote = bool(URL_IN_TEXT_RE.search(decoded_text) or IPV4_RE.search(decoded_text))
            has_cred = any_regex_match(cred_kw_rx, decoded_text) if cred_kw_rx else False

            # --- FIX: whitelist logic ---
            # Treat as "whitelisted" only if *all* remote indicators found in decoded_text are whitelisted.
            urls = URL_IN_TEXT_RE.findall(decoded_text)
            ips = IPV4_RE.findall(decoded_text)

            all_whitelisted = True
            for u in urls:
                if not is_whitelisted(u, wl_sub, wl_rx):
                    all_whitelisted = False
                    break

            if all_whitelisted:
                for ip in ips:
                    if not is_whitelisted(ip, wl_sub, wl_rx):
                        all_whitelisted = False
                        break
            # --- end fix ---

            if has_remote and not all_whitelisted:
                findings.append(Finding("HIGH", p, line_no, "B64_DECODE_REMOTE", b64s, decoded_text))
            elif has_cred:
                findings.append(Finding("HIGH", p, line_no, "B64_DECODE_CRED", b64s, decoded_text))
            else:
                # still interesting, but lower priority
                findings.append(Finding("LOW", p, line_no, "B64_DECODE_TEXT", b64s, decoded_text))

    if not findings:
        rep.ok(f"No suspicious base64 decodes found. Scanned {scanned_files} files.")
    else:
        rep.warn(f"Found {len(findings)} decoded base64 blobs (some may be benign). Scanned {scanned_files} files.\n")
        for f in findings[:3000]:
            sev_color = C.RED if f.severity == "HIGH" else (C.YELLOW if f.severity == "MEDIUM" else C.MAGENTA)
            decoded_bytes = f.context.encode("utf-8", errors="replace")
            rep.emit(f"{sev_color}{f.severity:<6}{C.RESET} {f.kind:<16} {f.file}:{f.line}")
            rep.emit(f"        b64: {redact_text(f.match, max_len=120)}")
            rep.emit(f"        dec_sha256: {sha256_hex(decoded_bytes)[:16]}…")
            rep.emit(f"        dec_preview: {C.DIM}{redact_text(f.context, max_len=220)}{C.RESET}")

        if len(findings) > 3000:
            rep.warn("Output truncated: showing first 3000 findings.")

    rep.header("Whitelist (base64) used for this run")
    rep.emit(f"{C.CYAN}whitelist_substrings:{C.RESET} {', '.join(wl_sub) if wl_sub else '(none)'}")
    rep.emit(
        f"{C.CYAN}whitelist_regex:{C.RESET} "
        f"{', '.join(cfg.get('whitelist_regex', [])) if cfg.get('whitelist_regex', []) else '(none)'}"
    )

    rep.close()

    if fail_threshold_met(findings, args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
