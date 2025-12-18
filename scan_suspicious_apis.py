#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List

from scanlib import (
    C, Finding, Reporter, any_regex_match, compile_regex_list, fail_threshold_met,
    iter_files, load_toml_config, make_arg_parser, merge_section, is_whitelisted,
    read_text_file, redact_text, now_stamp
)

# --- helpers to suppress noisy matches in comments ---
LINE_COMMENT_RE = re.compile(r"^\s*//")          # C#, JS
XML_COMMENT_RE = re.compile(r"^\s*<!--")         # XML/HTML
HASH_COMMENT_RE = re.compile(r"^\s*#")           # yaml/toml/ini-ish
BLOCK_COMMENT_START_RE = re.compile(r"/\*")
BLOCK_COMMENT_END_RE = re.compile(r"\*/")

def is_comment_only_line(line: str, in_block: bool) -> tuple[bool, bool]:
    """
    Returns (skip_line, new_in_block)
    - Skip if we are in a /* */ block, or the line is a single-line comment.
    - This is intentionally simple and language-agnostic.
    """
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


# Extract absolute URLs from a line (used for allowlist decisions)
URL_EXTRACT_RE = re.compile(r"https?://[^\s'\"<>)]+" , re.IGNORECASE)


# Built-in rule set (IDs so you can disable specific ones in config)
RULES: List[Dict] = [
    # Dynamic code execution
    {"id": "EXEC_PY", "sev": "HIGH", "kind": "DYNAMIC_EXEC", "rx": r"\b(eval|exec|compile)\s*\("},
    {"id": "FUNC_JS", "sev": "HIGH", "kind": "DYNAMIC_EXEC", "rx": r"\bnew\s+Function\s*\("},
    {"id": "EVAL_JS", "sev": "HIGH", "kind": "DYNAMIC_EXEC", "rx": r"\beval\s*\("},

    # Process execution / shell-outs
    {"id": "SUBPROC", "sev": "MEDIUM", "kind": "PROCESS_EXEC", "rx": r"\bsubprocess\.(Popen|run|call|check_output)\b"},
    {"id": "OS_SYSTEM", "sev": "MEDIUM", "kind": "PROCESS_EXEC", "rx": r"\bos\.system\s*\("},
    {"id": "CHILD_PROC_JS", "sev": "MEDIUM", "kind": "PROCESS_EXEC", "rx": r"\bchild_process\.(exec|spawn|execSync|spawnSync)\b"},
    {"id": "RUNTIME_EXEC_JAVA", "sev": "MEDIUM", "kind": "PROCESS_EXEC", "rx": r"\bRuntime\.getRuntime\(\)\.exec\s*\("},

    # Network primitives (even without hardcoded URLs)
    {"id": "SOCKET_PY", "sev": "MEDIUM", "kind": "NETWORK_PRIM", "rx": r"\bsocket\.socket\s*\("},
    {"id": "REQ_PY", "sev": "LOW", "kind": "NETWORK_LIB", "rx": r"\b(requests|urllib|http\.client)\b"},
    {"id": "FETCH_JS", "sev": "LOW", "kind": "NETWORK_LIB", "rx": r"\b(fetch|XMLHttpRequest)\b"},

    # Suspicious command strings (download/execute patterns)
    {"id": "CURL_PIPE", "sev": "HIGH", "kind": "DL_EXEC", "rx": r"\bcurl\b[^\n]*\|\s*(sh|bash)\b"},
    {"id": "WGET_PIPE", "sev": "HIGH", "kind": "DL_EXEC", "rx": r"\bwget\b[^\n]*\|\s*(sh|bash)\b"},
    {"id": "POWERSHELL_ENC", "sev": "HIGH", "kind": "OBFUSCATED_EXEC", "rx": r"(?i)\bpowershell\b[^\n]*\s-enc(odedcommand)?\b"},
    {"id": "CERTUTIL_DECODE", "sev": "MEDIUM", "kind": "OBFUSCATION_TOOL", "rx": r"(?i)\bcertutil\b[^\n]*\s-decode\b"},
    {"id": "BITSADMIN", "sev": "MEDIUM", "kind": "DL_TOOL", "rx": r"(?i)\bbitsadmin\b"},
    {"id": "NC_EXEC", "sev": "HIGH", "kind": "REMOTE_SHELL", "rx": r"(?i)\bnc\b[^\n]*\s-e\s"},

    # --- .NET / C# suspicious patterns ---
    {"id": "PROC_START", "sev": "HIGH", "kind": "PROCESS_EXEC", "rx": r"\bProcess\.Start\s*\("},
    {"id": "PROC_STARTINFO", "sev": "MEDIUM", "kind": "PROCESS_EXEC", "rx": r"\bProcessStartInfo\b"},
    {"id": "CMD_POWERSHELL_STR", "sev": "HIGH", "kind": "DL_EXEC", "rx": r"(?i)\b(cmd\.exe|powershell|pwsh)\b.*\s(/c|-c|-enc|EncodedCommand)\b"},

    # Networking primitives
    {"id": "WEBCLIENT", "sev": "MEDIUM", "kind": "NETWORK_PRIM", "rx": r"\bSystem\.Net\.WebClient\b|\bnew\s+WebClient\s*\("},
    {"id": "WEBCLIENT_DL", "sev": "HIGH", "kind": "DL_EXEC", "rx": r"\b(WebClient)\b.*\b(DownloadString|DownloadFile|OpenRead)\b|\b(DownloadString|DownloadFile|OpenRead)\s*\("},
    {"id": "WEBREQUEST", "sev": "MEDIUM", "kind": "NETWORK_PRIM", "rx": r"\bHttpWebRequest\b|\bWebRequest\.Create\s*\("},
    {"id": "HTTPCLIENT", "sev": "LOW", "kind": "NETWORK_LIB", "rx": r"\bHttpClient\b|\bnew\s+HttpClient\s*\("},

    # Hardcoded absolute URL usage in .NET code (signal)
    {"id": "DOTNET_ABS_URL", "sev": "MEDIUM", "kind": "NETWORK_DEST", "rx": r"(?i)\b(new\s+Uri\s*\(\s*\"https?://|GetAsync\s*\(\s*\"https?://|PostAsync\s*\(\s*\"https?://|PutAsync\s*\(\s*\"https?://|DeleteAsync\s*\(\s*\"https?://)"},
    {"id": "DOTNET_ABS_URL_S", "sev": "MEDIUM", "kind": "NETWORK_DEST", "rx": r"(?i)\b(new\s+Uri\s*\(\s*'https?://|GetAsync\s*\(\s*'https?://|PostAsync\s*\(\s*'https?://|PutAsync\s*\(\s*'https?://|DeleteAsync\s*\(\s*'https?://)"},

    # TLS / cert validation bypass (HIGH signal)
    {"id": "TLS_BYPASS_HANDLER", "sev": "HIGH", "kind": "TLS_BYPASS", "rx": r"(?i)\bServerCertificateCustomValidationCallback\b"},
    {"id": "TLS_BYPASS_DANGEROUS", "sev": "HIGH", "kind": "TLS_BYPASS", "rx": r"(?i)\bDangerousAcceptAnyServerCertificateValidator\b"},
    {"id": "TLS_BYPASS_SERVICEPOINT", "sev": "HIGH", "kind": "TLS_BYPASS", "rx": r"(?i)\bServicePointManager\.ServerCertificateValidationCallback\b"},

    # Dynamic loading/compiling
    {"id": "ASSEMBLY_LOADFROM", "sev": "HIGH", "kind": "DYNAMIC_LOAD", "rx": r"\bAssembly\.(LoadFrom|LoadFile|Load)\s*\("},
    {"id": "APPDOMAIN_RESOLVE", "sev": "MEDIUM", "kind": "DYNAMIC_LOAD", "rx": r"\bAppDomain\.CurrentDomain\.AssemblyResolve\b"},
    {"id": "REFLECTION_EMIT", "sev": "HIGH", "kind": "DYNAMIC_EXEC", "rx": r"\bSystem\.Reflection\.Emit\b"},
    {"id": "ROSLYN_COMPILE", "sev": "HIGH", "kind": "DYNAMIC_EXEC", "rx": r"\bMicrosoft\.CodeAnalysis\b|\bCSharpCompilation\b"},
    {"id": "CSHARP_CODEPROV", "sev": "HIGH", "kind": "DYNAMIC_EXEC", "rx": r"\bCSharpCodeProvider\b|\bCodeDomProvider\b"},

    # Native interop / injection-adjacent
    {"id": "PINVOKE_DLLIMPORT", "sev": "MEDIUM", "kind": "NATIVE_INTEROP", "rx": r"\[DllImport\s*\("},
    {"id": "MARSHAL", "sev": "MEDIUM", "kind": "NATIVE_INTEROP", "rx": r"\bSystem\.Runtime\.InteropServices\.Marshal\b"},
    {"id": "VIRTUALALLOC", "sev": "HIGH", "kind": "NATIVE_INTEROP", "rx": r"(?i)\bVirtualAlloc\b|\bCreateRemoteThread\b|\bWriteProcessMemory\b"},

    # Obfuscation hints
    {"id": "B64_FROM", "sev": "MEDIUM", "kind": "OBFUSCATION_HINT", "rx": r"\bConvert\.FromBase64String\s*\("},
    {"id": "GZIP_DEFLATE", "sev": "MEDIUM", "kind": "OBFUSCATION_HINT", "rx": r"\bGZipStream\b|\bDeflateStream\b"},
]


def main() -> int:
    ap = make_arg_parser("scan_suspicious_apis.py")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    cfg_all = load_toml_config(Path(args.config))
    cfg = merge_section(cfg_all, "suspicious_apis")
    gen = cfg_all.get("general", {})

    # Pull allowlist from remote_refs (shared policy)
    rr_cfg = merge_section(cfg_all, "remote_refs")
    rr_wl_sub = rr_cfg.get("whitelist_substrings", [])
    rr_wl_rx = compile_regex_list(rr_cfg.get("whitelist_regex", []))

    exclude_dirs = gen.get("exclude_dirs", [])
    exclude_globs = gen.get("exclude_globs", [])
    include_exts = gen.get("include_exts", [])
    max_mb = int(gen.get("max_file_size_mb", 5))
    max_bytes = max_mb * 1024 * 1024

    allow_line_rx = compile_regex_list(cfg.get("allow_line_regex", []))
    disabled = set(cfg.get("disable_rule_ids", []))

    compiled_rules = []
    for r in RULES:
        if r["id"] in disabled:
            continue
        try:
            compiled_rules.append({**r, "cre": re.compile(r["rx"])})
        except re.error:
            continue

    out_path = Path(args.out) if args.out else Path(f"suspicious_apis_report_{now_stamp()}.txt")
    rep = Reporter(out_path, color=(not args.no_color))

    rep.header(f"Suspicious API / Pattern Scan — root={root}")
    rep.emit(f"{C.DIM}Rules enabled: {len(compiled_rules)} (disable via [suspicious_apis].disable_rule_ids){C.RESET}")
    rep.emit(f"{C.DIM}Remote allowlist source: [remote_refs].whitelist_* (used to downgrade approved absolute-URL findings){C.RESET}")

    if not root.exists():
        rep.bad(f"Root path does not exist: {root}")
        rep.close()
        return 2

    findings: List[Finding] = []
    scanned_files = 0

    for p in iter_files(root, exclude_dirs, exclude_globs, include_exts, max_bytes):
        scanned_files += 1
        text = read_text_file(p)

        in_block_comment = False
        for i, line in enumerate(text.splitlines(), start=1):
            # allow list always wins
            if any_regex_match(allow_line_rx, line):
                continue

            skip, in_block_comment = is_comment_only_line(line, in_block_comment)
            if skip:
                continue

            for r in compiled_rules:
                if not r["cre"].search(line):
                    continue

                kind = f"{r['kind']}:{r['id']}"
                sev = r["sev"]
                match_val = r["rx"]

                # If this line contains absolute URL(s), apply remote_refs allowlist:
                # - If ALL absolute URLs found are whitelisted => downgrade to LOW and tag as WHITELISTED
                # - Otherwise tag as NON_WHITELISTED (keeps original severity)
                if r["id"] in ("DOTNET_ABS_URL", "DOTNET_ABS_URL_S"):
                    urls = URL_EXTRACT_RE.findall(line)
                    if urls:
                        match_val = " ".join(urls[:3]) + (" ..." if len(urls) > 3 else "")
                        all_wl = all(is_whitelisted(u, rr_wl_sub, rr_wl_rx) for u in urls)
                        if all_wl:
                            sev = "LOW"
                            kind = f"{kind}:WHITELISTED"
                        else:
                            kind = f"{kind}:NON_WHITELISTED"

                findings.append(Finding(sev, p, i, kind, match_val, line))

    if not findings:
        rep.ok(f"No suspicious patterns matched. Scanned {scanned_files} files.")
    else:
        rep.warn(f"Matched {len(findings)} suspicious patterns in {scanned_files} files.\n")
        for f in findings[:5000]:
            sev_color = C.RED if f.severity == "HIGH" else (C.YELLOW if f.severity == "MEDIUM" else C.MAGENTA)
            rep.emit(f"{sev_color}{f.severity:<6}{C.RESET} {f.kind:<34} {f.file}:{f.line}")
            rep.emit(f"        {C.DIM}ctx: {redact_text(f.context, max_len=240)}{C.RESET}")
            if f.match and f.match != "":
                rep.emit(f"        {C.DIM}match: {redact_text(f.match, max_len=200)}{C.RESET}")
        if len(findings) > 5000:
            rep.warn("Output truncated: showing first 5000 findings.")

    rep.header("Allow-list (suspicious_apis) used for this run")
    rep.emit(f"{C.CYAN}allow_line_regex:{C.RESET} {', '.join(cfg.get('allow_line_regex', [])) if cfg.get('allow_line_regex', []) else '(none)'}")
    rep.emit(f"{C.CYAN}disable_rule_ids:{C.RESET} {', '.join(cfg.get('disable_rule_ids', [])) if cfg.get('disable_rule_ids', []) else '(none)'}")

    rep.header("Remote allowlist (remote_refs) used for URL downgrade")
    rep.emit(f"{C.CYAN}whitelist_substrings:{C.RESET} {', '.join(rr_wl_sub) if rr_wl_sub else '(none)'}")
    rep.emit(f"{C.CYAN}whitelist_regex:{C.RESET} {', '.join(rr_cfg.get('whitelist_regex', [])) if rr_cfg.get('whitelist_regex', []) else '(none)'}")

    rep.close()

    return 1 if fail_threshold_met(findings, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
