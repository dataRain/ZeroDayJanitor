#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import hashlib
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_BANNER_PRINTED = False

BANNER = """
       _______    _______   _______  _______          ______   _______   ________       
      ╱       ╲╲╱╱       ╲╱╱       ╲╱       ╲╲      _╱      ╲╲╱       ╲╲╱    ╱   ╲      
     ╱-        ╱╱        ╱╱        ╱        ╱╱     ╱        ╱╱        ╱╱         ╱      
    ╱        _╱        _╱        _╱         ╱     ╱         ╱         ╱╲__     ╱╱       
    ╲________╱╲________╱╲____╱___╱╲________╱      ╲________╱╲___╱____╱   ╲____╱╱        
                    ______  _______    _______   ________  ________  _______    _______ 
                   ╱      ╲╱       ╲╲╱╱   ╱   ╲ ╱        ╲╱        ╲╱       ╲╲╱╱       ╲
                  ╱       ╱        ╱╱╱        ╱_╱       ╱╱        _╱        ╱╱╱        ╱
                _╱      ╱╱         ╱         ╱╱         ╱╱       ╱╱         ╱        _╱ 
                ╲______╱╱╲___╱____╱╲__╱_____╱ ╲╲_______╱ ╲_____╱╱ ╲________╱╲____╱___╱  

                                    ZeroDayJanitor v1.0
                                    By Marcel Goulart
                                    https://github.com/dataRain
    """

class C:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    CYAN = "\x1b[36m"
    MAGENTA = "\x1b[35m"


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def now_stamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_toml_config(path: Path) -> Dict:
    if not path.exists():
        return {}
    try:
        import tomllib  # py>=3.11
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except ModuleNotFoundError:
        # py<3.11 fallback
        import tomli  # type: ignore
        return tomli.loads(path.read_text(encoding="utf-8"))

def merge_section(cfg: Dict, section: str) -> Dict:
    merged = dict(cfg.get("general", {}))
    merged.update(cfg.get(section, {}))
    return merged

def is_probably_binary(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            chunk = f.read(2048)
        if b"\x00" in chunk:
            return True
        # Heuristic: lots of non-text bytes
        nontext = sum(b < 9 or (b > 13 and b < 32) for b in chunk)
        return (len(chunk) > 0) and (nontext / len(chunk) > 0.25)
    except Exception:
        return True

def iter_files(root: Path, exclude_dirs: List[str], exclude_globs: List[str], include_exts: List[str], max_bytes: int) -> Iterable[Path]:
    include_exts_norm = set([e.lower() for e in include_exts])
    for dirpath, dirnames, filenames in os.walk(root):
        # prune dirs
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for name in filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(root)

            # exclude globs (match on basename and relative path)
            if any(fnmatch.fnmatch(name, g) or fnmatch.fnmatch(str(rel), g) for g in exclude_globs):
                continue

            # extension filter (special-case Dockerfile-like names)
            ext = p.suffix.lower()
            if name == "Dockerfile":
                ok = "Dockerfile" in include_exts_norm
            else:
                ok = (ext in include_exts_norm) or (name.lower() in include_exts_norm)
            if not ok:
                continue

            try:
                if p.stat().st_size > max_bytes:
                    continue
            except Exception:
                continue

            if is_probably_binary(p):
                continue

            yield p

def read_text_file(p: Path) -> str:
    # replace errors so we don’t crash on weird encodings
    return p.read_text(encoding="utf-8", errors="replace")

def compile_regex_list(patterns: List[str]) -> List[re.Pattern]:
    out = []
    for pat in patterns:
        try:
            out.append(re.compile(pat))
        except re.error:
            # ignore bad regex so pipeline doesn't die unexpectedly
            pass
    return out

def any_regex_match(regexes: List[re.Pattern], s: str) -> bool:
    return any(r.search(s) for r in regexes)

def is_whitelisted(value: str, wl_substrings: List[str], wl_regexes: List[re.Pattern]) -> bool:
    v = value.lower()
    if any(w.lower() in v for w in wl_substrings):
        return True
    if any(r.search(value) for r in wl_regexes):
        return True
    return False

def redact_text(s: str, max_len: int = 160) -> str:
    # Redact common credential patterns
    s = re.sub(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*([^\s'\";]+)", r"\1=<REDACTED>", s)
    s = re.sub(r"(?i)\bauthorization\b\s*:\s*([^\s'\";]+)", "Authorization: <REDACTED>", s)
    # Redact JWT-ish strings
    s = re.sub(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "<JWT_REDACTED>", s)
    # Redact very long tokens/hex/base64-ish blobs in preview
    s = re.sub(r"\b[A-Fa-f0-9]{32,}\b", "<HEX_REDACTED>", s)
    s = re.sub(r"\b[A-Za-z0-9+/=_-]{48,}\b", "<BLOB_REDACTED>", s)

    s = s.replace("\r", "\\r").replace("\n", "\\n")
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s

@dataclass
class Finding:
    severity: str
    file: Path
    line: int
    kind: str
    match: str
    context: str

SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

class Reporter:
    def __init__(self, out_path: Path, color: bool = True):
        self.out_path = out_path
        self.color = color
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self.f = self.out_path.open("w", encoding="utf-8")
        self.write_plain(f"Report: {self.out_path.name}\nGenerated: {_dt.datetime.now().isoformat()}\n")

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass

    def write_plain(self, s: str):
        self.f.write(strip_ansi(s))
        if not s.endswith("\n"):
            self.f.write("\n")

    def emit(self, s: str):
        if self.color:
            print(s)
        else:
            print(strip_ansi(s))
        self.write_plain(s)

    def header(self, title: str):
        global _BANNER_PRINTED
        if not _BANNER_PRINTED:
            # Print banner to terminal only (not to file)
            #print(BANNER)
            for line in BANNER.splitlines():
                self.emit(line)
            _BANNER_PRINTED = True
        self.emit(f"{C.BOLD}{C.CYAN}{title}{C.RESET}")

    def ok(self, msg: str):
        self.emit(f"{C.GREEN}✔ {msg}{C.RESET}")

    def warn(self, msg: str):
        self.emit(f"{C.YELLOW}⚠ {msg}{C.RESET}")

    def bad(self, msg: str):
        self.emit(f"{C.RED}✖ {msg}{C.RESET}")

def fail_threshold_met(findings: List[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    thresh = SEV_ORDER.get(fail_on.upper(), 3)
    return any(SEV_ORDER.get(f.severity, 0) >= thresh for f in findings)

def make_arg_parser(tool_name: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=tool_name)
    p.add_argument("--root", required=True, help="Directory to scan")
    p.add_argument("--config", default="scanner_config.toml", help="Path to scanner_config.toml")
    p.add_argument("--out", default=None, help="Output report file (.txt). Default: auto in current dir.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument("--fail-on", choices=["none", "low", "medium", "high"], default="high",
                   help="Exit non-zero if findings at/above severity exist")
    return p
