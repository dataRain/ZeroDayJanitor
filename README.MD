
## Overview
The scripts in this repository provide lightweight static scans to catch risky patterns in source code and configuration files. Each scanner emits a report and can fail a pipeline based on a severity threshold, making it easy to add quick security checks to CI/CD workflows.

## Quick start
Run any scanner by pointing it at a source root and the shared configuration file:

```bash
python scan_remote_refs.py --root ./src --config scanner_config.toml --fail-on medium
```

All scanners accept common flags defined in `scanlib.py`:
- `--root`: Directory to scan.
- `--config`: Path to the TOML configuration file.
- `--fail-on`: Lowest severity (`low`, `medium`, or `high`) that will exit with a non-zero status.
- `--out`: Optional report file path (a timestamped filename is used if omitted).
- `--no-color`: Disable ANSI colors in output.

## Configuration (`scanner_config.toml`)
The shared TOML file controls filtering, whitelisting, and per-scanner behavior:

- `[general]`: Directory and filename exclusions (`exclude_dirs`, `exclude_globs`), allowed extensions (`include_exts`), and maximum file size (`max_file_size_mb`).
- `[remote_refs]`: Whitelisted substrings and regex patterns to suppress expected URLs, IPs, and UNC paths; `ignore_line_regex` skips lines entirely.
- `[suspicious_apis]`: `allow_line_regex` for inline exceptions and `disable_rule_ids` to turn off specific built-in rules.
- `[listening_ports]`: Similar allow/disable options plus `whitelist_ports` to downgrade known listener ports.
- `[webshells]`: Allow/disable options and `suspicious_param_name_regex` for flagging risky request parameters.

Adjust these sections to match your environment before running the scanners.

## Script catalog
### `scan_remote_refs.py`
Detects URLs, IP addresses (v4/v6), UNC shares, Git SCP URLs, and related remote reference patterns to prevent accidental secrets or external calls. Honors the `[remote_refs]` configuration for whitelisting and ignores.

Example:
```bash
python scan_remote_refs.py --root ./src --config scanner_config.toml --fail-on medium
```

### `scan_base64_strings.py`
Decodes and inspects base64-like strings to surface embedded secrets or payloads. Uses the `[general]` settings for file selection and size limits.

Example:
```bash
python scan_base64_strings.py --root ./src --config scanner_config.toml --fail-on high
```

### `scan_suspicious_apis.py`
Flags usage of risky APIs and patterns (e.g., command execution, dynamic code loading). Inline exceptions can be added with `# nosec` or `ALLOW_SUSPICIOUS_OK`, and rules can be disabled via `[suspicious_apis].disable_rule_ids`.

Example:
```bash
python scan_suspicious_apis.py --root ./src --config scanner_config.toml --fail-on medium
```

### `scan_listening_ports.py`
Finds code that opens listening sockets or binds to ports. Expected ports (e.g., 80, 443, 5000, 5001) can be added to `[listening_ports].whitelist_ports` to reduce noise.

Example:
```bash
python3 scan_listening_ports.py --root /path/to/source --config scanner_config.toml --fail-on medium
```

### `scan_webshell_indicators.py`
Searches for webshell-like parameters and payload handlers, using `[webshells].suspicious_param_name_regex` to tune detections.

Example:
```bash
python3 scan_webshell_indicators.py --root /path/to/source --config scanner_config.toml --fail-on high
```

## Author
Speed Triage Maintainers
