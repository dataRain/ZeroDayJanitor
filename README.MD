
# Remote references (URLs/IPs/UNC shares)
python scan_remote_refs.py --root ./src --config scanner_config.toml --fail-on medium

# Base64 decode & inspect
python scan_base64_strings.py --root ./src --config scanner_config.toml --fail-on high

# Suspicious API/pattern scan
python scan_suspicious_apis.py --root ./src --config scanner_config.toml --fail-on medium

# local / listening ports
python3 scan_listening_ports.py --root /path/to/source --config scanner_config.toml --fail-on medium

# webshell indicators
python3 scan_webshell_indicators.py --root /path/to/source --config scanner_config.toml --fail-on high

