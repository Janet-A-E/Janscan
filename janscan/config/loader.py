"""Config loader — reads ~/.janscan/config.toml and merges with defaults."""

import tomllib
import copy
from pathlib import Path
from janscan.config.defaults import DEFAULT_CONFIG

JANSCAN_DIR = Path.home() / ".janscan"
DATA_DIR = JANSCAN_DIR / "data"
REPORTS_DIR = JANSCAN_DIR / "reports"
CONFIG_PATH = JANSCAN_DIR / "config.toml"


def init_directories():
    for d in [JANSCAN_DIR, DATA_DIR, REPORTS_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        write_default_config()


def write_default_config():
    lines = [
        "[general]",
        "max_workers = 8",
        "scan_timeout = 30",
        'report_formats = ["json", "html", "pdf"]',
        "auto_report = true",
        "",
        "[paths]",
        'db_path = "~/.janscan/data/scans.db"',
        'reports_dir = "~/.janscan/reports"',
        "",
        "[modules]",
        'enabled = "all"',
        "disabled = []",
        "",
        "[thresholds]",
        "disk_usage_warn = 85",
        "disk_usage_critical = 95",
        "cpu_warn = 80",
        "memory_warn = 85",
        "max_open_ports_warn = 20",
        "failed_logins_warn = 50",
        "",
        "[output]",
        "show_info_findings = true",
        "show_pass_findings = false",
        "color = true",
    ]
    CONFIG_PATH.write_text("\n".join(lines) + "\n")


def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config() -> dict:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "rb") as f:
                user_cfg = tomllib.load(f)
            cfg = _deep_merge(cfg, user_cfg)
        except Exception:
            pass
    return cfg
