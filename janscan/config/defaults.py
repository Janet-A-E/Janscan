"""Default configuration values."""

DEFAULT_CONFIG = {
    "general": {
        "max_workers": 8,
        "scan_timeout": 30,
        "report_formats": ["json", "html", "pdf"],
        "auto_report": True,
    },
    "paths": {
        "db_path": "~/.janscan/data/scans.db",
        "reports_dir": "~/.janscan/reports",
    },
    "modules": {
        "enabled": "all",
        "disabled": [],
    },
    "thresholds": {
        "disk_usage_warn": 85,
        "disk_usage_critical": 95,
        "cpu_warn": 80,
        "memory_warn": 85,
        "max_open_ports_warn": 20,
        "failed_logins_warn": 50,
    },
    "output": {
        "show_info_findings": True,
        "show_pass_findings": False,
        "color": True,
    },
}
