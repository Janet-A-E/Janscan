# JanScan — Linux Security Audit Tool

```
     ██╗ █████╗ ███╗  ██╗███████╗ ██████╗ █████╗ ███╗  ██╗
     ██║██╔══██╗████╗ ██║██╔════╝██╔════╝██╔══██╗████╗ ██║
     ██║███████║██╔██╗██║███████╗██║     ███████║██╔██╗██║
██   ██║██╔══██║██║╚████║╚════██║██║     ██╔══██║██║╚████║
╚█████╔╝██║  ██║██║ ╚███║███████║╚██████╗██║  ██║██║ ╚███║
 ╚════╝ ╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
```

A professional Linux security audit CLI tool with msfconsole-style UI.

## Quick Start

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install and run
cd janscan/
uv sync
uv run janscan

# Full audit (recommended — run as root for all checks)
sudo uv run janscan
```

## Features

- **18+ audit modules** — SSH, firewalls, kernel, users, ports, disk encryption, and more
- **msfconsole-style UI** — interactive prompt with rich color output
- **SQLite history** — every scan stored, queryable, comparable
- **3 report formats** — JSON, HTML (dark theme), PDF (professional)
- **Modular** — drop a new `.py` file in `modules/` to add a check, zero other changes needed
- **Non-destructive** — read-only audit, never modifies your system
- **Privilege-aware** — gracefully skips privileged checks when not root

## Commands

```
janscan > scan                        # Full system audit
janscan > scan --modules ssh_security,kernel  # Specific modules only
janscan > history                     # View past scans
janscan > history --limit 5
janscan > report                      # Regenerate last scan's reports
janscan > report --id 42              # Report from scan #42
janscan > report --open               # Open HTML in browser
janscan > diff 41 42                  # Compare two scans
janscan > diff 41 42 --format html    # Diff with HTML report
janscan > modules                     # List all modules
janscan > config                      # View config
janscan > config --edit               # Edit config in $EDITOR
janscan > export --format pdf --id 5  # Export specific format
janscan > help                        # Command reference
janscan > exit
```

## Audit Modules

| Module | Checks |
|--------|--------|
| system_info | OS, kernel, CPU, RAM, uptime |
| user_accounts | UID 0, empty passwords, service accounts |
| ssh_security | sshd_config, ciphers, MACs, root login |
| firewalls | ufw, firewalld, iptables, nftables |
| file_permissions | SUID/SGID, world-writable, shadow/sudoers |
| services | Running services, risky daemons |
| updates | Pending updates, security patches |
| network | IP forwarding, SYN cookies, redirects |
| logging_audit | syslog, auditd, journald, failed logins |
| kernel | ASLR, kptr_restrict, BPF, NX, ptrace |
| open_ports | TCP/UDP listeners, risky ports |
| active_connections | Established connections, suspicious ports |
| disk_encryption | LUKS, swap encryption, TPM |
| sudo_config | NOPASSWD, broad grants, logging |
| disk_usage | Partition usage, inodes |
| system_health | CPU, memory, swap, zombies, OOM |
| ip_addresses | All interfaces, MACs, VPN detection |
| security_hygiene | Password policy, umask, .rhosts, PATH |

## Adding a Custom Module

```python
# janscan/modules/my_check.py
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity
import time

class MyCheckModule(BaseModule):
    name = "my_check"
    display_name = "My Custom Check"
    description = "A custom security check."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []
        # ... your checks ...
        findings.append(Finding(
            title="My Finding",
            description="Details here.",
            severity=Severity.INFO,
            passed=True,
        ))
        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
```

Drop the file in `janscan/modules/` — it's auto-discovered on next run. No other files need changing.

## Report Output

Reports saved to `~/.janscan/reports/<timestamp>_<uuid>/`:
- `report.json` — machine-readable full data
- `report.html` — dark-theme web report with collapsible modules
- `report.pdf` — professional PDF with cover page and recommendations

## Configuration

Edit `~/.janscan/config.toml` or use `config --edit` inside janscan.

## Scoring

| Score | Grade | Meaning |
|-------|-------|---------|
| 90–100 | A | Excellent |
| 75–89 | B | Good |
| 60–74 | C | Fair |
| 40–59 | D | Poor |
| 0–39 | F | Critical Risk |

Deductions: CRITICAL −20, HIGH −10, MEDIUM −5, LOW −2
