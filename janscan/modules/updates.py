"""System Updates audit module."""

import time
import os
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class UpdatesModule(BaseModule):
    name = "updates"
    display_name = "System Updates"
    description = "Checks for pending system updates and security patches."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # Detect package manager
        pm = None
        for mgr in ["apt", "dnf", "yum", "pacman", "zypper"]:
            stdout, _, rc = self._run_command(["which", mgr])
            if rc == 0 and stdout.strip():
                pm = mgr
                break

        findings.append(Finding("Package Manager", f"Detected: {pm or 'None found'}", Severity.INFO, True))

        if pm == "apt":
            # Update cache first (non-intrusive)
            stdout, _, rc = self._run_command(["apt", "list", "--upgradable"], timeout=20)
            if rc == 0:
                lines = [l for l in stdout.splitlines() if "/" in l]
                count = len(lines)
                if count == 0:
                    findings.append(Finding("System Up to Date", "No pending apt updates.", Severity.PASS, True))
                elif count > 20:
                    findings.append(Finding(
                        title=f"Many Pending Updates ({count})",
                        description=f"{count} packages have updates available.",
                        severity=Severity.HIGH, passed=False,
                        recommendation="Run: sudo apt update && sudo apt upgrade",
                        tags=["updates"],
                    ))
                else:
                    findings.append(Finding(
                        title=f"Pending Updates ({count})",
                        description=f"{count} packages have updates available.",
                        severity=Severity.MEDIUM, passed=False,
                        recommendation="Run: sudo apt update && sudo apt upgrade",
                        raw_output="\n".join(lines[:20]),
                        tags=["updates"],
                    ))

                # Security updates
                security = [l for l in lines if "security" in l.lower()]
                if security:
                    findings.append(Finding(
                        title=f"Security Updates Pending ({len(security)})",
                        description=f"{len(security)} security update(s) available.",
                        severity=Severity.CRITICAL, passed=False,
                        recommendation="Apply security updates immediately: sudo apt-get upgrade",
                        raw_output="\n".join(security[:20]),
                        tags=["updates", "security"],
                    ))

            # Unattended upgrades
            stdout, _, rc = self._run_command(["dpkg", "-l", "unattended-upgrades"])
            if rc == 0 and "ii" in stdout:
                findings.append(Finding("Automatic Updates Configured", "unattended-upgrades is installed.", Severity.PASS, True))
            else:
                findings.append(Finding(
                    title="Automatic Updates Not Configured",
                    description="unattended-upgrades not installed.",
                    severity=Severity.LOW, passed=False,
                    recommendation="Install: sudo apt install unattended-upgrades",
                    tags=["updates"],
                ))

        elif pm in ("dnf", "yum"):
            stdout, _, rc = self._run_command([pm, "check-update", "--quiet"], timeout=20)
            if rc == 100:  # 100 means updates available
                lines = [l for l in stdout.splitlines() if l.strip() and not l.startswith("Last")]
                findings.append(Finding(
                    title=f"Pending Updates ({len(lines)})",
                    description=f"{len(lines)} packages have updates available.",
                    severity=Severity.MEDIUM if len(lines) < 20 else Severity.HIGH,
                    passed=False,
                    recommendation=f"Run: sudo {pm} update",
                    tags=["updates"],
                ))
            elif rc == 0:
                findings.append(Finding("System Up to Date", "No pending updates.", Severity.PASS, True))

        elif pm == "pacman":
            stdout, _, rc = self._run_command(["pacman", "-Qu"], timeout=20)
            if rc == 0 and stdout.strip():
                count = len(stdout.strip().splitlines())
                findings.append(Finding(
                    title=f"Pending Updates ({count})",
                    description=f"{count} packages have updates.",
                    severity=Severity.MEDIUM if count < 20 else Severity.HIGH,
                    passed=False,
                    recommendation="Run: sudo pacman -Syu",
                    tags=["updates"],
                ))
            else:
                findings.append(Finding("System Up to Date", "No pending updates.", Severity.PASS, True))

        else:
            findings.append(Finding(
                "Update Check Skipped",
                f"No supported package manager found (detected: {pm}).",
                Severity.INFO, True,
            ))

        # Last update (check DB timestamps)
        for path in ["/var/lib/apt/lists", "/var/cache/yum", "/var/lib/pacman/sync"]:
            if os.path.isdir(path):
                try:
                    mtime = os.path.getmtime(path)
                    import datetime
                    days = (datetime.datetime.now().timestamp() - mtime) / 86400
                    if days > 30:
                        findings.append(Finding(
                            title="Package Database Outdated",
                            description=f"Package database last updated {int(days)} days ago.",
                            severity=Severity.MEDIUM, passed=False,
                            recommendation="Update package database.",
                            tags=["updates"],
                        ))
                    else:
                        findings.append(Finding("Package DB Recent", f"Package DB updated {int(days)} day(s) ago.", Severity.PASS, True))
                    break
                except Exception:
                    pass

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
