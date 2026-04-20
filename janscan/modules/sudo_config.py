"""Sudo Configuration audit module."""

import time
import os
import glob
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class SudoConfigModule(BaseModule):
    name = "sudo_config"
    display_name = "Sudo Configuration"
    description = "Audits sudoers file for overly permissive or insecure sudo rules."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # Read sudoers
        sudoers_content = self._read_file("/etc/sudoers")
        sudoers_files = ["/etc/sudoers"]
        try:
            for f in glob.glob("/etc/sudoers.d/*"):
                sudoers_files.append(f)
                sudoers_content += "\n" + self._read_file(f)
        except Exception:
            pass

        if not sudoers_content:
            findings.append(Finding(
                "sudoers Unreadable",
                "/etc/sudoers cannot be read (try running as root).",
                Severity.INFO, True,
            ))
        else:
            # NOPASSWD
            nopasswd = [l.strip() for l in sudoers_content.splitlines()
                       if "NOPASSWD" in l and not l.strip().startswith("#")]
            if nopasswd:
                findings.append(Finding(
                    title=f"NOPASSWD Sudo Rules Found ({len(nopasswd)})",
                    description=f"Passwordless sudo rules: {'; '.join(nopasswd[:3])}",
                    severity=Severity.HIGH, passed=False,
                    recommendation="Remove NOPASSWD from sudoers unless absolutely necessary.",
                    raw_output="\n".join(nopasswd),
                    tags=["sudo", "privilege"],
                ))
            else:
                findings.append(Finding("No NOPASSWD Sudo Rules", "No passwordless sudo rules found.", Severity.PASS, True))

            # ALL=(ALL) ALL
            all_rules = [l.strip() for l in sudoers_content.splitlines()
                        if "ALL=(ALL)" in l and "ALL" in l and not l.strip().startswith("#")
                        and "root" not in l]
            if all_rules:
                findings.append(Finding(
                    title=f"Broad Sudo Grant (ALL) Found ({len(all_rules)})",
                    description=f"Users/groups with full sudo access: {'; '.join(all_rules[:3])}",
                    severity=Severity.HIGH, passed=False,
                    recommendation="Restrict sudo to specific commands using command allowlists.",
                    raw_output="\n".join(all_rules),
                    tags=["sudo", "privilege"],
                ))

            # Logging
            if "Defaults logfile" in sudoers_content or "Defaults log_output" in sudoers_content:
                findings.append(Finding("Sudo Logging Enabled", "Sudo logging is configured.", Severity.PASS, True))
            else:
                findings.append(Finding(
                    title="Sudo Logging Not Configured",
                    description="Sudo does not have explicit logging configured.",
                    severity=Severity.MEDIUM, passed=False,
                    recommendation="Add 'Defaults logfile=/var/log/sudo.log' to /etc/sudoers",
                    tags=["sudo", "logging"],
                ))

            # Timeout
            if "timestamp_timeout" in sudoers_content:
                findings.append(Finding("Sudo Timestamp Timeout Set", "Custom sudo timeout configured.", Severity.PASS, True))
            else:
                findings.append(Finding(
                    title="Sudo Timeout Not Configured",
                    description="Default sudo credential caching timeout (15 min) in use.",
                    severity=Severity.LOW, passed=False,
                    recommendation="Add 'Defaults timestamp_timeout=5' to reduce credential cache window.",
                    tags=["sudo"],
                ))

            # requiretty
            if "requiretty" in sudoers_content:
                findings.append(Finding("requiretty Configured", "Sudo requires a TTY.", Severity.PASS, True))
            else:
                findings.append(Finding(
                    title="requiretty Not Set",
                    description="sudo does not require a real TTY.",
                    severity=Severity.LOW, passed=False,
                    recommendation="Add 'Defaults requiretty' to /etc/sudoers",
                    tags=["sudo"],
                ))

        # Current user sudo rights
        stdout, _, rc = self._run_command(["sudo", "-l", "-n"])
        if rc == 0 and stdout.strip():
            findings.append(Finding(
                "Current User Sudo Rights",
                f"sudo -l output captured.",
                Severity.INFO, True,
                raw_output=stdout[:500],
            ))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
