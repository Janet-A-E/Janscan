"""Logging & Audit module."""

import time
import os
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity
from janscan import IS_ROOT


class LoggingAuditModule(BaseModule):
    name = "logging_audit"
    display_name = "Logging & Audit"
    description = "Checks syslog, journald, auditd, and log file security."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # syslog/rsyslog
        for svc in ["rsyslog", "syslog"]:
            stdout, _, rc = self._run_command(["systemctl", "is-active", svc])
            if rc == 0 and stdout.strip() == "active":
                findings.append(Finding(f"{svc} Running", f"{svc} service is active.", Severity.PASS, True, tags=["logging"]))
                break
        else:
            findings.append(Finding(
                title="No Syslog Service Active",
                description="Neither rsyslog nor syslog is running.",
                severity=Severity.HIGH, passed=False,
                recommendation="Install and enable rsyslog: sudo apt install rsyslog && sudo systemctl enable --now rsyslog",
                tags=["logging"],
            ))

        # journald persistent
        journald_cfg = self._read_file("/etc/systemd/journald.conf")
        if "Storage=persistent" in journald_cfg or "Storage=auto" in journald_cfg:
            findings.append(Finding("journald Persistent Logging", "journald is set to persistent storage.", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="journald Not Persistent",
                description="journald may not persist logs across reboots.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Set Storage=persistent in /etc/systemd/journald.conf",
                tags=["logging"],
            ))

        # auditd
        stdout, _, rc = self._run_command(["systemctl", "is-active", "auditd"])
        if rc == 0 and stdout.strip() == "active":
            findings.append(Finding("auditd Running", "auditd is active.", Severity.PASS, True, tags=["audit"]))
        else:
            findings.append(Finding(
                title="auditd Not Running",
                description="auditd audit daemon is not active.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Install and enable: sudo apt install auditd && sudo systemctl enable --now auditd",
                tags=["audit"],
            ))

        # auditd rules
        audit_rules = self._read_file("/etc/audit/audit.rules")
        if not audit_rules:
            audit_rules = self._read_file("/etc/audit/rules.d/audit.rules")
        if audit_rules and len(audit_rules.strip()) > 20:
            findings.append(Finding("Audit Rules Configured", "Audit rules found in /etc/audit/", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="No Audit Rules Configured",
                description="auditd has no custom rules.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Configure audit rules in /etc/audit/rules.d/",
                tags=["audit"],
            ))

        # Log rotation
        if os.path.isfile("/etc/logrotate.conf"):
            findings.append(Finding("Log Rotation Configured", "/etc/logrotate.conf exists.", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="Log Rotation Not Configured",
                description="/etc/logrotate.conf not found.",
                severity=Severity.LOW, passed=False,
                recommendation="Install logrotate: sudo apt install logrotate",
                tags=["logging"],
            ))

        # Failed logins in last 24h
        for log_path in ["/var/log/auth.log", "/var/log/secure"]:
            if os.path.isfile(log_path):
                try:
                    stdout, _, rc = self._run_command(
                        ["grep", "-c", "Failed password", log_path], timeout=10
                    )
                    count = int(stdout.strip()) if stdout.strip().isdigit() else 0
                    if count > 50:
                        findings.append(Finding(
                            title=f"High Failed Login Count ({count})",
                            description=f"{count} failed password attempts in {log_path}.",
                            severity=Severity.HIGH, passed=False,
                            recommendation="Review auth logs and consider fail2ban installation.",
                            tags=["auth", "logging"],
                        ))
                    else:
                        findings.append(Finding(
                            f"Failed Logins: {count}",
                            f"{count} failed password attempts in {log_path}.",
                            Severity.PASS if count < 10 else Severity.LOW, count < 50,
                        ))
                    break
                except Exception:
                    pass

        # Root SSH login success
        for log_path in ["/var/log/auth.log", "/var/log/secure"]:
            if os.path.isfile(log_path):
                stdout, _, rc = self._run_command(["grep", "Accepted.*root", log_path], timeout=10)
                if rc == 0 and stdout.strip():
                    count = len(stdout.strip().splitlines())
                    findings.append(Finding(
                        title=f"Successful Root SSH Logins ({count})",
                        description=f"{count} successful root login(s) found in logs.",
                        severity=Severity.HIGH, passed=False,
                        recommendation="Disable root SSH login and use sudo instead.",
                        tags=["auth", "ssh"],
                    ))
                break

        # World-readable log files
        stdout, _, rc = self._run_command(["find", "/var/log", "-perm", "-o+r", "-type", "f"], timeout=10)
        if rc == 0 and stdout.strip():
            wlogs = stdout.strip().splitlines()
            findings.append(Finding(
                title=f"World-Readable Log Files ({len(wlogs)})",
                description=f"{len(wlogs)} log file(s) are world-readable.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Restrict log permissions: chmod o-r /var/log/*",
                raw_output="\n".join(wlogs[:20]),
                tags=["logging", "permissions"],
            ))
        else:
            findings.append(Finding("Log File Permissions OK", "No world-readable log files found.", Severity.PASS, True))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
