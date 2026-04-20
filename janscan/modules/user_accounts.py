"""User Accounts audit module."""

import time
import os
from pathlib import Path
from datetime import datetime, timedelta
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity
from janscan import IS_ROOT


class UserAccountsModule(BaseModule):
    name = "user_accounts"
    display_name = "User Accounts"
    description = "Audits user accounts for security issues (empty passwords, UID 0, etc.)."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # Parse /etc/passwd
        passwd = self._read_file("/etc/passwd")
        users = []
        real_users = []
        service_accounts_with_shell = []

        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            uname, _, uid, gid, _, home, shell = parts[:7]
            uid = int(uid) if uid.isdigit() else -1
            users.append({"name": uname, "uid": uid, "home": home, "shell": shell})
            if uid >= 1000:
                real_users.append(uname)
            elif uid > 0 and shell in ("/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"):
                service_accounts_with_shell.append(uname)

        findings.append(Finding(
            title="Real User Accounts",
            description=f"Found {len(real_users)} real user(s): {', '.join(real_users) or 'none'}",
            severity=Severity.INFO,
            passed=True,
            tags=["users"],
        ))

        # UID 0 other than root
        uid0 = [u["name"] for u in users if u["uid"] == 0 and u["name"] != "root"]
        if uid0:
            findings.append(Finding(
                title="Multiple UID 0 Accounts",
                description=f"Non-root accounts with UID 0: {', '.join(uid0)}",
                severity=Severity.CRITICAL,
                passed=False,
                recommendation="Investigate and remove unauthorized UID 0 accounts immediately.",
                tags=["users", "privilege"],
            ))
        else:
            findings.append(Finding("UID 0 Check", "Only root has UID 0.", Severity.PASS, True))

        # Service accounts with login shells
        if service_accounts_with_shell:
            findings.append(Finding(
                title="Service Accounts with Login Shell",
                description=f"Service accounts with interactive shell: {', '.join(service_accounts_with_shell)}",
                severity=Severity.MEDIUM,
                passed=False,
                recommendation="Set shell to /usr/sbin/nologin or /bin/false for service accounts.",
                tags=["users"],
            ))

        # Guest account
        if any(u["name"] == "guest" for u in users):
            findings.append(Finding(
                title="Guest Account Exists",
                description="A 'guest' account was found.",
                severity=Severity.LOW,
                passed=False,
                recommendation="Remove or disable the guest account if not needed.",
                tags=["users"],
            ))

        # Recently created accounts (check /home mtime)
        week_ago = datetime.now() - timedelta(days=7)
        recent = []
        for u in real_users:
            home = Path("/home") / u
            if home.exists():
                mtime = datetime.fromtimestamp(home.stat().st_mtime)
                if mtime > week_ago:
                    recent.append(u)
        if recent:
            findings.append(Finding(
                title="Recently Created Accounts",
                description=f"Accounts created in last 7 days: {', '.join(recent)}",
                severity=Severity.LOW,
                passed=False,
                recommendation="Verify these accounts were intentionally created.",
                tags=["users"],
            ))

        # Empty passwords from /etc/shadow (root only)
        if IS_ROOT:
            shadow = self._read_file("/etc/shadow")
            empty_pw = []
            for line in shadow.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] in ("", "!!", ":"):
                    # Actually empty means no password
                    if parts[1] == "":
                        empty_pw.append(parts[0])
            if empty_pw:
                findings.append(Finding(
                    title="Accounts with Empty Passwords",
                    description=f"Accounts with no password: {', '.join(empty_pw)}",
                    severity=Severity.CRITICAL,
                    passed=False,
                    recommendation="Set passwords for all accounts or lock them with passwd -l <user>.",
                    tags=["users", "auth"],
                ))
            else:
                findings.append(Finding("Empty Password Check", "No accounts with empty passwords found.", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="Empty Password Check",
                description="Skipped: reading /etc/shadow requires root.",
                severity=Severity.INFO,
                passed=True,
            ))

        # SSH root login
        sshd_cfg = self._read_file("/etc/ssh/sshd_config")
        for line in sshd_cfg.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("permitrootlogin"):
                val = stripped.split(None, 1)[1].lower() if len(stripped.split()) > 1 else ""
                if val not in ("no", "prohibit-password", "forced-commands-only"):
                    findings.append(Finding(
                        title="Root SSH Login Enabled",
                        description=f"PermitRootLogin is set to '{val}' in sshd_config.",
                        severity=Severity.HIGH,
                        passed=False,
                        recommendation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config.",
                        tags=["ssh", "users"],
                    ))
                break

        return ModuleResult(
            module_name=self.name,
            module_display_name=self.display_name,
            findings=findings,
            duration_seconds=time.time() - t0,
        )
