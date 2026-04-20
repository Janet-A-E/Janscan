"""SSH Security audit module."""

import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class SSHSecurityModule(BaseModule):
    name = "ssh_security"
    display_name = "SSH Security"
    description = "Audits SSH daemon configuration for security best practices."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        sshd_cfg = self._read_file("/etc/ssh/sshd_config")
        if not sshd_cfg:
            findings.append(Finding(
                title="sshd_config not found",
                description="/etc/ssh/sshd_config could not be read.",
                severity=Severity.INFO,
                passed=True,
            ))
            return ModuleResult(self.name, self.display_name, findings, time.time() - t0)

        config = {}
        for line in sshd_cfg.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                parts = stripped.split(None, 1)
                if len(parts) == 2:
                    config[parts[0].lower()] = parts[1].lower()

        # PermitRootLogin
        val = config.get("permitrootlogin", "yes")
        if val in ("no", "prohibit-password", "forced-commands-only"):
            findings.append(Finding("Root Login Disabled", f"PermitRootLogin={val}", Severity.PASS, True, tags=["ssh"]))
        else:
            findings.append(Finding(
                title="Root Login Enabled via SSH",
                description=f"PermitRootLogin={val}",
                severity=Severity.HIGH, passed=False,
                recommendation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
                tags=["ssh", "auth"],
            ))

        # PasswordAuthentication
        val = config.get("passwordauthentication", "yes")
        if val == "no":
            findings.append(Finding("Password Auth Disabled", "PasswordAuthentication=no", Severity.PASS, True, tags=["ssh"]))
        else:
            findings.append(Finding(
                title="SSH Password Authentication Enabled",
                description="PasswordAuthentication=yes — key-based auth not enforced.",
                severity=Severity.HIGH, passed=False,
                recommendation="Set 'PasswordAuthentication no' and use SSH keys only.",
                tags=["ssh", "auth"],
            ))

        # PermitEmptyPasswords
        val = config.get("permitemptypasswords", "no")
        if val == "no":
            findings.append(Finding("Empty Password Login Disabled", "PermitEmptyPasswords=no", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="Empty Password SSH Login Allowed",
                description="PermitEmptyPasswords=yes",
                severity=Severity.CRITICAL, passed=False,
                recommendation="Set 'PermitEmptyPasswords no' in sshd_config.",
                tags=["ssh", "auth"],
            ))

        # X11Forwarding
        val = config.get("x11forwarding", "no")
        if val == "no":
            findings.append(Finding("X11 Forwarding Disabled", "X11Forwarding=no", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="X11 Forwarding Enabled",
                description="X11Forwarding=yes — potential attack vector.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Set 'X11Forwarding no' unless required.",
                tags=["ssh"],
            ))

        # MaxAuthTries
        val = config.get("maxauthtries", "6")
        try:
            n = int(val)
            if n <= 3:
                findings.append(Finding("MaxAuthTries Set Low", f"MaxAuthTries={n}", Severity.PASS, True))
            else:
                findings.append(Finding(
                    title="MaxAuthTries Too High",
                    description=f"MaxAuthTries={n} — allows many brute-force attempts.",
                    severity=Severity.MEDIUM, passed=False,
                    recommendation="Set 'MaxAuthTries 3' in sshd_config.",
                    tags=["ssh", "brute-force"],
                ))
        except ValueError:
            pass

        # SSH Port
        port = config.get("port", "22")
        if port == "22":
            findings.append(Finding(
                title="SSH on Default Port 22",
                description="Using default port 22 increases exposure to automated scans.",
                severity=Severity.LOW, passed=False,
                recommendation="Consider changing to a non-standard port.",
                tags=["ssh"],
            ))
        else:
            findings.append(Finding(f"SSH Non-Default Port", f"Port={port}", Severity.PASS, True))

        # AllowUsers / AllowGroups
        if "allowusers" in config or "allowgroups" in config:
            findings.append(Finding("SSH Access Restriction", "AllowUsers/AllowGroups defined.", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="No SSH Access Restrictions",
                description="AllowUsers/AllowGroups not set — any valid user can SSH in.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Add 'AllowUsers <user>' to restrict SSH access.",
                tags=["ssh"],
            ))

        # Banner
        if "banner" in config:
            findings.append(Finding("SSH Banner Configured", f"Banner={config['banner']}", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="No SSH Warning Banner",
                description="SSH Banner not configured.",
                severity=Severity.LOW, passed=False,
                recommendation="Set 'Banner /etc/issue.net' for legal warning on login.",
                tags=["ssh"],
            ))

        # UsePAM
        val = config.get("usepam", "no")
        findings.append(Finding("UsePAM", f"UsePAM={val}", Severity.INFO, True))

        # Weak ciphers
        ciphers = config.get("ciphers", "")
        weak = [c for c in ["arcfour", "des", "3des"] if c in ciphers]
        if weak:
            findings.append(Finding(
                title="Weak SSH Ciphers Configured",
                description=f"Weak ciphers detected: {', '.join(weak)}",
                severity=Severity.HIGH, passed=False,
                recommendation="Remove weak ciphers from sshd_config Ciphers directive.",
                tags=["ssh", "crypto"],
            ))

        # Weak MACs
        macs = config.get("macs", "")
        if "md5" in macs:
            findings.append(Finding(
                title="Weak SSH MACs Configured",
                description="MD5-based MACs detected in sshd_config.",
                severity=Severity.HIGH, passed=False,
                recommendation="Remove hmac-md5 from MACs directive.",
                tags=["ssh", "crypto"],
            ))

        # SSH service status
        stdout, _, rc = self._run_command(["systemctl", "is-active", "sshd"])
        if rc == 0:
            findings.append(Finding("SSH Service Running", "sshd is active.", Severity.INFO, True))
        else:
            stdout2, _, rc2 = self._run_command(["systemctl", "is-active", "ssh"])
            if rc2 == 0:
                findings.append(Finding("SSH Service Running", "ssh is active.", Severity.INFO, True))
            else:
                findings.append(Finding("SSH Service Not Running", "sshd/ssh not active.", Severity.INFO, True))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
