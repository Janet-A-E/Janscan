"""Security Hygiene audit module."""

import time
import os
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class SecurityHygieneModule(BaseModule):
    name = "security_hygiene"
    display_name = "Security Hygiene"
    description = "Checks password policy, PAM lockout, umask, PATH, and security tools."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # Password policy
        pwquality = self._read_file("/etc/security/pwquality.conf")
        pam_pw = self._read_file("/etc/pam.d/common-password")
        combined = pwquality + pam_pw
        if "minlen" in combined or "pam_pwquality" in combined or "pam_cracklib" in combined:
            findings.append(Finding("Password Policy Configured", "Password quality policy found.", Severity.PASS, True, tags=["auth"]))
        else:
            findings.append(Finding(
                title="No Password Policy Found",
                description="No password complexity/length policy detected.",
                severity=Severity.HIGH, passed=False,
                recommendation="Install libpam-pwquality and configure /etc/security/pwquality.conf",
                tags=["auth", "passwords"],
            ))

        # Account lockout
        pam_auth = self._read_file("/etc/pam.d/common-auth")
        pam_sshd = self._read_file("/etc/pam.d/sshd")
        lockout_content = pam_auth + pam_sshd
        if "pam_faillock" in lockout_content or "pam_tally2" in lockout_content:
            findings.append(Finding("Account Lockout Policy", "pam_faillock/pam_tally2 configured.", Severity.PASS, True, tags=["auth"]))
        else:
            findings.append(Finding(
                title="No Account Lockout Policy",
                description="pam_faillock or pam_tally2 not found in PAM config.",
                severity=Severity.HIGH, passed=False,
                recommendation="Configure pam_faillock in /etc/pam.d/common-auth to lock accounts after failed attempts.",
                tags=["auth"],
            ))

        # Umask
        umask_ok = False
        for profile in ["/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", "/etc/login.defs"]:
            content = self._read_file(profile)
            if "umask 027" in content or "umask 077" in content:
                umask_ok = True
                break
            if "UMASK" in content:
                for line in content.splitlines():
                    if "UMASK" in line and not line.strip().startswith("#"):
                        val = line.split()[-1]
                        if val in ("027", "077", "022"):
                            umask_ok = True
        if umask_ok:
            findings.append(Finding("Umask Configured", "Restrictive umask (022/027/077) found.", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="Umask Not Explicitly Set",
                description="No restrictive umask found in system profiles.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Add 'umask 027' to /etc/profile or /etc/bash.bashrc",
                tags=["permissions"],
            ))

        # .bash_history permissions
        history = os.path.expanduser("~/.bash_history")
        if os.path.isfile(history):
            mode = oct(os.stat(history).st_mode & 0o777)
            if "6" in mode[2:] or "4" in mode[2:]:
                findings.append(Finding(
                    title="Bash History Readable by Others",
                    description=f"~/.bash_history permissions: {mode}",
                    severity=Severity.LOW, passed=False,
                    recommendation="chmod 600 ~/.bash_history",
                    tags=["privacy"],
                ))
            else:
                findings.append(Finding("Bash History Permissions OK", f"~/.bash_history: {mode}", Severity.PASS, True))

        # Core dumps
        limits = self._read_file("/etc/security/limits.conf")
        if "core" in limits and "0" in limits:
            findings.append(Finding("Core Dumps Disabled", "limits.conf restricts core dumps.", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="Core Dumps Not Restricted",
                description="No core dump restriction found in limits.conf.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Add '* hard core 0' to /etc/security/limits.conf",
                tags=["security"],
            ))

        # USB storage blacklisted
        usb_bl = self._read_file("/etc/modprobe.d/blacklist.conf")
        usb_bl2 = self._read_file("/etc/modprobe.d/blacklist-usb.conf")
        if "usb-storage" in usb_bl or "usb-storage" in usb_bl2:
            findings.append(Finding("USB Storage Blacklisted", "usb-storage module is blacklisted.", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="USB Storage Not Blacklisted",
                description="usb-storage module is not blacklisted.",
                severity=Severity.LOW, passed=False,
                recommendation="Add 'blacklist usb-storage' to /etc/modprobe.d/blacklist.conf if USB not needed.",
                tags=["hardware"],
            ))

        # .rhosts / .netrc
        stdout, _, rc = self._run_command(["find", "/home", "/root", "-name", ".rhosts", "-o", "-name", ".netrc"], timeout=10)
        if rc == 0 and stdout.strip():
            findings.append(Finding(
                title="Dangerous Config Files Found (.rhosts/.netrc)",
                description=f"Files: {stdout.strip()}",
                severity=Severity.HIGH, passed=False,
                recommendation="Delete .rhosts and .netrc files immediately.",
                tags=["auth"],
            ))
        else:
            findings.append(Finding("No .rhosts/.netrc Files", "No .rhosts or .netrc files found.", Severity.PASS, True))

        # Cron permissions
        import stat
        cron_issues = []
        for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/crontab"]:
            if os.path.exists(cron_dir):
                try:
                    st = os.stat(cron_dir)
                    if st.st_uid != 0:
                        cron_issues.append(f"{cron_dir} not owned by root")
                except Exception:
                    pass
        if cron_issues:
            findings.append(Finding(
                title="Cron Permission Issues",
                description="; ".join(cron_issues),
                severity=Severity.MEDIUM, passed=False,
                recommendation="Ensure cron dirs are owned by root: chown root:root /etc/cron.*",
                tags=["cron"],
            ))
        else:
            findings.append(Finding("Cron Permissions OK", "Cron directories are root-owned.", Severity.PASS, True))

        # PATH contains '.'
        path_val = os.environ.get("PATH", "")
        if ":." in path_val or path_val.startswith("."):
            findings.append(Finding(
                title="PATH Contains '.'",
                description=f"Current PATH has '.': {path_val}",
                severity=Severity.HIGH, passed=False,
                recommendation="Remove '.' from PATH environment variable.",
                tags=["security"],
            ))
        else:
            findings.append(Finding("PATH Secure", "'.' not in PATH.", Severity.PASS, True))

        # Antivirus/rootkit tools
        av_tools = []
        for tool in ["clamav", "rkhunter", "chkrootkit", "lynis"]:
            stdout, _, rc = self._run_command(["which", tool])
            if rc == 0 and stdout.strip():
                av_tools.append(tool)
        if av_tools:
            findings.append(Finding("Security Scanning Tools Installed", f"Found: {', '.join(av_tools)}", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="No Security Scanning Tools Installed",
                description="No antivirus or rootkit scanner found.",
                severity=Severity.LOW, passed=False,
                recommendation="Install rkhunter or clamav: sudo apt install rkhunter",
                tags=["security"],
            ))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
