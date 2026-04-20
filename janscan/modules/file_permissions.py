"""File Permissions audit module."""

import time
import os
import stat
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class FilePermissionsModule(BaseModule):
    name = "file_permissions"
    display_name = "File Permissions"
    description = "Checks critical file permissions, SUID/SGID binaries, and world-writable files."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # /etc/passwd permissions
        self._check_file_perms(findings, "/etc/passwd", 0o644, "CRITICAL", "/etc/passwd should be 644.")
        # /etc/shadow
        self._check_file_perms(findings, "/etc/shadow", 0o640, "CRITICAL", "/etc/shadow should be 640 (root:shadow).")
        # /etc/sudoers
        self._check_file_perms(findings, "/etc/sudoers", 0o440, "CRITICAL", "/etc/sudoers should be 440.")

        # Sticky bit on /tmp
        try:
            mode = os.stat("/tmp").st_mode
            if mode & stat.S_ISVTX:
                findings.append(Finding("Sticky Bit on /tmp", "/tmp has sticky bit set.", Severity.PASS, True))
            else:
                findings.append(Finding(
                    title="/tmp Missing Sticky Bit",
                    description="/tmp does not have the sticky bit set.",
                    severity=Severity.MEDIUM, passed=False,
                    recommendation="Set sticky bit: chmod +t /tmp",
                    tags=["permissions"],
                ))
        except Exception:
            pass

        # World-writable files in /etc
        stdout, _, rc = self._run_command(["find", "/etc", "-perm", "-o+w", "-type", "f"], timeout=15)
        if rc == 0 and stdout.strip():
            files = stdout.strip().splitlines()
            findings.append(Finding(
                title="World-Writable Files in /etc",
                description=f"Found {len(files)} world-writable file(s): {', '.join(files[:5])}{'...' if len(files) > 5 else ''}",
                severity=Severity.HIGH, passed=False,
                recommendation="Remove world-write permission: chmod o-w <file>",
                raw_output=stdout[:500],
                tags=["permissions"],
            ))
        else:
            findings.append(Finding("No World-Writable Files in /etc", "No world-writable files found in /etc.", Severity.PASS, True))

        # SUID binaries
        stdout, _, rc = self._run_command(
            ["find", "/usr", "/bin", "/sbin", "-perm", "-4000", "-type", "f"], timeout=15
        )
        if rc == 0 and stdout.strip():
            suid = stdout.strip().splitlines()
            expected_suid = {"sudo", "su", "passwd", "ping", "mount", "umount", "newgrp", "chsh", "chfn", "gpasswd"}
            unexpected = [f for f in suid if not any(e in f for e in expected_suid)]
            if unexpected:
                findings.append(Finding(
                    title="Unexpected SUID Binaries",
                    description=f"{len(unexpected)} unexpected SUID binary(ies): {', '.join(unexpected[:5])}",
                    severity=Severity.MEDIUM, passed=False,
                    recommendation="Review SUID binaries and remove if unnecessary: chmod u-s <file>",
                    raw_output="\n".join(unexpected[:20]),
                    tags=["permissions", "suid"],
                ))
            else:
                findings.append(Finding("SUID Binaries", f"{len(suid)} SUID binaries — all appear standard.", Severity.PASS, True))

        # SGID binaries
        stdout, _, rc = self._run_command(
            ["find", "/usr", "/bin", "/sbin", "-perm", "-2000", "-type", "f"], timeout=15
        )
        if rc == 0 and stdout.strip():
            sgid = stdout.strip().splitlines()
            findings.append(Finding(
                title="SGID Binaries Found",
                description=f"{len(sgid)} SGID binaries found.",
                severity=Severity.LOW, passed=False,
                recommendation="Review SGID binaries and remove if unnecessary.",
                raw_output="\n".join(sgid[:20]),
                tags=["permissions", "sgid"],
            ))

        # SSH private keys world-readable
        home = os.path.expanduser("~")
        ssh_dir = f"{home}/.ssh"
        if os.path.isdir(ssh_dir):
            stdout, _, rc = self._run_command(["find", ssh_dir, "-perm", "-o+r", "-name", "id_*"])
            if rc == 0 and stdout.strip():
                findings.append(Finding(
                    title="SSH Private Keys World-Readable",
                    description=f"World-readable private key(s): {stdout.strip()}",
                    severity=Severity.CRITICAL, passed=False,
                    recommendation="chmod 600 ~/.ssh/id_*",
                    tags=["ssh", "permissions"],
                ))
            else:
                findings.append(Finding("SSH Key Permissions OK", "SSH private keys are not world-readable.", Severity.PASS, True))

        # Home directories world-readable
        home_dirs = []
        try:
            for entry in os.scandir("/home"):
                if entry.is_dir():
                    mode = entry.stat().st_mode
                    if mode & stat.S_IROTH:
                        home_dirs.append(entry.name)
        except PermissionError:
            pass
        if home_dirs:
            findings.append(Finding(
                title="World-Readable Home Directories",
                description=f"Home dirs readable by all: {', '.join(home_dirs)}",
                severity=Severity.MEDIUM, passed=False,
                recommendation="chmod 750 /home/<user>",
                tags=["permissions"],
            ))
        else:
            findings.append(Finding("Home Directory Permissions OK", "No world-readable home directories.", Severity.PASS, True))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)

    def _check_file_perms(self, findings, path, expected_mode, sev_if_bad, rec):
        try:
            mode = os.stat(path).st_mode & 0o777
            if mode == expected_mode:
                findings.append(Finding(f"{path} Permissions OK", f"{path} is {oct(mode)}", Severity.PASS, True))
            else:
                findings.append(Finding(
                    title=f"Insecure Permissions: {path}",
                    description=f"{path} has permissions {oct(mode)}, expected {oct(expected_mode)}",
                    severity=Severity(sev_if_bad), passed=False,
                    recommendation=f"Fix with: chmod {oct(expected_mode)[2:]} {path}",
                    tags=["permissions"],
                ))
        except FileNotFoundError:
            findings.append(Finding(f"{path} not found", f"{path} does not exist.", Severity.INFO, True))
        except PermissionError:
            findings.append(Finding(f"{path} permission denied", f"Cannot stat {path} without root.", Severity.INFO, True))
