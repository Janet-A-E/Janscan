"""Disk Usage audit module."""

import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class DiskUsageModule(BaseModule):
    name = "disk_usage"
    display_name = "Disk Usage"
    description = "Checks disk space usage and inode usage across all partitions."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # df -h
        stdout, _, rc = self._run_command(["df", "-h", "--output=source,size,used,avail,pcent,target"])
        if rc == 0 and stdout:
            critical_partitions = []
            warning_partitions = []
            for line in stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    pct_str = parts[4].replace("%", "")
                    try:
                        pct = int(pct_str)
                        mount = parts[5]
                        if pct >= 95:
                            critical_partitions.append((mount, pct, parts[1]))
                        elif pct >= 85:
                            warning_partitions.append((mount, pct, parts[1]))
                    except ValueError:
                        pass

            for mount, pct, size in critical_partitions:
                findings.append(Finding(
                    title=f"Disk Critical: {mount} ({pct}%)",
                    description=f"{mount} is {pct}% full (size: {size}).",
                    severity=Severity.HIGH, passed=False,
                    recommendation=f"Free up space on {mount} immediately or expand partition.",
                    tags=["disk"],
                ))
            for mount, pct, size in warning_partitions:
                findings.append(Finding(
                    title=f"Disk Warning: {mount} ({pct}%)",
                    description=f"{mount} is {pct}% full (size: {size}).",
                    severity=Severity.MEDIUM, passed=False,
                    recommendation=f"Monitor disk usage on {mount} and clean up.",
                    tags=["disk"],
                ))
            if not critical_partitions and not warning_partitions:
                findings.append(Finding("Disk Usage OK", "All partitions below 85% usage.", Severity.PASS, True))

            findings.append(Finding("Disk Usage Overview", "df output captured.", Severity.INFO, True, raw_output=stdout[:600]))

        # df -i (inodes)
        stdout_i, _, rc_i = self._run_command(["df", "-i", "--output=source,iused,iavail,ipcent,target"])
        if rc_i == 0 and stdout_i:
            for line in stdout_i.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    pct_str = parts[3].replace("%", "")
                    try:
                        pct = int(pct_str)
                        if pct >= 90:
                            findings.append(Finding(
                                title=f"Inode Usage Critical: {parts[4]} ({pct}%)",
                                description=f"Inode usage at {pct}% on {parts[4]}.",
                                severity=Severity.HIGH, passed=False,
                                recommendation="Delete many small files or increase inode count.",
                                tags=["disk", "inodes"],
                            ))
                    except ValueError:
                        pass

        # /tmp size
        stdout, _, rc = self._run_command(["du", "-sh", "/tmp"])
        if rc == 0:
            findings.append(Finding("/tmp Size", stdout.split()[0] if stdout else "?", Severity.INFO, True))

        # /var/log size
        stdout, _, rc = self._run_command(["du", "-sh", "/var/log"])
        if rc == 0:
            findings.append(Finding("/var/log Size", stdout.split()[0] if stdout else "?", Severity.INFO, True))

        # Home directory sizes
        stdout, _, rc = self._run_command(["du", "-sh", "--", "/home/*"], timeout=15)
        if rc == 0 and stdout:
            findings.append(Finding("Home Directory Sizes", "Sizes captured.", Severity.INFO, True, raw_output=stdout[:300]))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
