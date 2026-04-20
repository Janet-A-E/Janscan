"""System Information module."""

import sys
import socket
import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class SystemInfoModule(BaseModule):
    name = "system_info"
    display_name = "System Information"
    description = "Collects basic system information (OS, kernel, CPU, RAM, uptime)."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # OS distribution
        os_release = self._read_file("/etc/os-release")
        os_name = "Unknown"
        for line in os_release.splitlines():
            if line.startswith("PRETTY_NAME="):
                os_name = line.split("=", 1)[1].strip('"')
                break
        findings.append(Finding("OS Distribution", os_name, Severity.INFO, True))

        # Kernel version
        stdout, _, _ = self._run_command(["uname", "-r"])
        findings.append(Finding("Kernel Version", stdout or "Unknown", Severity.INFO, True))

        # Hostname
        findings.append(Finding("Hostname", socket.gethostname(), Severity.INFO, True))

        # Architecture
        stdout, _, _ = self._run_command(["uname", "-m"])
        findings.append(Finding("Architecture", stdout or "Unknown", Severity.INFO, True))

        # Uptime
        uptime_raw = self._read_file("/proc/uptime")
        if uptime_raw:
            seconds = float(uptime_raw.split()[0])
            d, rem = divmod(int(seconds), 86400)
            h, rem = divmod(rem, 3600)
            m = rem // 60
            uptime_str = f"{d}d {h}h {m}m"
        else:
            uptime_str = "Unknown"
        findings.append(Finding("Uptime", uptime_str, Severity.INFO, True))

        # CPU
        cpuinfo = self._read_file("/proc/cpuinfo")
        cpu_model = "Unknown"
        for line in cpuinfo.splitlines():
            if "model name" in line:
                cpu_model = line.split(":", 1)[1].strip()
                break
        findings.append(Finding("CPU Model", cpu_model, Severity.INFO, True))

        # RAM
        meminfo = self._read_file("/proc/meminfo")
        mem_total = "Unknown"
        for line in meminfo.splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                mem_total = f"{kb // 1024} MB"
                break
        findings.append(Finding("Total RAM", mem_total, Severity.INFO, True))

        # Python version
        findings.append(Finding("Python Version", sys.version.split()[0], Severity.INFO, True))

        # Timezone
        stdout, _, _ = self._run_command(["timedatectl", "show", "--property=Timezone", "--value"])
        tz = stdout or "Unknown"
        findings.append(Finding("System Timezone", tz, Severity.INFO, True))

        # Last boot
        stdout, _, _ = self._run_command(["who", "-b"])
        boot_time = stdout.strip() if stdout else "Unknown"
        findings.append(Finding("Last Boot", boot_time, Severity.INFO, True))

        return ModuleResult(
            module_name=self.name,
            module_display_name=self.display_name,
            findings=findings,
            duration_seconds=time.time() - t0,
        )
