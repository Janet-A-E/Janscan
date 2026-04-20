"""System Health audit module."""

import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class SystemHealthModule(BaseModule):
    name = "system_health"
    display_name = "System Health"
    description = "Checks CPU, memory, swap, load average, and process health."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        try:
            import psutil

            # CPU usage
            cpu_pct = psutil.cpu_percent(interval=1)
            if cpu_pct > 90:
                findings.append(Finding(
                    title=f"High CPU Usage ({cpu_pct:.1f}%)",
                    description=f"CPU usage is critically high at {cpu_pct:.1f}%.",
                    severity=Severity.HIGH, passed=False,
                    recommendation="Investigate high-CPU processes: top or htop",
                    tags=["health", "cpu"],
                ))
            else:
                findings.append(Finding(f"CPU Usage: {cpu_pct:.1f}%", "CPU usage is normal.", Severity.PASS, True))

            # Memory
            mem = psutil.virtual_memory()
            mem_pct = mem.percent
            mem_used = mem.used // (1024 ** 2)
            mem_total = mem.total // (1024 ** 2)
            if mem_pct > 90:
                findings.append(Finding(
                    title=f"High Memory Usage ({mem_pct:.1f}%)",
                    description=f"{mem_used}MB / {mem_total}MB used.",
                    severity=Severity.HIGH, passed=False,
                    recommendation="Free up memory or add RAM.",
                    tags=["health", "memory"],
                ))
            else:
                findings.append(Finding(f"Memory Usage: {mem_pct:.1f}%", f"{mem_used}MB / {mem_total}MB", Severity.PASS, True))

            # Swap
            swap = psutil.swap_memory()
            if swap.total > 0:
                swap_pct = swap.percent
                if swap_pct > 80:
                    findings.append(Finding(
                        title=f"High Swap Usage ({swap_pct:.1f}%)",
                        description=f"Swap at {swap_pct:.1f}% — system may be memory-constrained.",
                        severity=Severity.MEDIUM, passed=False,
                        recommendation="Reduce memory usage or increase RAM.",
                        tags=["health", "swap"],
                    ))
                else:
                    findings.append(Finding(f"Swap Usage: {swap_pct:.1f}%", "Swap usage is normal.", Severity.PASS, True))
            else:
                findings.append(Finding("No Swap Configured", "System has no swap.", Severity.INFO, True))

            # Temperatures
            try:
                temps = psutil.sensors_temperatures()
                if temps:
                    for sensor, readings in temps.items():
                        for r in readings:
                            if r.current and r.current > 85:
                                findings.append(Finding(
                                    title=f"High Temperature: {sensor} ({r.current:.1f}°C)",
                                    description=f"Sensor '{r.label or sensor}' at {r.current:.1f}°C — above safe threshold.",
                                    severity=Severity.HIGH, passed=False,
                                    recommendation="Check system cooling and airflow.",
                                    tags=["health", "hardware"],
                                ))
                            elif r.current:
                                findings.append(Finding(f"Temp: {sensor}", f"{r.current:.1f}°C", Severity.INFO, True))
            except Exception:
                findings.append(Finding("Temperature Sensors", "Not available on this system.", Severity.INFO, True))

            # Battery
            try:
                batt = psutil.sensors_battery()
                if batt:
                    findings.append(Finding(
                        "Battery Status",
                        f"{batt.percent:.1f}% ({'charging' if batt.power_plugged else 'discharging'})",
                        Severity.INFO, True,
                    ))
            except Exception:
                pass

        except ImportError:
            findings.append(Finding("psutil Unavailable", "Install psutil for health checks.", Severity.INFO, True))

        # Load average
        loadavg = self._read_file("/proc/loadavg")
        if loadavg:
            parts = loadavg.split()
            load1, load5, load15 = float(parts[0]), float(parts[1]), float(parts[2])

            # Get CPU count
            try:
                import os
                cpu_count = os.cpu_count() or 1
            except Exception:
                cpu_count = 1

            if load1 > cpu_count * 2:
                findings.append(Finding(
                    title=f"High Load Average ({load1:.2f})",
                    description=f"1-min load {load1:.2f} exceeds {cpu_count * 2} (2x CPU count of {cpu_count}).",
                    severity=Severity.MEDIUM, passed=False,
                    recommendation="Investigate high-load processes with 'top' or 'htop'.",
                    tags=["health"],
                ))
            else:
                findings.append(Finding(f"Load Average: {load1:.2f} / {load5:.2f} / {load15:.2f}", "Load within normal range.", Severity.PASS, True))

        # Zombie processes
        stdout, _, rc = self._run_command(["ps", "aux"])
        if rc == 0:
            zombies = [l for l in stdout.splitlines() if " Z " in l or "zombie" in l.lower()]
            if zombies:
                findings.append(Finding(
                    title=f"Zombie Processes Detected ({len(zombies)})",
                    description=f"{len(zombies)} zombie process(es) found.",
                    severity=Severity.MEDIUM, passed=False,
                    recommendation="Investigate zombie processes and restart parent or reboot.",
                    raw_output="\n".join(zombies[:10]),
                    tags=["health", "processes"],
                ))
            else:
                findings.append(Finding("No Zombie Processes", "No zombie processes found.", Severity.PASS, True))

        # OOM killer events
        stdout, _, rc = self._run_command(["dmesg"], timeout=10)
        if rc == 0:
            oom = [l for l in stdout.splitlines() if "out of memory" in l.lower() or "oom" in l.lower()]
            if oom:
                findings.append(Finding(
                    title=f"OOM Killer Events ({len(oom)})",
                    description="Out-of-memory events detected in kernel log.",
                    severity=Severity.HIGH, passed=False,
                    recommendation="Add more RAM or reduce memory usage.",
                    raw_output="\n".join(oom[-5:]),
                    tags=["health", "memory"],
                ))
            else:
                findings.append(Finding("No OOM Events", "No out-of-memory events in dmesg.", Severity.PASS, True))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
