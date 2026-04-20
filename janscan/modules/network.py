"""Network Configuration audit module."""

import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class NetworkModule(BaseModule):
    name = "network"
    display_name = "Network Configuration"
    description = "Audits kernel network parameters and network configuration."
    requires_root = False

    def _read_proc(self, path):
        val = self._read_file(path).strip()
        return val

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        checks = [
            ("/proc/sys/net/ipv4/ip_forward",                    "0", "IP Forwarding",         "IP forwarding enabled — system may route traffic.",   Severity.HIGH,   "echo 0 > /proc/sys/net/ipv4/ip_forward"),
            ("/proc/sys/net/ipv4/conf/all/accept_redirects",     "0", "ICMP Redirects",        "Accepting ICMP redirects — can be used for MITM.",    Severity.MEDIUM, "sysctl -w net.ipv4.conf.all.accept_redirects=0"),
            ("/proc/sys/net/ipv4/conf/all/accept_source_route",  "0", "Source Routing",        "Source routing enabled — security risk.",              Severity.HIGH,   "sysctl -w net.ipv4.conf.all.accept_source_route=0"),
            ("/proc/sys/net/ipv4/tcp_syncookies",                "1", "SYN Flood Protection",  "SYN cookies disabled — vulnerable to SYN floods.",    Severity.HIGH,   "sysctl -w net.ipv4.tcp_syncookies=1"),
            ("/proc/sys/net/ipv4/conf/all/rp_filter",            "1", "Reverse Path Filter",   "Reverse path filtering disabled.",                    Severity.MEDIUM, "sysctl -w net.ipv4.conf.all.rp_filter=1"),
            ("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",   "1", "ICMP Broadcast Ping",   "System responds to broadcast pings — smurf attack risk.", Severity.MEDIUM, "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"),
        ]

        for proc_path, good_val, title, bad_desc, severity, fix in checks:
            val = self._read_proc(proc_path)
            if not val:
                findings.append(Finding(f"{title}: unavailable", f"Could not read {proc_path}", Severity.INFO, True))
                continue
            if val == good_val:
                findings.append(Finding(f"{title}: OK", f"{proc_path} = {val}", Severity.PASS, True))
            else:
                findings.append(Finding(
                    title=f"{title}: Misconfigured",
                    description=f"{bad_desc} ({proc_path} = {val})",
                    severity=severity, passed=False,
                    recommendation=f"Fix: {fix}",
                    tags=["network", "kernel"],
                ))

        # Network interfaces
        stdout, _, rc = self._run_command(["ip", "link", "show"])
        if rc == 0:
            ifaces = [l.split(":")[1].strip() for l in stdout.splitlines() if l and l[0].isdigit()]
            findings.append(Finding("Network Interfaces", f"Interfaces: {', '.join(ifaces)}", Severity.INFO, True, raw_output=stdout[:300]))

        # DNS servers
        resolv = self._read_file("/etc/resolv.conf")
        dns = [l.split()[1] for l in resolv.splitlines() if l.startswith("nameserver")]
        if dns:
            findings.append(Finding("DNS Servers", f"Configured: {', '.join(dns)}", Severity.INFO, True))
        else:
            findings.append(Finding("No DNS Configured", "/etc/resolv.conf has no nameservers.", Severity.MEDIUM, False,
                recommendation="Configure DNS servers in /etc/resolv.conf"))

        # Hosts file
        hosts = self._read_file("/etc/hosts")
        suspicious = []
        for line in hosts.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                parts = stripped.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    names = parts[1:]
                    # Suspicious: localhost mapped to non-127 IP
                    if any(n in ("localhost", "localhost.localdomain") for n in names) and not ip.startswith("127."):
                        suspicious.append(stripped)
        if suspicious:
            findings.append(Finding(
                title="Suspicious /etc/hosts Entries",
                description=f"Suspicious entries: {'; '.join(suspicious[:5])}",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Review /etc/hosts for unauthorized entries.",
                tags=["network"],
            ))
        else:
            findings.append(Finding("/etc/hosts Clean", "No suspicious entries in /etc/hosts.", Severity.PASS, True))

        # IPv6 disabled
        val = self._read_proc("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        if val == "1":
            findings.append(Finding("IPv6 Disabled", "IPv6 is disabled system-wide.", Severity.INFO, True))
        else:
            findings.append(Finding("IPv6 Enabled", "IPv6 is active — ensure firewall covers IPv6.", Severity.LOW, False,
                recommendation="If IPv6 is unused, disable it or ensure ip6tables rules are configured."))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
