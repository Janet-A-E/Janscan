"""Active Network Connections audit module."""

import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 6666, 9001, 8888, 12345, 54321}
RFC1918 = [("10.", True), ("172.16.", True), ("172.17.", True), ("172.18.", True),
           ("172.19.", True), ("172.20.", True), ("172.21.", True), ("172.22.", True),
           ("172.23.", True), ("172.24.", True), ("172.25.", True), ("172.26.", True),
           ("172.27.", True), ("172.28.", True), ("172.29.", True), ("172.30.", True),
           ("172.31.", True), ("192.168.", True), ("127.", True), ("::1", True)]

def is_private(ip):
    return any(ip.startswith(prefix) for prefix, _ in RFC1918)


class ActiveConnectionsModule(BaseModule):
    name = "active_connections"
    display_name = "Active Connections"
    description = "Audits active TCP connections for suspicious activity."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        stdout, _, rc = self._run_command(["ss", "-tnp", "state", "established"])
        if rc != 0:
            stdout, _, rc = self._run_command(["netstat", "-tnp"])

        connections = []
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                if not line or line.startswith("Netid") or line.startswith("State"):
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    connections.append(line)

        findings.append(Finding(
            title=f"Active TCP Connections ({len(connections)})",
            description=f"{len(connections)} established connections.",
            severity=Severity.INFO, passed=True,
            raw_output="\n".join(connections[:50]),
        ))

        # Check for suspicious ports
        suspicious = []
        for line in connections:
            for port in SUSPICIOUS_PORTS:
                if f":{port}" in line or f":{port} " in line:
                    suspicious.append((port, line.strip()))
        if suspicious:
            for port, line in suspicious:
                findings.append(Finding(
                    title=f"Connection to Suspicious Port {port}",
                    description=f"Active connection involving port {port}: {line[:120]}",
                    severity=Severity.HIGH, passed=False,
                    recommendation="Investigate immediately — port may indicate backdoor/C2.",
                    tags=["network", "connections"],
                ))

        # Too many connections
        if len(connections) > 50:
            findings.append(Finding(
                title=f"High Connection Count ({len(connections)})",
                description=f"{len(connections)} active connections — possible DoS or unusual activity.",
                severity=Severity.LOW, passed=False,
                recommendation="Review connections with: ss -tnp state established",
                tags=["network"],
            ))

        # TIME_WAIT count
        stdout_tw, _, rc_tw = self._run_command(["ss", "-tn", "state", "time-wait"])
        if rc_tw == 0:
            tw_count = max(0, len(stdout_tw.strip().splitlines()) - 1)
            findings.append(Finding(
                f"TIME_WAIT Connections: {tw_count}",
                f"{tw_count} connections in TIME_WAIT state.",
                Severity.INFO, True,
            ))

        # Foreign (non-RFC1918) connections
        foreign = []
        for line in connections:
            parts = line.split()
            for part in parts:
                if ":" in part:
                    ip = part.rsplit(":", 1)[0].strip("[]")
                    if ip and not is_private(ip) and ip not in ("0.0.0.0", "*", "::"):
                        foreign.append(ip)
                        break
        if foreign:
            unique_foreign = list(set(foreign))
            findings.append(Finding(
                title=f"External Connections ({len(unique_foreign)} unique IPs)",
                description=f"Connections to non-private IPs: {', '.join(unique_foreign[:10])}",
                severity=Severity.INFO, passed=True,
                tags=["network"],
            ))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
