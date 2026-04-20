"""Open Listening Ports audit module."""

import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity

RISKY_PORTS = {23: "Telnet", 21: "FTP", 513: "rlogin", 514: "rsh", 515: "printer", 111: "portmapper", 2049: "NFS"}

class OpenPortsModule(BaseModule):
    name = "open_ports"
    display_name = "Open Listening Ports"
    description = "Enumerates all TCP/UDP listening ports and flags dangerous ones."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        ports = []

        # Try ss first, fall back to netstat
        stdout, _, rc = self._run_command(["ss", "-tlnp"])
        if rc != 0:
            stdout, _, rc = self._run_command(["netstat", "-tlnp"])

        if rc == 0 and stdout:
            for line in stdout.splitlines()[1:]:
                parts = line.split()
                if not parts:
                    continue
                # Parse address:port
                for part in parts:
                    if ":" in part:
                        segments = part.rsplit(":", 1)
                        if len(segments) == 2 and segments[1].isdigit():
                            port_num = int(segments[1])
                            bind_addr = segments[0]
                            proc = ""
                            for p in parts:
                                if "pid=" in p or ("," in p and "/" in p):
                                    proc = p
                            ports.append({
                                "port": port_num,
                                "proto": "tcp",
                                "bind": bind_addr,
                                "process": proc,
                            })
                            break

        # UDP ports
        stdout_udp, _, rc_udp = self._run_command(["ss", "-ulnp"])
        udp_ports = []
        if rc_udp == 0 and stdout_udp:
            for line in stdout_udp.splitlines()[1:]:
                parts = line.split()
                for part in parts:
                    if ":" in part:
                        seg = part.rsplit(":", 1)
                        if len(seg) == 2 and seg[1].isdigit():
                            udp_ports.append({"port": int(seg[1]), "proto": "udp", "bind": seg[0], "process": ""})
                            break

        all_ports = ports + udp_ports

        findings.append(Finding(
            title=f"Open Listening Ports ({len(all_ports)})",
            description=f"TCP: {len(ports)}, UDP: {len(udp_ports)} listening ports found.",
            severity=Severity.INFO, passed=True,
            raw_output="\n".join(f"{p['proto']}:{p['port']} [{p['bind']}]" for p in all_ports[:50]),
        ))

        # Risky ports
        for p in all_ports:
            if p["port"] in RISKY_PORTS:
                svc = RISKY_PORTS[p["port"]]
                findings.append(Finding(
                    title=f"Dangerous Port Open: {p['port']} ({svc})",
                    description=f"Port {p['port']} ({svc}) is listening on {p['bind']}.",
                    severity=Severity.CRITICAL, passed=False,
                    recommendation=f"Disable {svc} service immediately.",
                    tags=["ports", "network"],
                ))

        # Web servers
        web_ports = [p for p in all_ports if p["port"] in (80, 443, 8080, 8443)]
        if web_ports:
            findings.append(Finding(
                title="Web Server Ports Open",
                description=f"Port(s) open: {', '.join(str(p['port']) for p in web_ports)}",
                severity=Severity.LOW, passed=False,
                recommendation="Verify web server is intentionally exposed.",
                tags=["ports", "web"],
            ))

        # Ports on 0.0.0.0
        exposed = [p for p in all_ports if p["bind"] in ("0.0.0.0", "*", "[::]", "::")]
        if exposed:
            findings.append(Finding(
                title=f"Ports Exposed to All Interfaces ({len(exposed)})",
                description=f"{len(exposed)} port(s) listening on 0.0.0.0/:: (all interfaces).",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Bind services to 127.0.0.1 where possible.",
                raw_output="\n".join(f"{p['proto']}:{p['port']}" for p in exposed[:20]),
                tags=["ports", "network"],
            ))

        # Too many open ports
        if len(all_ports) > 20:
            findings.append(Finding(
                title=f"High Number of Open Ports ({len(all_ports)})",
                description=f"{len(all_ports)} listening ports — reduce attack surface.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Disable unused services.",
                tags=["ports"],
            ))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
