"""IP Addresses audit module."""

import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class IPAddressesModule(BaseModule):
    name = "ip_addresses"
    display_name = "IP Addresses"
    description = "Enumerates all network interfaces, IPs, MACs, and VPN detection."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # ip addr
        stdout, _, rc = self._run_command(["ip", "addr", "show"])
        if rc == 0 and stdout:
            findings.append(Finding("Network Interfaces & IPs", "Interface data captured.", Severity.INFO, True, raw_output=stdout[:800]))

            # Parse IPs
            ipv4s, ipv6s = [], []
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "127." not in line:
                    ipv4s.append(line.split()[1])
                elif line.startswith("inet6 ") and "::1" not in line and "fe80" not in line:
                    ipv6s.append(line.split()[1])

            if ipv4s:
                findings.append(Finding("IPv4 Addresses", f"{', '.join(ipv4s)}", Severity.INFO, True))
            if ipv6s:
                findings.append(Finding("IPv6 Addresses", f"{', '.join(ipv6s)}", Severity.INFO, True))

        # MAC addresses
        stdout_mac, _, rc_mac = self._run_command(["ip", "link", "show"])
        if rc_mac == 0:
            macs = []
            for line in stdout_mac.splitlines():
                if "link/ether" in line:
                    parts = line.split()
                    idx = parts.index("link/ether")
                    macs.append(parts[idx + 1])
            if macs:
                findings.append(Finding("MAC Addresses", f"{', '.join(macs)}", Severity.INFO, True))

        # VPN detection
        vpn_ifaces = []
        for iface_prefix in ["tun", "tap", "wg", "vpn", "ppp", "ipsec"]:
            if stdout_mac and iface_prefix in stdout_mac.lower():
                vpn_ifaces.append(iface_prefix)
        if vpn_ifaces:
            findings.append(Finding("VPN Interface Detected", f"VPN-like interfaces: {', '.join(vpn_ifaces)}", Severity.INFO, True, tags=["vpn"]))
        else:
            findings.append(Finding("No VPN Interface Detected", "No VPN interfaces found.", Severity.INFO, True))

        # Loopback
        lo_up = False
        if stdout:
            for line in stdout.splitlines():
                if "lo:" in line and "UP" in line:
                    lo_up = True
                    break
        findings.append(Finding("Loopback Interface", "lo is UP." if lo_up else "lo may be down.", Severity.PASS if lo_up else Severity.MEDIUM, lo_up))

        # Public IP (best-effort, may fail offline)
        pub_stdout, _, rc_pub = self._run_command(["curl", "-s", "--max-time", "5", "https://api.ipify.org"])
        if rc_pub == 0 and pub_stdout.strip():
            findings.append(Finding("Public IP Address", pub_stdout.strip(), Severity.INFO, True))
        else:
            findings.append(Finding("Public IP Unavailable", "Could not reach ipify.org.", Severity.INFO, True))

        # Network namespaces (root)
        stdout_ns, _, rc_ns = self._run_command(["ip", "netns", "list"])
        if rc_ns == 0:
            ns = [l.strip() for l in stdout_ns.splitlines() if l.strip()]
            findings.append(Finding(
                f"Network Namespaces ({len(ns)})",
                f"{', '.join(ns) if ns else 'None'}",
                Severity.INFO, True,
            ))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
