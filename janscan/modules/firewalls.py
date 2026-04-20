"""Firewall Configuration audit module."""

import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity
from janscan import IS_ROOT


class FirewallsModule(BaseModule):
    name = "firewalls"
    display_name = "Firewall Configuration"
    description = "Checks ufw, firewalld, iptables, and nftables firewall status."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        active_firewalls = []

        # UFW
        stdout, _, rc = self._run_command(["ufw", "status"])
        if rc != -1:
            if "active" in stdout.lower():
                active_firewalls.append("ufw")
                findings.append(Finding("UFW Firewall Active", stdout[:200], Severity.PASS, True, tags=["firewall"]))
            else:
                findings.append(Finding(
                    title="UFW Firewall Inactive",
                    description="UFW is installed but not active.",
                    severity=Severity.HIGH, passed=False,
                    recommendation="Enable UFW: sudo ufw enable",
                    tags=["firewall"],
                ))

        # firewalld
        stdout, _, rc = self._run_command(["systemctl", "is-active", "firewalld"])
        if rc != -1:
            if stdout.strip() == "active":
                active_firewalls.append("firewalld")
                findings.append(Finding("firewalld Active", "firewalld service is running.", Severity.PASS, True, tags=["firewall"]))
            else:
                findings.append(Finding(
                    title="firewalld Inactive",
                    description="firewalld service is not running.",
                    severity=Severity.INFO, passed=True,
                    tags=["firewall"],
                ))

        # iptables
        stdout, _, rc = self._run_command(["iptables", "-L", "-n"])
        if rc == 0:
            if "ACCEPT" in stdout and stdout.count("\n") > 5:
                findings.append(Finding("iptables Rules Present", "iptables has rules configured.", Severity.INFO, True, tags=["firewall"]))
                active_firewalls.append("iptables")
                # Check default INPUT policy
                for line in stdout.splitlines():
                    if "Chain INPUT" in line and "policy ACCEPT" in line:
                        findings.append(Finding(
                            title="iptables INPUT Default ACCEPT",
                            description="iptables INPUT chain default policy is ACCEPT.",
                            severity=Severity.HIGH, passed=False,
                            recommendation="Set default INPUT policy to DROP: iptables -P INPUT DROP",
                            tags=["firewall", "iptables"],
                        ))
                    elif "Chain FORWARD" in line and "policy ACCEPT" in line:
                        findings.append(Finding(
                            title="iptables FORWARD Default ACCEPT",
                            description="iptables FORWARD chain default policy is ACCEPT.",
                            severity=Severity.HIGH, passed=False,
                            recommendation="Set: iptables -P FORWARD DROP",
                            tags=["firewall"],
                        ))
            else:
                findings.append(Finding(
                    title="iptables Empty or Default Rules",
                    description="iptables appears to have no meaningful rules.",
                    severity=Severity.INFO, passed=True,
                    tags=["firewall"],
                ))
        else:
            findings.append(Finding("iptables Not Available", "iptables command not found or requires root.", Severity.INFO, True))

        # nftables
        stdout, _, rc = self._run_command(["nft", "list", "ruleset"])
        if rc == 0:
            if stdout.strip():
                active_firewalls.append("nftables")
                findings.append(Finding("nftables Rules Present", "nftables has ruleset configured.", Severity.PASS, True, tags=["firewall"]))
            else:
                findings.append(Finding(
                    title="nftables Empty Ruleset",
                    description="nftables is available but has no rules.",
                    severity=Severity.INFO, passed=True,
                    tags=["firewall"],
                ))

        # IPv6 firewall
        stdout, _, rc = self._run_command(["ip6tables", "-L", "-n"])
        if rc == 0 and stdout.strip():
            findings.append(Finding("IPv6 Firewall Rules", "ip6tables has rules configured.", Severity.INFO, True))
        else:
            findings.append(Finding(
                title="No IPv6 Firewall Rules",
                description="ip6tables has no rules or is unavailable.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Configure ip6tables or use a firewall that handles IPv6.",
                tags=["firewall", "ipv6"],
            ))

        # Overall assessment
        if not active_firewalls:
            findings.append(Finding(
                title="No Active Firewall Detected",
                description="None of ufw/firewalld/iptables/nftables appear active.",
                severity=Severity.CRITICAL, passed=False,
                recommendation="Enable a firewall immediately. Recommended: sudo ufw enable",
                tags=["firewall"],
            ))
        else:
            findings.append(Finding(
                title="Active Firewall(s) Detected",
                description=f"Active: {', '.join(active_firewalls)}",
                severity=Severity.PASS, passed=True,
                tags=["firewall"],
            ))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
