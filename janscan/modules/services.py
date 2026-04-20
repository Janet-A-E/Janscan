"""Running Services audit module."""

import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


RISKY_SERVICES = ["telnet", "rsh", "rlogin", "rexec", "tftp", "finger", "chargen", "daytime", "echo", "discard"]
FTP_SERVICES = ["vsftpd", "proftpd", "pure-ftpd"]

class ServicesModule(BaseModule):
    name = "services"
    display_name = "Running Services"
    description = "Audits running services for dangerous or unnecessary ones."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # List running services
        stdout, _, rc = self._run_command(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"])
        running_services = []
        if rc == 0:
            for line in stdout.splitlines():
                parts = line.split()
                if parts and parts[0].endswith(".service"):
                    name = parts[0].replace(".service", "")
                    running_services.append(name)
            findings.append(Finding(
                title="Running Services",
                description=f"{len(running_services)} services running.",
                severity=Severity.INFO, passed=True,
                raw_output="\n".join(running_services[:50]),
                tags=["services"],
            ))

        # Risky services
        found_risky = []
        for svc in running_services:
            for risky in RISKY_SERVICES:
                if risky in svc.lower():
                    found_risky.append(svc)
                    break
        if found_risky:
            for svc in found_risky:
                findings.append(Finding(
                    title=f"Dangerous Service Running: {svc}",
                    description=f"Service '{svc}' is a known insecure service.",
                    severity=Severity.HIGH, passed=False,
                    recommendation=f"Disable with: sudo systemctl disable --now {svc}",
                    tags=["services", "network"],
                ))
        else:
            findings.append(Finding("No Risky Services Running", "No known dangerous services detected.", Severity.PASS, True))

        # FTP services
        found_ftp = [s for s in running_services if any(f in s.lower() for f in FTP_SERVICES)]
        if found_ftp:
            findings.append(Finding(
                title="FTP Service Running",
                description=f"FTP service(s) detected: {', '.join(found_ftp)}. FTP is unencrypted.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Replace FTP with SFTP (part of SSH). Disable FTP: sudo systemctl disable --now <service>",
                tags=["services", "ftp"],
            ))

        # Failed services
        stdout, _, rc = self._run_command(["systemctl", "list-units", "--state=failed", "--no-pager", "--plain"])
        failed = []
        if rc == 0:
            for line in stdout.splitlines():
                parts = line.split()
                if parts and parts[0].endswith(".service"):
                    failed.append(parts[0])
        if failed:
            findings.append(Finding(
                title="Failed Services Detected",
                description=f"{len(failed)} failed service(s): {', '.join(failed[:10])}",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Investigate failed services: journalctl -u <service>",
                raw_output="\n".join(failed),
                tags=["services"],
            ))
        else:
            findings.append(Finding("No Failed Services", "No failed systemd services.", Severity.PASS, True))

        # Enabled at boot
        stdout, _, rc = self._run_command(["systemctl", "list-unit-files", "--state=enabled", "--type=service", "--no-pager", "--plain"])
        if rc == 0:
            enabled = [l.split()[0] for l in stdout.splitlines() if l.strip() and l.split()[0].endswith(".service")]
            findings.append(Finding(
                title="Services Enabled at Boot",
                description=f"{len(enabled)} services enabled at boot.",
                severity=Severity.INFO, passed=True,
                raw_output="\n".join(enabled[:50]),
            ))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
