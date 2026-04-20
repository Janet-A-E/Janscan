"""Disk Encryption audit module."""

import time
import os
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity
from janscan import IS_ROOT


class DiskEncryptionModule(BaseModule):
    name = "disk_encryption"
    display_name = "Disk Encryption"
    description = "Checks LUKS encryption, encrypted swap, and TPM availability."
    requires_root = False

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # lsblk - look for LUKS
        stdout, _, rc = self._run_command(["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"])
        luks_found = False
        crypto_devices = []
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                if "crypto_luks" in line.lower():
                    luks_found = True
                    crypto_devices.append(line.strip())
            if luks_found:
                findings.append(Finding(
                    title="LUKS Encrypted Partitions Found",
                    description=f"Found LUKS partition(s): {'; '.join(crypto_devices[:5])}",
                    severity=Severity.PASS, passed=True,
                    raw_output=stdout[:500],
                    tags=["encryption"],
                ))
            else:
                findings.append(Finding(
                    title="No LUKS Encryption Detected",
                    description="No LUKS-encrypted partitions found on this system.",
                    severity=Severity.HIGH, passed=False,
                    recommendation="Enable full-disk encryption with LUKS for sensitive systems.",
                    tags=["encryption"],
                ))
            findings.append(Finding("Block Device Layout", "lsblk output captured.", Severity.INFO, True, raw_output=stdout[:500]))

        # dmsetup - encrypted volumes mounted
        stdout, _, rc = self._run_command(["dmsetup", "ls", "--target", "crypt"])
        if rc == 0 and stdout.strip() and stdout.strip() != "No devices found":
            devs = stdout.strip().splitlines()
            findings.append(Finding(
                title=f"Encrypted Volumes Mounted ({len(devs)})",
                description=f"Active encrypted volumes: {', '.join(d.split()[0] for d in devs[:5])}",
                severity=Severity.INFO, passed=True,
                tags=["encryption"],
            ))
        else:
            findings.append(Finding("No Encrypted Volumes Active", "No active dm-crypt devices found.", Severity.INFO, True))

        # Swap encryption
        swaps = self._read_file("/proc/swaps")
        if swaps:
            swap_lines = [l for l in swaps.splitlines()[1:] if l.strip()]
            if swap_lines:
                # Check if swap is encrypted (crude: if swap device is in dmsetup crypt list)
                encrypted_swap = False
                for line in swap_lines:
                    dev = line.split()[0]
                    if "dm-" in dev or "crypt" in dev:
                        encrypted_swap = True
                if encrypted_swap:
                    findings.append(Finding("Swap Encrypted", "Swap appears to be on an encrypted device.", Severity.PASS, True))
                else:
                    findings.append(Finding(
                        title="Swap Not Encrypted",
                        description=f"Swap device(s) may not be encrypted: {swap_lines[0].split()[0]}",
                        severity=Severity.MEDIUM, passed=False,
                        recommendation="Use encrypted swap or tmpfs. See cryptsetup documentation.",
                        tags=["encryption", "swap"],
                    ))
            else:
                findings.append(Finding("No Swap", "No swap is configured.", Severity.INFO, True))
        else:
            findings.append(Finding("Swap Info Unavailable", "Could not read /proc/swaps.", Severity.INFO, True))

        # eCryptfs / home encryption
        stdout, _, rc = self._run_command(["mount"])
        if rc == 0 and "ecryptfs" in stdout.lower():
            findings.append(Finding("eCryptfs Home Encryption", "eCryptfs detected — home directory is encrypted.", Severity.PASS, True))

        # TPM
        tpm_path = "/sys/class/tpm"
        if os.path.isdir(tpm_path) and os.listdir(tpm_path):
            findings.append(Finding("TPM Device Available", f"TPM found in {tpm_path}", Severity.INFO, True, tags=["tpm"]))
        else:
            findings.append(Finding("No TPM Device Detected", "No TPM found in /sys/class/tpm/", Severity.INFO, True))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
