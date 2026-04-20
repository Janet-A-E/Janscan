"""Kernel Security audit module."""

import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class KernelModule(BaseModule):
    name = "kernel"
    display_name = "Kernel Security"
    description = "Checks kernel security parameters (ASLR, kptr_restrict, dmesg, etc.)."
    requires_root = False

    def _proc(self, path):
        return self._read_file(path).strip()

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        # ASLR
        val = self._proc("/proc/sys/kernel/randomize_va_space")
        if val == "2":
            findings.append(Finding("ASLR Fully Enabled", "randomize_va_space=2", Severity.PASS, True, tags=["kernel"]))
        elif val == "1":
            findings.append(Finding(
                title="ASLR Partially Enabled",
                description="randomize_va_space=1 — partial ASLR only.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="Set full ASLR: sysctl -w kernel.randomize_va_space=2",
                tags=["kernel"],
            ))
        elif val == "0":
            findings.append(Finding(
                title="ASLR Disabled",
                description="randomize_va_space=0 — ASLR is completely disabled.",
                severity=Severity.HIGH, passed=False,
                recommendation="Enable ASLR: sysctl -w kernel.randomize_va_space=2",
                tags=["kernel"],
            ))

        # kptr_restrict
        val = self._proc("/proc/sys/kernel/kptr_restrict")
        if val == "2":
            findings.append(Finding("Kernel Pointer Restriction: Max", "kptr_restrict=2", Severity.PASS, True))
        elif val == "1":
            findings.append(Finding("Kernel Pointer Restriction: Partial", "kptr_restrict=1", Severity.LOW, False,
                recommendation="Set kptr_restrict=2 for full protection."))
        else:
            findings.append(Finding(
                title="Kernel Pointers Exposed",
                description="kptr_restrict=0 — kernel addresses visible to unprivileged users.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="sysctl -w kernel.kptr_restrict=2",
                tags=["kernel"],
            ))

        # dmesg_restrict
        val = self._proc("/proc/sys/kernel/dmesg_restrict")
        if val == "1":
            findings.append(Finding("dmesg Restricted", "dmesg_restrict=1", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="dmesg Unrestricted",
                description="Unprivileged users can read kernel messages.",
                severity=Severity.LOW, passed=False,
                recommendation="sysctl -w kernel.dmesg_restrict=1",
                tags=["kernel"],
            ))

        # Core dump
        val = self._proc("/proc/sys/fs/suid_dumpable")
        if val == "0":
            findings.append(Finding("Core Dumps Restricted", "suid_dumpable=0", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="Core Dumps Not Restricted",
                description=f"suid_dumpable={val} — SUID programs can produce core dumps.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="sysctl -w fs.suid_dumpable=0",
                tags=["kernel"],
            ))

        # ptrace scope
        val = self._proc("/proc/sys/kernel/yama/ptrace_scope")
        if not val:
            findings.append(Finding("ptrace_scope Unavailable", "Yama LSM may not be active.", Severity.INFO, True))
        elif int(val) >= 1:
            findings.append(Finding(f"ptrace Scope Restricted (={val})", "ptrace_scope >= 1", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="ptrace Unrestricted",
                description="ptrace_scope=0 — any process can trace any other process.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="sysctl -w kernel.yama.ptrace_scope=1",
                tags=["kernel"],
            ))

        # Unprivileged BPF
        val = self._proc("/proc/sys/kernel/unprivileged_bpf_disabled")
        if val == "1":
            findings.append(Finding("Unprivileged BPF Disabled", "unprivileged_bpf_disabled=1", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="Unprivileged BPF Enabled",
                description="Unprivileged users can use eBPF programs.",
                severity=Severity.MEDIUM, passed=False,
                recommendation="sysctl -w kernel.unprivileged_bpf_disabled=1",
                tags=["kernel"],
            ))

        # NX/DEP
        cpuinfo = self._read_file("/proc/cpuinfo")
        if " nx " in cpuinfo or "\tnx\n" in cpuinfo or "nx" in cpuinfo.split():
            findings.append(Finding("NX/DEP Support", "CPU supports NX (No-eXecute) bit.", Severity.PASS, True))
        else:
            findings.append(Finding(
                title="NX/DEP Not Detected",
                description="CPU NX bit not found in /proc/cpuinfo.",
                severity=Severity.HIGH, passed=False,
                recommendation="Ensure NX is enabled in BIOS/UEFI settings.",
                tags=["kernel", "cpu"],
            ))

        # Loaded modules
        stdout, _, rc = self._run_command(["lsmod"])
        if rc == 0:
            mods = [l.split()[0] for l in stdout.splitlines()[1:] if l.strip()]
            findings.append(Finding("Loaded Kernel Modules", f"{len(mods)} modules loaded.", Severity.INFO, True, raw_output="\n".join(mods[:50])))

        # Secure boot
        stdout, _, rc = self._run_command(["mokutil", "--sb-state"])
        if rc == 0:
            if "enabled" in stdout.lower():
                findings.append(Finding("Secure Boot Enabled", stdout.strip(), Severity.PASS, True))
            else:
                findings.append(Finding(
                    title="Secure Boot Disabled",
                    description=stdout.strip() or "Secure Boot is not enabled.",
                    severity=Severity.LOW, passed=False,
                    recommendation="Enable Secure Boot in BIOS/UEFI settings.",
                    tags=["kernel", "boot"],
                ))
        else:
            findings.append(Finding("Secure Boot Status Unknown", "mokutil not available.", Severity.INFO, True))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
