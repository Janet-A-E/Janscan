"""Base module contract — all audit modules must implement this."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import subprocess


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"
    PASS     = "PASS"


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    passed: bool
    recommendation: str = ""
    raw_output: str = ""
    references: list = field(default_factory=list)
    tags: list = field(default_factory=list)


@dataclass
class ModuleResult:
    module_name: str
    module_display_name: str
    findings: list
    duration_seconds: float = 0.0
    error: Optional[str] = None


class BaseModule(ABC):
    name: str = ""
    display_name: str = ""
    description: str = ""
    requires_root: bool = False

    @abstractmethod
    def run(self) -> ModuleResult:
        """Execute all checks. Must return ModuleResult. Must not raise."""
        pass

    def _skip_no_root(self) -> ModuleResult:
        return ModuleResult(
            module_name=self.name,
            module_display_name=self.display_name,
            findings=[Finding(
                title=f"{self.display_name}: skipped (requires root)",
                description="This module requires root privileges. Run with sudo.",
                severity=Severity.INFO,
                passed=True,
            )],
            duration_seconds=0.0,
        )

    def _run_command(self, cmd: list, timeout: int = 10) -> tuple:
        """Run subprocess. Returns (stdout, stderr, returncode). Never raises."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1
        except Exception as e:
            return "", str(e), -1

    def _read_file(self, path: str) -> str:
        """Read file safely. Returns empty string on failure."""
        try:
            with open(path) as f:
                return f.read()
        except Exception:
            return ""
