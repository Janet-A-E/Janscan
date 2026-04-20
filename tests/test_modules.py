"""Basic module loading tests."""

import pytest
from janscan.modules.base import BaseModule, Finding, Severity, ModuleResult


def test_finding_creation():
    f = Finding(
        title="Test finding",
        description="A test.",
        severity=Severity.HIGH,
        passed=False,
        recommendation="Fix it.",
    )
    assert f.title == "Test finding"
    assert f.severity == Severity.HIGH
    assert not f.passed


def test_severity_enum():
    assert Severity.CRITICAL == "CRITICAL"
    assert Severity.PASS == "PASS"


def test_module_result():
    f = Finding("t", "d", Severity.PASS, True)
    r = ModuleResult(module_name="test", module_display_name="Test", findings=[f])
    assert r.module_name == "test"
    assert len(r.findings) == 1


def test_loader_finds_modules():
    from janscan.engine.loader import load_modules
    mods = load_modules()
    assert len(mods) > 0
    for m in mods:
        assert isinstance(m, BaseModule)
        assert m.name
        assert m.display_name
