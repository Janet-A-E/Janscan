"""Auto-discovers and loads audit modules."""

import importlib
import pkgutil
from pathlib import Path
from janscan.modules.base import BaseModule


def load_modules() -> list:
    modules = []
    modules_path = Path(__file__).parent.parent / "modules"
    package = "janscan.modules"

    skip = {"base", "__init__", "audit_summary"}

    for importer, modname, ispkg in pkgutil.iter_modules(
        path=[str(modules_path)],
        prefix=package + "."
    ):
        short = modname.split(".")[-1]
        if short in skip:
            continue
        try:
            mod = importlib.import_module(modname)
            for attr in dir(mod):
                cls = getattr(mod, attr)
                if (
                    isinstance(cls, type)
                    and issubclass(cls, BaseModule)
                    and cls is not BaseModule
                ):
                    modules.append(cls())
                    break
        except Exception as e:
            print(f"[!] Failed to load module {modname}: {e}")

    # audit_summary always last
    try:
        from janscan.modules.audit_summary import AuditSummaryModule
        modules.append(AuditSummaryModule())
    except Exception as e:
        print(f"[!] Failed to load audit_summary: {e}")

    return modules
