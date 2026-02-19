"""
Launcher for M365 Security & IAM Intelligence Engine.

The project folder name (M365-Security-Remediation) contains hyphens which
prevents `python -m <folder>` and `python .` from working with relative
imports.  This script registers the current directory under the alias
`m365_security_engine` and then executes __main__.py.

Usage (run from inside the project directory):
    python run.py
    python run.py profile add <name> --tenant-id ... --client-id ... --cert-path ...
    python run.py profile list
    python run.py --profile <name>
"""
import importlib.util
import io
import os
import sys
import types
from pathlib import Path

# On Windows, switch the console to UTF-8 (code page 65001) so that Unicode
# chars in the banner and reports render correctly.  Must happen before any
# print() calls.
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass
    # Also reconfigure Python's stdout/stderr to use UTF-8.
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            import io as _io
            # Cast to TextIOWrapper so Pylance sees reconfigure().
            _stdout = _io.TextIOWrapper.__new__(_io.TextIOWrapper)
            _stdout = sys.stdout  # type: ignore[assignment]
            _stdout.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[union-attr]
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[union-attr]
        except Exception:
            pass
    elif hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

PKG_NAME = "m365_security_engine"
pkg_dir = Path(__file__).resolve().parent

# 1. Make parent visible so absolute imports work if ever used.
sys.path.insert(0, str(pkg_dir.parent))

# 2. Register this directory as the m365_security_engine package so that
#    relative imports (from .config import ...) inside __main__.py resolve.
pkg_mod = types.ModuleType(PKG_NAME)
pkg_mod.__path__ = [str(pkg_dir)]
pkg_mod.__package__ = PKG_NAME
pkg_mod.__spec__ = importlib.util.spec_from_file_location(
    PKG_NAME,
    pkg_dir / "__init__.py",
    submodule_search_locations=[str(pkg_dir)],
)
sys.modules[PKG_NAME] = pkg_mod
assert pkg_mod.__spec__ is not None, "Failed to create spec for package"
assert pkg_mod.__spec__.loader is not None, "Package spec has no loader"
pkg_mod.__spec__.loader.exec_module(pkg_mod)  # type: ignore[union-attr]

# 3. Load and execute __main__.py under the package namespace.
main_spec = importlib.util.spec_from_file_location(
    f"{PKG_NAME}.__main__",
    pkg_dir / "__main__.py",
    submodule_search_locations=[str(pkg_dir)],
)
assert main_spec is not None, f"Could not locate {PKG_NAME}.__main__"
assert main_spec.loader is not None, "__main__ spec has no loader"
main_mod = importlib.util.module_from_spec(main_spec)
main_mod.__package__ = PKG_NAME
sys.modules[f"{PKG_NAME}.__main__"] = main_mod
main_spec.loader.exec_module(main_mod)  # type: ignore[union-attr]

# __main__.py guards its entry point with `if __name__ == "__main__"`, which
# never fires when loaded via exec_module (name is the package path, not
# "__main__").  Call main() explicitly.
main_mod.main()
