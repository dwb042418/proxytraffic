"""ETIP compatibility bootstrap.

The current workspace contains legacy CPython caches for several platform
modules whose sources are unavailable.  This finder keeps those modules usable
on the matching interpreter until their original sources are restored.
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import importlib.util
import sys
from pathlib import Path


_ROOT = Path(__file__).resolve().parent
__version__ = "0.1.0"


class _CachedModuleFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname: str, path=None, target=None):  # type: ignore[no-untyped-def]
        prefix = __name__ + "."
        if not fullname.startswith(prefix):
            return None
        relative = fullname[len(prefix):].split(".")
        module_dir = _ROOT.joinpath(*relative[:-1])
        candidate = module_dir / "__pycache__" / f"{relative[-1]}.cpython-{sys.version_info.major}{sys.version_info.minor}.pyc"
        if not candidate.is_file():
            return None
        loader = importlib.machinery.SourcelessFileLoader(fullname, str(candidate))
        return importlib.util.spec_from_file_location(fullname, candidate, loader=loader)


if not any(isinstance(finder, _CachedModuleFinder) for finder in sys.meta_path):
    sys.meta_path.insert(0, _CachedModuleFinder())
