"""Shared fixtures for the labforge SIEM test suite."""
from __future__ import annotations

import os
import sys

import pytest

# Make the package importable when pytest is run from the repo root or siem/.
_SIEM_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SIEM_DIR not in sys.path:
    sys.path.insert(0, _SIEM_DIR)

from labforge_siem.corpus import write_corpus  # noqa: E402
from labforge_siem.store import LogStore  # noqa: E402


@pytest.fixture()
def log_root(tmp_path):
    """A temp LOG_ROOT seeded with the canned attack corpus."""
    root = tmp_path / "logs"
    root.mkdir()
    write_corpus(str(root))
    return str(root)


@pytest.fixture()
def store(log_root):
    return LogStore(log_root)


@pytest.fixture()
def empty_store(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    return LogStore(str(root))
