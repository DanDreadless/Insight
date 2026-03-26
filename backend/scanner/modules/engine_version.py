"""
Detection engine version — read from version.txt in this package directory.

Increment version.txt whenever a detection module is changed so that cached
scans are re-evaluated against the updated rules even when the target page
content has not changed.

The .githooks/pre-commit hook handles this automatically when git is configured
to use it:
    git config core.hooksPath .githooks
"""
from pathlib import Path

_VERSION_FILE = Path(__file__).parent / 'version.txt'


def get_engine_version() -> int:
    """Return the current detection engine version as an integer."""
    try:
        return int(_VERSION_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return 0
