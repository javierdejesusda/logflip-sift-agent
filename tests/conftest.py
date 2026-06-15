"""Pytest path setup so sift_mcp and sift_agent import without an editable install.

Inserts the repository root onto sys.path so the test suite runs from a fresh
checkout with no `pip install -e .` step. The logflip engine is expected to be
importable already (installed per the setup instructions).
"""

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
