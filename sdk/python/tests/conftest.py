"""Path setup, so the SDK is importable without being installed.

The SDK is a path-based package rather than a distribution: this repository
already has one Python project (the detector) and adding a second lockfile to
own four files would cost more than it explains. A caller vendors these files
or installs from a checkout, which is what the README says.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
