"""Smoke test.

Exists from the first commit so the CI pipeline is green and meaningful before there
is anything to test. A pipeline introduced later is a pipeline that gets introduced
after the first bug.
"""

from __future__ import annotations

import promptsentinel


def test_package_is_importable_and_versioned():
    assert promptsentinel.__version__.count(".") == 2
