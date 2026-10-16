"""--profile CLI wiring and profile-driven thresholds"""
import os
import subprocess
import sys

from mcpwn import load_profile
from tests.side_channel import SideChannelTest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARANOID = os.path.join(ROOT, "profiles", "paranoid.json")


def test_profile_flag_is_accepted():
    """--profile must be a real CLI flag (unknown args exit 2)"""
    result = subprocess.run(
        [sys.executable, "mcpwn.py", "--profile", PARANOID],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    assert "unrecognized arguments" not in result.stderr
    assert result.returncode == 1  # no server command -> usage error, not argparse
    assert "MCP server command required" in result.stdout + result.stderr


def test_paranoid_profile_reaches_side_channel():
    """Thresholds from profiles/paranoid.json override the built-in defaults"""
    profile = load_profile(PARANOID)
    test = SideChannelTest(pentester=None, profile=profile)
    assert test.timing_threshold == 1.0  # slow_query_ms 1000
    assert "/etc/passwd" in test.root_indicators


def test_bad_profile_rejected(tmp_path):
    """A missing or non-object profile fails loudly, not silently"""
    import pytest

    with pytest.raises(ValueError):
        load_profile(str(tmp_path / "nope.json"))
