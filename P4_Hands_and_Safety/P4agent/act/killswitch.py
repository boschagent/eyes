"""Kill switch: the agent halts if ./KILL exists or env AGENT_KILL=1.

Checked before EVERY action and every loop step (P1 should call `check()` at the
top of each agent-loop iteration; ActionClient and verify.py already call it).
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

# ASSUMPTION: the KILL file lives in the current working directory (repo root).
KILL_FILE = "KILL"
KILL_ENV = "AGENT_KILL"


class KillSwitchEngaged(RuntimeError):
    """Raised by check() when the kill switch is engaged."""


def _path(kill_file: str | os.PathLike | None) -> Path:
    return Path(kill_file or os.environ.get("AGENT_KILL_FILE", KILL_FILE))


def is_engaged(kill_file: str | os.PathLike | None = None) -> bool:
    return _path(kill_file).exists() or os.environ.get(KILL_ENV) == "1"


def reason(kill_file: str | os.PathLike | None = None) -> str | None:
    if os.environ.get(KILL_ENV) == "1":
        return f"env {KILL_ENV}=1"
    p = _path(kill_file)
    if p.exists():
        return f"file {p} exists"
    return None


def check(kill_file: str | os.PathLike | None = None) -> None:
    """Raise KillSwitchEngaged if the switch is on. Call at the top of every step."""
    r = reason(kill_file)
    if r:
        raise KillSwitchEngaged(r)


def engage(kill_file: str | os.PathLike | None = None, why: str = "manual") -> Path:
    """Create the KILL file (atomic write). Used by the UI's KILL button."""
    p = _path(kill_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        f.write(f"killed: {why}\n")
    os.replace(tmp, p)
    return p


def clear(kill_file: str | os.PathLike | None = None) -> None:
    _path(kill_file).unlink(missing_ok=True)


def selftest() -> None:
    with tempfile.TemporaryDirectory() as d:
        kf = Path(d) / "KILL"
        old = os.environ.pop(KILL_ENV, None)
        try:
            assert not is_engaged(kf)
            check(kf)  # must not raise
            engage(kf, "test")
            assert is_engaged(kf) and "exists" in reason(kf)
            try:
                check(kf)
                raise AssertionError("check() should have raised")
            except KillSwitchEngaged:
                pass
            clear(kf)
            assert not is_engaged(kf)
            os.environ[KILL_ENV] = "1"
            assert is_engaged(kf) and "env" in reason(kf)
            os.environ[KILL_ENV] = "0"  # only "1" counts
            assert not is_engaged(kf)
        finally:
            os.environ.pop(KILL_ENV, None)
            if old is not None:
                os.environ[KILL_ENV] = old


if __name__ == "__main__":
    selftest()
    print("ALL TESTS PASSED")
