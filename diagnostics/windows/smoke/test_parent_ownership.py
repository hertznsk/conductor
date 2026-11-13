"""Real actor OLD/NEW ownership and query survival, with explicitly substituted native ABI."""

import ctypes
import json
import sys

import pytest
from smoke.parent_ownership_exercise import exercise
from smoke.parent_ownership_probe import ActorCase


@pytest.fixture
def reap_orphans():
    """Keep test actors reapable even when the original root is deliberately stopped."""
    if sys.platform == "linux":
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
        assert libc.prctl(36, 1, 0, 0, 0) == 0
        yield
        assert libc.prctl(36, previous.value, 0, 0, 0) == 0
    else:
        yield


@pytest.mark.parametrize("variant", ["old", "new"])
def test_real_original_root_alias_old_new(tmp_path, monkeypatch, reap_orphans, variant):
    # Requirement: an original-root controller alias is admitted by its full self identity.
    row = exercise(tmp_path, monkeypatch, ActorCase(variant, 0, False, False))
    assert len(row["stops"]) == 1 and row["stops"][0]["peers"] == []
    assert row["note"] is not None
    assert "owner=" not in row["note"]
    if variant == "new":
        assert [a["role"] for a in row["attempts"]] == ["controller"]
        assert [n["kind"] for n in row["bindings"]] == ["root"]


@pytest.mark.parametrize(
    "variant,depth,promote",
    [("old", 2, True), ("new", 1, False), ("new", 2, True), ("new", 3, True)],
)
def test_real_worker_before_controller_and_exact_signal_membership(
    tmp_path, monkeypatch, reap_orphans, variant, depth, promote
):
    # Requirement: OLD refuses indirect W but admits direct C; NEW preserves W-first promotion.
    row = exercise(tmp_path, monkeypatch, ActorCase(variant, depth, promote, False))
    if variant == "old":
        assert row["note"] is not None
        assert row["old_sha"] is not None and "owner=run:parent-check:" in row["note"]
        release = json.loads((tmp_path / "release.json").read_bytes())
        assert row["stops"][0]["peers"] == [release["controller"]]
        assert release["gw0"] not in row["stops"][0]["peers"]
        return
    assert all(not a["refused"] for a in row["attempts"])
    assert [a["role"] for a in row["attempts"]] == (["gw0", "controller"] if promote else ["gw0"])
    sources = {n["pid"] for n in row["bindings"] if n["kind"] == "source"}
    assert set(row["stops"][0]["peers"]) == sources
    assert len(sources) == (2 if promote else 1)
    assert sorted(row["closes"]) == sorted(n["pid"] for n in row["bindings"])
    assert row["native_close_count"] == depth
    assert all(rights == 0x101000 and not inherit for _, rights, inherit in row["native_open"])


def test_real_query_survivor_has_no_signal_authority(tmp_path, monkeypatch, reap_orphans):
    # Requirement: a live query stays unsignalled until rescue and makes cleanup incomplete.
    row = exercise(tmp_path, monkeypatch, ActorCase("new", 2, False, True))
    queries = [n for n in row["bindings"] if n["kind"] == "query"]
    assert len(queries) == 1 and queries[0]["status"] == "live"
    assert queries[0]["pid"] not in row["stops"][0]["peers"]
    assert row["note"] is not None
    assert "cleanup=false error=cleanup-unconfirmed" in row["note"]
    assert row["primary"] == "TimeoutExpired"
    assert row["native_close_count"] == 2
    assert all(0 <= ms <= 3000 for ms in row["wait_ms"])
