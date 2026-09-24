"""Tests for :mod:`conductor.bundle.store` — the content-addressed bundle store.

The store contract under test: a bundle publishes to
``<CONDUCTOR_HOME>/cache/bundles/<sha256:hex>/`` with the entry tree, a
deterministic ``bundle.tar.gz``, and ``bundle.json`` written last as the
readiness sentinel; republishing reuses a valid directory without re-hashing;
an invalid directory is warned about, removed, and rebuilt; a crash mid-write
leaves no residue; concurrent publishers of one digest both end up with a
valid store path.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from conductor.bundle.model import (
    BundleEntry,
    BundleManifest,
    compute_bundle_digest,
    serialize_manifest,
)
from conductor.bundle.store import bundle_store_base, publish_bundle

_POSIX = hasattr(os, "symlink")


def _file_entry(logical_path: str, data: bytes, *, executable: bool = False) -> BundleEntry:
    return BundleEntry(
        logical_path=logical_path,
        kind="file",
        digest=f"sha256:{hashlib.sha256(data).hexdigest()}",
        size=len(data),
        executable=executable,
        link_target=None,
        origin_kind="asset",
        origin_detail=f"asset:{logical_path}",
    )


def _symlink_entry(logical_path: str, target: str) -> BundleEntry:
    return BundleEntry.for_symlink(
        logical_path,
        target,
        origin_kind="asset",
        origin_detail=f"asset:{logical_path}",
    )


def _manifest(entries: list[BundleEntry]) -> BundleManifest:
    digest = compute_bundle_digest(entries, {}, {})
    return BundleManifest(
        version=1,
        bundle_digest=digest,
        entries=tuple(entries),
        skills_topology={},
        plugins_topology={},
    )


def _payload_manifest(with_symlink: bool = _POSIX) -> tuple[BundleManifest, dict, dict]:
    """A consistent manifest + files + links fixture for the happy path."""
    entries = [
        _file_entry("tree/main/workflow.yaml", b"workflow: {entry_point: a}\n"),
        _file_entry("tree/main/scripts/run.sh", b"#!/bin/sh\necho hi\n", executable=True),
        _file_entry("tree/main/plain.txt", b"plain\n"),
    ]
    links: dict[str, str] = {}
    if with_symlink:
        entries.append(_symlink_entry("tree/main/link.txt", "plain.txt"))
        links = {"tree/main/link.txt": "plain.txt"}
    files = {
        "tree/main/workflow.yaml": b"workflow: {entry_point: a}\n",
        "tree/main/scripts/run.sh": b"#!/bin/sh\necho hi\n",
        "tree/main/plain.txt": b"plain\n",
    }
    return _manifest(entries), files, links


class TestBundleStoreBase:
    def test_honors_conductor_home(self):
        # Requirement: the store base resolves under $CONDUCTOR_HOME (the
        # conftest tmp-home fixture sets it), mirroring the plugin cache idiom.
        base = bundle_store_base()
        assert base == Path(os.environ["CONDUCTOR_HOME"]) / "cache" / "bundles"


class TestPublish:
    def test_publish_creates_complete_store_dir(self):
        # Requirement: publishing stages the entry tree at full store-relative
        # logical paths, writes bundle.tar.gz, and writes bundle.json last as
        # the readiness sentinel whose bundle_digest equals the dir name.
        manifest, files, links = _payload_manifest()
        final = publish_bundle(manifest, files, links)

        assert final == bundle_store_base() / manifest.bundle_digest
        assert final.is_dir()
        assert (final / "tree/main/workflow.yaml").read_bytes() == files["tree/main/workflow.yaml"]
        assert (final / "bundle.tar.gz").is_file()
        parsed = json.loads((final / "bundle.json").read_text(encoding="utf-8"))
        assert parsed["bundle_digest"] == final.name == manifest.bundle_digest

    def test_exec_bit_staged_from_manifest_entry(self):
        # Requirement: an executable=True entry is staged 0o755 and a
        # non-executable one 0o644, per the manifest entry, not the payload.
        manifest, files, links = _payload_manifest()
        final = publish_bundle(manifest, files, links)
        exec_mode = os.stat(final / "tree/main/scripts/run.sh").st_mode
        plain_mode = os.stat(final / "tree/main/plain.txt").st_mode
        assert stat.S_IMODE(exec_mode) == 0o755
        assert stat.S_IMODE(plain_mode) == 0o644

    @pytest.mark.skipif(not _POSIX, reason="symlink support is POSIX-first")
    def test_symlink_entry_materialized_in_store(self):
        # Requirement: a link entry is materialized with os.symlink at its
        # full logical path — the store tree is a faithful POSIX staging.
        manifest, files, links = _payload_manifest()
        final = publish_bundle(manifest, files, links)
        link = final / "tree/main/link.txt"
        assert link.is_symlink()
        assert os.readlink(link) == "plain.txt"

    def test_manifest_copy_inside_archive_matches_bundle_json(self):
        # Requirement: the archive carries .bundle/manifest.json byte-identical
        # to the bundle.json sentinel — publish stages the copy before archiving.
        manifest, files, links = _payload_manifest()
        final = publish_bundle(manifest, files, links)
        with tarfile.open(final / "bundle.tar.gz", "r:gz") as tar:
            member = tar.getmember(".bundle/manifest.json")
            extracted = tar.extractfile(member)
            assert extracted is not None
            archived = extracted.read()
        assert archived == (final / "bundle.json").read_bytes()
        assert archived == serialize_manifest(manifest).encode("utf-8")

    def test_publish_rejects_malformed_digest(self):
        # Requirement: the store key is the full sha256:<64 hex> digest; a
        # malformed digest is a caller bug and raises before any I/O.
        manifest, files, links = _payload_manifest()
        broken = manifest.model_copy(update={"bundle_digest": "sha256:abc"})
        with pytest.raises(ValueError, match="sha256"):
            publish_bundle(broken, files, links)

    def test_publish_rejects_payload_not_in_manifest(self):
        # Requirement: payloads and links must be declared manifest entries of
        # the matching kind — a silent mode/content mismatch is a caller bug.
        manifest, files, links = _payload_manifest()
        with pytest.raises(ValueError, match="not a declared"):
            publish_bundle(manifest, {**files, "tree/main/extra.txt": b"x"}, links)


class TestReuse:
    def test_second_publish_reuses_valid_dir(self):
        # Requirement: republishing the same digest returns the existing path
        # and does not rewrite bundle.json — its mtime is unchanged (the
        # is_cached precedent: validate by parsing, never re-hash the tree).
        manifest, files, links = _payload_manifest()
        first = publish_bundle(manifest, files, links)
        sentinel = first / "bundle.json"
        mtime_ns = sentinel.stat().st_mtime_ns

        second = publish_bundle(manifest, files, links)

        assert second == first
        assert sentinel.stat().st_mtime_ns == mtime_ns

    def test_invalid_preexisting_dir_warns_and_rebuilds(self, caplog):
        # Requirement: a pre-existing dir whose bundle.json carries a
        # DIFFERENT digest is invalid — the store warns (module logger) and
        # self-heals by removing and rebuilding the tree.
        manifest, files, links = _payload_manifest()
        final = bundle_store_base() / manifest.bundle_digest
        final.mkdir(parents=True)
        (final / "bundle.json").write_text(
            json.dumps({"bundle_digest": "sha256:" + "f" * 64}), encoding="utf-8"
        )

        with caplog.at_level(logging.WARNING, logger="conductor.bundle.store"):
            result = publish_bundle(manifest, files, links)

        assert result == final
        assert any("Invalid bundle store directory" in rec.message for rec in caplog.records)
        parsed = json.loads((final / "bundle.json").read_text(encoding="utf-8"))
        assert parsed["bundle_digest"] == manifest.bundle_digest
        assert (final / "tree/main/workflow.yaml").is_file()

    def test_warning_sink_override_receives_message(self):
        # Requirement: the invalid-dir warning is delivered to an explicit
        # on_warning sink when one is passed, instead of only the logger.
        manifest, files, links = _payload_manifest()
        final = bundle_store_base() / manifest.bundle_digest
        final.mkdir(parents=True)
        (final / "bundle.json").write_text("not json", encoding="utf-8")
        messages: list[str] = []

        publish_bundle(manifest, files, links, on_warning=messages.append)

        assert any("Invalid bundle store directory" in message for message in messages)
        parsed = json.loads((final / "bundle.json").read_text(encoding="utf-8"))
        assert parsed["bundle_digest"] == manifest.bundle_digest


class TestCrashAndRace:
    def test_crash_mid_write_leaves_no_residue(self, monkeypatch):
        # Requirement: an exception between file writes removes the staging
        # dir and leaves no final dir or temp files behind, and the next
        # publish succeeds cleanly (cache self-healing).
        manifest, files, links = _payload_manifest()

        def _boom(*_args, **_kwargs):
            raise RuntimeError("simulated crash mid-write")

        # A nested context, so reverting the crash patch cannot also revert
        # the conftest autouse CONDUCTOR_HOME isolation on this monkeypatch.
        with monkeypatch.context() as crash_patch:
            crash_patch.setattr("conductor.bundle.store.write_bundle_archive", _boom)
            with pytest.raises(RuntimeError, match="simulated crash"):
                publish_bundle(manifest, files, links)

        base = bundle_store_base()
        assert not (base / manifest.bundle_digest).exists()
        leftovers = [entry.name for entry in base.iterdir() if entry.name.startswith("tmp")]
        assert leftovers == []
        archive_leftovers = [
            entry.name for entry in base.iterdir() if entry.name.startswith(".tmp")
        ]
        assert archive_leftovers == []

        final = publish_bundle(manifest, files, links)
        assert (final / "bundle.json").is_file()

    def test_concurrent_publishers_both_get_valid_store_path(self):
        # Requirement: two threads publishing the same digest concurrently
        # race on the atomic rename — the loser switches to validate-and-return
        # the winner's dir, so both callers receive a valid store path.
        manifest, files, links = _payload_manifest()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(publish_bundle, manifest, files, links) for _ in range(2)]
            results = [future.result() for future in futures]

        final = bundle_store_base() / manifest.bundle_digest
        assert results[0] == results[1] == final
        parsed = json.loads((final / "bundle.json").read_text(encoding="utf-8"))
        assert parsed["bundle_digest"] == manifest.bundle_digest
