"""Tests for ``conductor.filesystem`` — pre-3.14 pathlib probe semantics.

Python 3.14's ``pathlib`` swallows ``PermissionError`` in ``exists()`` /
``is_dir()`` / ``is_file()`` (issue #540); these tests pin that
``conductor.filesystem``'s probes re-raise it on every interpreter. They
monkeypatch ``Path.stat`` rather than relying on ``chmod``, which is
ineffective for root and on Windows.
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import pytest

from conductor.config.schema import PluginSourceDef
from conductor.filesystem import (
    exists_strict,
    is_dir_strict,
    is_file_strict,
    stat_or_none,
)
from conductor.plugins.errors import (
    PluginManifestError,
    PluginNotFoundError,
    PluginSourceError,
)
from conductor.plugins.registry import resolve_plugin
from conductor.plugins.resolution import resolve_plugin_sources
from conductor.skills.discovery import _has_repo_marker, _scan_root
from conductor.skills.registry import (
    SkillNotFoundError,
    expand_skills_root,
    resolve_skills,
)


class _WindowsError(OSError):
    """An ``OSError`` carrying a ``winerror``, as stat raises on Windows."""

    winerror: int


def _raising_stat(exc: OSError) -> Callable[..., NoReturn]:
    """A ``Path.stat`` stand-in that always raises ``exc``."""

    def _stat(self: Path, *, follow_symlinks: bool = True) -> NoReturn:
        raise exc

    return _stat


def _deny(path_cls: type[Path]) -> Callable[..., NoReturn]:
    return _raising_stat(PermissionError(errno.EACCES, "Permission denied"))


class TestStatOrNone:
    def test_existing_file_returns_its_stat(self, tmp_path: Path) -> None:
        # Requirement: a readable existing path yields its real stat result.
        target = tmp_path / "f.txt"
        target.write_text("x")
        info = stat_or_none(target)
        assert info is not None
        assert stat.S_ISREG(info.st_mode)

    def test_missing_path_returns_none(self, tmp_path: Path) -> None:
        # Requirement: a genuinely absent path reads as absent.
        assert stat_or_none(tmp_path / "nope") is None

    @pytest.mark.parametrize(
        "error_number", [errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP]
    )
    def test_allowlisted_errnos_return_none(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error_number: int
    ) -> None:
        # Requirement: the pre-3.14 pathlib errno allowlist reads as absent,
        # preserving exists()/is_dir()/is_file() behaviour from Python ≤3.13.
        monkeypatch.setattr(Path, "stat", _raising_stat(OSError(error_number, "ignored")))
        assert stat_or_none(tmp_path / "x") is None

    @pytest.mark.parametrize("winerror", [21, 123, 1921])
    def test_allowlisted_winerrors_return_none(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, winerror: int
    ) -> None:
        # Requirement: the pre-3.14 pathlib winerror allowlist reads as absent.
        exc = _WindowsError("ignored")
        exc.winerror = winerror
        monkeypatch.setattr(Path, "stat", _raising_stat(exc))
        assert stat_or_none(tmp_path / "x") is None

    def test_permission_error_propagates(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Requirement: EACCES is never swallowed — it must propagate so
        # callers can distinguish "could not be read" from "does not exist".
        monkeypatch.setattr(Path, "stat", _deny(Path))
        with pytest.raises(PermissionError):
            stat_or_none(tmp_path / "x")

    def test_non_allowlisted_winerror_propagates(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Requirement: a winerror outside the allowlist (ERROR_ACCESS_DENIED)
        # propagates rather than reading as absent.
        exc = _WindowsError("denied")
        exc.winerror = 5
        monkeypatch.setattr(Path, "stat", _raising_stat(exc))
        with pytest.raises(OSError):
            stat_or_none(tmp_path / "x")


class TestStrictPredicates:
    def test_classification_by_kind(self, tmp_path: Path) -> None:
        # Requirement: predicates classify by kind and report absent paths
        # as False, matching their pathlib counterparts.
        directory = tmp_path / "d"
        directory.mkdir()
        file = tmp_path / "f"
        file.write_text("x")

        assert is_dir_strict(directory)
        assert not is_file_strict(directory)
        assert is_file_strict(file)
        assert not is_dir_strict(file)
        assert not exists_strict(tmp_path / "absent")
        assert not is_dir_strict(tmp_path / "absent")
        assert not is_file_strict(tmp_path / "absent")

    @pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
    def test_symlinks_are_followed_like_pathlib(self, tmp_path: Path) -> None:
        # Requirement: the probes follow symlinks, matching Path.is_dir() /
        # is_file() / exists() (a broken symlink reads as absent).
        directory = tmp_path / "d"
        directory.mkdir()
        link = tmp_path / "ld"
        link.symlink_to(directory, target_is_directory=True)
        broken = tmp_path / "broken"
        broken.symlink_to(tmp_path / "missing")

        assert is_dir_strict(link)
        assert not exists_strict(broken)

    @pytest.mark.parametrize("probe", [exists_strict, is_dir_strict, is_file_strict])
    def test_permission_error_propagates_from_every_probe(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        probe: Callable[[Path], bool],
    ) -> None:
        # Requirement: every strict probe re-raises EACCES on any
        # interpreter — Python 3.14's pathlib equivalents swallow it.
        monkeypatch.setattr(Path, "stat", _deny(Path))
        with pytest.raises(PermissionError):
            probe(tmp_path / "x")


class TestCallSiteWiring:
    """Path-resolution call sites must route a PermissionError — the one
    Python 3.14's pathlib would have swallowed — into their "could not be
    read" diagnostic instead of "does not exist" / a silent skip."""

    def test_skill_path_reports_could_not_be_read(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Requirement: an unreadable skill path entry raises
        # SkillNotFoundError naming the entry, never "does not exist".
        monkeypatch.setattr(Path, "stat", _deny(Path))
        with pytest.raises(SkillNotFoundError, match="could not be read"):
            resolve_skills(["./acme"], base_dir=tmp_path)

    def test_plugin_path_reports_could_not_be_read(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Requirement: an unreadable plugin path entry raises
        # PluginNotFoundError naming the entry, never "does not exist".
        monkeypatch.setattr(Path, "stat", _deny(Path))
        with pytest.raises(PluginNotFoundError, match="could not be read"):
            resolve_plugin(str(tmp_path / "p"))

    def test_local_plugin_source_reports_could_not_be_read(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Requirement: an unreadable local plugin source raises
        # PluginSourceError ("could not be read"), never "not a directory".
        monkeypatch.setattr(Path, "stat", _deny(Path))
        with pytest.raises(PluginSourceError, match="could not be read"):
            resolve_plugin_sources({"local": PluginSourceDef(source="./vendor")}, base_dir=tmp_path)

    def test_repo_marker_probe_permission_error_still_warns(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Requirement: an unreadable .git probe must warn (and treat the
        # directory as not-a-root) rather than silently reporting no marker.
        monkeypatch.setattr(Path, "stat", _deny(Path))
        warnings: list[str] = []
        assert _has_repo_marker(tmp_path, warnings.append) is False
        assert any("could not check" in warning for warning in warnings)

    def test_scan_root_permission_error_reports_failed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Requirement: an unreadable discovery root warns and reports
        # failed=True, never silently reading as "nothing here".
        monkeypatch.setattr(Path, "stat", _deny(Path))
        warnings: list[str] = []
        assert _scan_root(tmp_path, "project", warnings.append) == ([], True)
        assert any("could not read" in warning for warning in warnings)

    def test_expand_skills_root_marks_unreadable_child(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Requirement: a child whose SKILL.md probe fails with EACCES lands
        # in `unreadable`, never in `skipped` or nowhere.
        root = tmp_path / "skills"
        blocked = root / "blocked"
        blocked.mkdir(parents=True)
        real_stat = Path.stat

        def _stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
            if self.parent == blocked:
                raise PermissionError(errno.EACCES, "Permission denied")
            return real_stat(self, follow_symlinks=follow_symlinks)

        monkeypatch.setattr(Path, "stat", _stat)
        children, skipped, unreadable = expand_skills_root(root)
        assert children == []
        assert skipped == []
        assert unreadable == ["blocked"]

    def test_plugin_skills_dir_permission_error_reports_could_not_be_read(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Requirement: an unreadable plugin ``skills/`` directory raises
        # PluginManifestError, never resolving as a plugin with no skills.
        root = tmp_path / "p"
        (root / ".claude-plugin").mkdir(parents=True)
        (root / ".claude-plugin" / "plugin.json").write_text('{"name": "p"}', encoding="utf-8")
        (root / "skills").mkdir()
        real_stat = Path.stat

        def _stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
            if self.name == "skills":
                raise PermissionError(errno.EACCES, "Permission denied")
            return real_stat(self, follow_symlinks=follow_symlinks)

        monkeypatch.setattr(Path, "stat", _stat)
        with pytest.raises(PluginManifestError, match="could not be read"):
            resolve_plugin(str(root))
