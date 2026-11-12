"""Exercise smoke publication through real pytest sessions and command files."""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


def command_record(paths: list[Path]) -> bytes:
    """Expected transport bytes, not an implementation of the runner parser."""
    text = "paths<<SMOKE_PATHS\n" + "\n".join(map(str, paths)) + "\nSMOKE_PATHS\n"
    return text.replace("\n", os.linesep).encode("utf-8")


def run_smoke(root: Path, body: str, missing: str = "") -> subprocess.CompletedProcess[str]:
    """Run the actual service hooks in an isolated child, without collecting other smoke tests."""
    for name in ("child-home", "child-temp", "export"):
        (root / name).mkdir()
    target = root / "test_probe.py"
    target.write_text(
        "import hashlib, json, os, pytest\nfrom pathlib import Path\n"
        "from artifact_policy import SCHEMA\n"
        "def test_probe(request):\n" + textwrap.indent(textwrap.dedent(body), "    "),
        encoding="utf-8",
    )
    environment = dict(os.environ)
    for key in ("HOME", "USERPROFILE", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        environment[key] = str(root / "child-home")
    for key in ("TMPDIR", "TMP", "TEMP"):
        environment[key] = str(root / "child-temp")
    environment.update(
        GITHUB_ENV=str(root / "github-env"),
        GITHUB_OUTPUT=str(root / "command-file"),
        SMOKE_EXPORT_ROOT=str(root / "export"),
        PYTHONDONTWRITEBYTECODE="1",
    )
    if missing:
        environment.pop(missing)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-p",
            "conftest",
            "-c",
            os.devnull,
            "--rootdir",
            str(root),
            "--basetemp",
            str(root / "state"),
            "-q",
            str(target),
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_early_route_survives_abrupt_exit_before_fixture_teardown(tmp_path: Path) -> None:
    # Requirement: an abrupt exit with masked env must leave the original report route intact.
    result = run_smoke(
        tmp_path,
        """
        root = Path(os.environ["SMOKE_EXPORT_ROOT"])
        assert (root / "smoke-report.jsonl").is_file()
        os.environ["GITHUB_OUTPUT"] = str(root / "masked-command")
        os.environ["SMOKE_EXPORT_ROOT"] = str(root / "masked-export")
        os._exit(23)
        """,
    )
    assert result.returncode == 23, result.stdout + result.stderr
    assert (tmp_path / "command-file").read_bytes() == command_record(
        [tmp_path / "export/smoke-report.jsonl"]
    )
    assert not (tmp_path / "export/masked-command").exists()


def test_finish_uses_original_address_and_exact_validated_set(tmp_path: Path) -> None:
    # Requirement: final export replaces the early value with only the original validated paths.
    result = run_smoke(
        tmp_path,
        """
        root = Path(os.environ["SMOKE_EXPORT_ROOT"])
        peer = root / "peer-parent-natural.jsonl"
        peer.write_bytes(b"{}\\n")
        peer.with_suffix(".sha256").write_text(hashlib.sha256(peer.read_bytes()).hexdigest())
        case = root / "w1-pass"
        case.mkdir()
        (case / "environment.jsonl").write_bytes(b"{}\\n")
        (case / "step.jsonl").write_bytes(b"private withheld")
        (case / "raw.txt").write_bytes(b"private raw")
        (case / "manifest.json").write_text(json.dumps({
            "schema": SCHEMA, "artifacts": [
                {"path": "environment.jsonl", "status": "complete"},
                {"path": "step.jsonl", "status": "withheld"},
            ],
        }))
        class MaskFinish:
            @pytest.hookimpl(tryfirst=True)
            def pytest_sessionfinish(self):
                os.environ["GITHUB_OUTPUT"] = str(root / "masked-command")
                os.environ["SMOKE_EXPORT_ROOT"] = str(root / "masked-export")
        request.config.pluginmanager.register(MaskFinish(), "mask-finish")
        """,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    root = tmp_path / "export"
    report = root / "smoke-report.jsonl"
    expected = [
        report,
        root / "peer-parent-natural.jsonl",
        root / "peer-parent-natural.sha256",
        root / "w1-pass/environment.jsonl",
        root / "w1-pass/manifest.json",
    ]
    assert (tmp_path / "command-file").read_bytes() == command_record([report]) + command_record(
        expected
    )
    assert not (root / "masked-command").exists()
    assert {row["phase"] for row in map(json.loads, report.read_text().splitlines())} == {
        "setup",
        "call",
        "teardown",
    }


@pytest.mark.parametrize(
    ("action", "failure"),
    [
        (
            '(case / "manifest.json").write_text(json.dumps({"schema": "wrong"}))',
            "AssertionError",
        ),
        (
            '(case / "manifest.json").write_text(json.dumps({"schema": SCHEMA, '
            '"artifacts": [{"path": "raw.txt", "status": "complete"}]}))',
            "AssertionError",
        ),
        (
            '(root / "peer-parent-natural.jsonl").write_bytes(b"{}\\n"); '
            '(root / "peer-parent-natural.sha256").write_text("bad")',
            "AssertionError",
        ),
        (
            "from smoke.long_protocol import PROCESS_CAP\n"
            'long = root / "long-w1"\nlong.mkdir()\n'
            '(long / "manifest.json").write_bytes(b" " * (PROCESS_CAP + 1))',
            "oversize",
        ),
    ],
    ids=["schema", "whitelist", "digest", "cap"],
)
def test_final_validation_failure_preserves_only_early_report(
    tmp_path: Path, action: str, failure: str
) -> None:
    # Requirement: failed validation must not replace the early route or expose rejected files.
    result = run_smoke(
        tmp_path,
        'root = Path(os.environ["SMOKE_EXPORT_ROOT"])\n'
        'case = root / "w1-pass"\ncase.mkdir()\n' + action + "\n",
    )
    assert result.returncode != 0
    assert failure in result.stdout + result.stderr
    assert (tmp_path / "command-file").read_bytes() == command_record(
        [tmp_path / "export/smoke-report.jsonl"]
    )


@pytest.mark.parametrize("missing", ["GITHUB_OUTPUT", "SMOKE_EXPORT_ROOT"])
def test_missing_original_environment_never_publishes_fixture_output(
    tmp_path: Path, missing: str
) -> None:
    # Requirement: fixture env must not invent a runner destination absent at session start.
    result = run_smoke(
        tmp_path,
        'os.environ["GITHUB_OUTPUT"] = str(Path.cwd() / "spurious-command")\n',
        missing,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "command-file").exists()
    assert not (tmp_path / "spurious-command").exists()
