"""The OpenAPI dumper feeds the console's generated types, so CI depends on it."""

from __future__ import annotations

import json
from pathlib import Path

from alert2attack.api.openapi import main


def test_writes_parseable_json(tmp_path: Path) -> None:
    out = tmp_path / "openapi.json"
    assert main([str(out)]) == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["openapi"].startswith("3.")
    assert "/scenarios" in document["paths"]


def test_file_holds_json_and_nothing_else(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """The regression this module exists for.

    Building the app logs a warning when no credential is configured. Shell
    redirection of stdout put that line into the document and broke the type
    generator at line 3; writing the file from Python keeps them separate.
    """
    out = tmp_path / "openapi.json"
    main([str(out)])

    text = out.read_text(encoding="utf-8")
    assert text.lstrip().startswith("{")
    assert "auth.disabled" not in text
    assert "[warning" not in text


def test_progress_goes_to_stderr_not_stdout(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    main([str(tmp_path / "openapi.json")])
    captured = capsys.readouterr()
    assert "wrote" in captured.err
    assert "wrote" not in captured.out


def test_documents_the_routes_the_console_consumes(tmp_path: Path) -> None:
    out = tmp_path / "openapi.json"
    main([str(out)])
    paths = json.loads(out.read_text(encoding="utf-8"))["paths"]
    for route in (
        "/scenarios",
        "/scenarios/{scenario_id}",
        "/scenarios/{scenario_id}/events",
        "/investigations",
        "/investigations/{job_id}/evidence/{evidence_id}",
        "/investigations/{job_id}/review",
        "/reviews",
        "/reviews/export",
        "/auth/token",
        "/me",
    ):
        assert route in paths, f"{route} missing from the schema the console generates from"
