"""Lightning helper scripts resolve Studio paths from env and can print them."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"

LIGHTNING_SCRIPTS = (
    "lightning_qlora_run.sh",
    "lightning_qlora_smoke.sh",
    "lightning_qlora_official.sh",
    "lightning_graph_only_official.sh",
)


def _print_paths(script: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ALERT2ATTACK_PRINT_PATHS"] = "1"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(SCRIPTS / script)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_lightning_scripts_print_override_paths() -> None:
    extra = {
        "ALERT2ATTACK_STUDIO_ROOT": "/tmp/studio-x",
        "ALERT2ATTACK_EVAL_DIR": "/tmp/eval-x",
        "ALERT2ATTACK_EXP_DIR": "/tmp/exp-x",
    }
    for name in LIGHTNING_SCRIPTS:
        proc = _print_paths(name, extra)
        assert proc.returncode == 0, f"{name}: {proc.stderr}"
        assert "ALERT2ATTACK_STUDIO_ROOT=/tmp/studio-x" in proc.stdout
        assert "ALERT2ATTACK_EVAL_DIR=/tmp/eval-x" in proc.stdout
        assert "ALERT2ATTACK_EXP_DIR=/tmp/exp-x" in proc.stdout
        assert "nvidia-smi" not in proc.stdout
        assert "ollama" not in proc.stdout.lower()


def test_lightning_scripts_default_studio_root() -> None:
    env_drop = os.environ.copy()
    env_drop["ALERT2ATTACK_PRINT_PATHS"] = "1"
    env_drop["ALERT2ATTACK_STUDIO_ROOT"] = "/tmp/studio-default"
    for key in ("ALERT2ATTACK_EVAL_DIR", "ALERT2ATTACK_EXP_DIR", "EXP004_ROOT"):
        env_drop.pop(key, None)

    smoke = subprocess.run(
        ["bash", str(SCRIPTS / "lightning_qlora_smoke.sh")],
        check=False,
        capture_output=True,
        text=True,
        env=env_drop,
    )
    assert smoke.returncode == 0, smoke.stderr
    assert smoke.stdout.splitlines() == [
        "ALERT2ATTACK_STUDIO_ROOT=/tmp/studio-default",
        "ALERT2ATTACK_EVAL_DIR=/tmp/studio-default/alert2attack-lever6",
        "ALERT2ATTACK_EXP_DIR=/tmp/studio-default/exp004-n14",
    ]

    graph = subprocess.run(
        ["bash", str(SCRIPTS / "lightning_graph_only_official.sh")],
        check=False,
        capture_output=True,
        text=True,
        env=env_drop,
    )
    assert graph.returncode == 0, graph.stderr
    assert "ALERT2ATTACK_EXP_DIR=/tmp/studio-default/exp005-graph-only" in graph.stdout


def test_qlora_run_exp004_root_alias() -> None:
    env = os.environ.copy()
    env["ALERT2ATTACK_PRINT_PATHS"] = "1"
    env["ALERT2ATTACK_STUDIO_ROOT"] = "/tmp/studio-alias"
    env["EXP004_ROOT"] = "/tmp/legacy-exp"
    for key in ("ALERT2ATTACK_EVAL_DIR", "ALERT2ATTACK_EXP_DIR"):
        env.pop(key, None)
    proc = subprocess.run(
        ["bash", str(SCRIPTS / "lightning_qlora_run.sh")],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ALERT2ATTACK_EXP_DIR=/tmp/legacy-exp" in proc.stdout
