"""HTTP API tests (offline ScriptedChat; no live LLM)."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from alert2attack.agent.llm import ChatResponse, ScriptedChat
from alert2attack.api.app import create_app
from alert2attack.domain.scenario import SCENARIOS_ROOT, load_scenario


def _scripted_factory(_model: str) -> ScriptedChat:
    scenario = load_scenario(SCENARIOS_ROOT / "otrf_empire_launcher_vbs")
    eid = scenario.alert.trigger_event_id
    casefile = {
        "verdict": "malicious",
        "confidence": "medium",
        "summary": "OTRF empire launcher activity looks malicious.",
        "timeline": [{"ts": "2020-09-04T20:09:55Z", "text": "encoded powershell", "evidence": [eid]}],
        "techniques": [],
        "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
        "next_actions": [
            {"action": "escalate", "rationale": {"text": "need analyst", "evidence": [eid]}},
        ],
        "open_questions": [],
    }
    payload = json.dumps(casefile)
    return ScriptedChat(
        [
            ChatResponse(content="1. alert 2. write"),
            ChatResponse(content="ready"),
            ChatResponse(content=payload),
            ChatResponse(content=payload),
            ChatResponse(content=payload),
        ]
    )


def test_health_and_metrics() -> None:
    client = TestClient(create_app(chat_factory=_scripted_factory))
    assert client.get("/health").json() == {"status": "ok"}
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "alert2attack_investigations_total" in metrics.text or metrics.text.startswith("#")


def test_sync_investigation() -> None:
    client = TestClient(create_app(chat_factory=_scripted_factory))
    resp = client.post(
        "/investigations",
        json={"scenario_id": "otrf_empire_launcher_vbs", "model": "scripted", "sync": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "succeeded"
    assert body["result"]["case_file"]["verdict"] == "malicious"
    assert body["result"]["verification"]["passed"] is True
    got = client.get(f"/investigations/{body['id']}")
    assert got.status_code == 200
    assert got.json()["status"] == "succeeded"


def test_async_investigation() -> None:
    client = TestClient(create_app(chat_factory=_scripted_factory))
    resp = client.post(
        "/investigations",
        json={"scenario_id": "otrf_empire_launcher_vbs", "model": "scripted", "sync": False},
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] in {"queued", "running", "succeeded"}
    # TestClient runs background tasks before returning for sync client; poll anyway.
    done = client.get(f"/investigations/{body['id']}")
    assert done.status_code == 200
    assert done.json()["status"] == "succeeded"


def test_unknown_scenario_sync_fails() -> None:
    client = TestClient(create_app(chat_factory=_scripted_factory))
    resp = client.post(
        "/investigations",
        json={"scenario_id": "does_not_exist", "model": "scripted", "sync": True},
    )
    assert resp.status_code == 400


def test_scripted_without_factory_rejected() -> None:
    client = TestClient(create_app())
    resp = client.post(
        "/investigations",
        json={"scenario_id": "otrf_empire_launcher_vbs", "model": "scripted", "sync": True},
    )
    assert resp.status_code == 400


def test_list_investigations() -> None:
    client = TestClient(create_app(chat_factory=_scripted_factory))
    client.post(
        "/investigations",
        json={"scenario_id": "otrf_empire_launcher_vbs", "model": "scripted", "sync": True},
    )
    listed = client.get("/investigations")
    assert listed.status_code == 200
    assert len(listed.json()) >= 1
