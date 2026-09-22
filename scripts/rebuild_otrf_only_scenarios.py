#!/usr/bin/env python3
"""Rebuild datasets/scenarios from downloaded OTRF zips only (no authored telemetry)."""

from __future__ import annotations

import json
import re
import shutil
import zipfile
from datetime import timedelta
from pathlib import Path

import yaml

from alert2attack.dataset.build import (
    build_scenario_from_records,
    load_otrf_records,
    sha256_file,
    truncate_to_trigger_context,
    write_scenario_dir,
)
from alert2attack.dataset.otrf import iter_normalized
from alert2attack.dataset.window import assign_evidence_ids
from alert2attack.domain.alert import Alert, Severity
from alert2attack.domain.events import Event, EventKind
from alert2attack.domain.scenario import Gold, Provenance, Scenario, Window

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "datasets" / "scenarios"
CATALOG_PATH = ROOT / "datasets" / "catalog.yaml"
ZIP_DIRS = [Path("/tmp/otrf-dl"), Path("/tmp/otrf-dl2")]

RULES = {
    "mshta": ("win_susp_mshta", "Mshta Proxy Execution"),
    "rundll": ("win_susp_rundll32", "Suspicious Rundll32 Execution"),
    "schtask": ("win_susp_schtask_creation", "Suspicious Scheduled Task Creation"),
    "lsass": ("win_susp_lsass_access", "LSASS Memory Access"),
    "runkey": ("win_susp_run_key", "Registry Run Key Persistence"),
    "certutil": ("win_susp_certutil_download", "Certutil Download"),
    "default": ("win_powershell_encoded_command", "Suspicious Encoded PowerShell Command Line"),
}

TECHNIQUES: dict[str, list[str]] = {
    "empire_launcher_vbs": ["T1059.001", "T1027", "T1204.002"],
    "empire_launcher_sct_regsvr32": ["T1218.010", "T1059.001"],
    "psh_powershell_httplistener": ["T1059.001", "T1071.001"],
    "cmd_sharpview_pcre_net": ["T1059.003", "T1047"],
    "psh_python_webserver": ["T1059.001", "T1105"],
    "cmd_bitsadmin_download_psh_script": ["T1105", "T1197"],
    "cmd_mshta_javascript_getobject_sct": ["T1218.005", "T1059.001"],
    "cmd_mshta_vbscript_execute_psh": ["T1218.005", "T1059.001"],
    "psh_mshta_html_application_execution": ["T1218.005"],
    "cmd_userinitmprlogonscript_batch": ["T1037.001", "T1059.003"],
    "empire_persistence_registry_modification_run_keys_elevated_user": ["T1547.001", "T1059.001"],
    "empire_persistence_registry_modification_run_keys_standard_user": ["T1547.001"],
    "empire_schtasks_creation_execution_elevated_user": ["T1053.005"],
    "cmd_dumping_ntds_dit_file_ntdsutil": ["T1003.003"],
    "cmd_dumping_ntds_dit_file_volume_shadow_copy": ["T1003.003"],
    "cmd_disable_eventlog_service_startuptype_modification_via_registry": ["T1562.002", "T1112"],
    "auditpol_system_user_auditpolicy_modification": ["T1562.002"],
    "cmd_lsass_memory_dumpert_syscalls": ["T1003.001"],
    "cmd_psexec_lsa_secrets_dump": ["T1003.001", "T1021.002"],
    "covenant_installutil": ["T1218.004", "T1059.003"],
    "covenant_lolbin_wuauclt_createremotethread": ["T1218", "T1055"],
    "covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges": ["T1003.006"],
    "empire_dcsync_dcerpc_drsuapi_DsGetNCChanges": ["T1003.006"],
    "empire_dllinjection_LoadLibrary_CreateRemoteThread": ["T1055"],
    "empire_mimikatz_logonpasswords": ["T1003.001"],
    "empire_mimikatz_extract_keys": ["T1003.001"],
    "empire_mimikatz_backupkeys_dcerpc_smb_lsarpc": ["T1003.001"],
    "empire_monologue_netntlm_downgrade": ["T1112", "T1003"],
    "empire_powerview_ldap_ntsecuritydescriptor": ["T1047", "T1222"],
    "empire_psinject_PEinjection": ["T1055"],
    "empire_wmic_add_user_backdoor": ["T1047"],
    "wmic_remote_xsl_jscript": ["T1047", "T1220"],
}


def basename(path: str | None) -> str:
    return (path or "").split("\\")[-1].lower()


def catalog_id_from_zip(name: str) -> str:
    stem = name[:-4] if name.endswith(".zip") else name
    slug = re.sub(r"[^a-z0-9]+", "_", stem.lower()).strip("_")
    return slug


def rule_for(catalog_id: str) -> tuple[str, str]:
    cid = catalog_id.lower()
    if "mshta" in cid:
        return RULES["mshta"]
    if "rundll" in cid:
        return RULES["rundll"]
    if "schtask" in cid:
        return RULES["schtask"]
    if "lsass" in cid or "mimikatz" in cid or "dumpert" in cid or "dcsync" in cid:
        return RULES["lsass"]
    if "run_keys" in cid or "run_key" in cid or "userinit" in cid:
        return RULES["runkey"]
    if "certutil" in cid:
        return RULES["certutil"]
    return RULES["default"]


def techniques_for(zip_name: str, catalog_id: str) -> list[str]:
    stem = zip_name[:-4] if zip_name.endswith(".zip") else zip_name
    if stem in TECHNIQUES:
        return list(TECHNIQUES[stem])
    if catalog_id in TECHNIQUES:
        return list(TECHNIQUES[catalog_id])
    # fuzzy
    for key, techs in TECHNIQUES.items():
        if key.lower() in catalog_id or catalog_id in key.lower():
            return list(techs)
    return ["T1059.001"]


def load_zip_records(zip_path: Path) -> list[dict]:
    with zipfile.ZipFile(zip_path) as zf:
        names = [n for n in zf.namelist() if n.endswith(".json")]
        if not names:
            raise FileNotFoundError(f"no json in {zip_path}")
        raw = zf.read(names[0])
    tmp = Path("/tmp/_otrf_rebuild.json")
    tmp.write_bytes(raw)
    return load_otrf_records(tmp)


def discover_zips() -> dict[str, Path]:
    found: dict[str, Path] = {}
    for d in ZIP_DIRS:
        if not d.exists():
            continue
        for z in d.glob("*.zip"):
            found[z.name] = z
    return found


def otrf_url(folder: str, zip_name: str) -> str:
    return (
        "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
        f"datasets/atomic/windows/{folder}/{zip_name}"
    )


def infer_folder(zip_name: str) -> str:
    # Prefer meta if present
    for meta_path in [Path("/tmp/otrf-dl/catalog_meta.json"), Path("/tmp/otrf-dl2/catalog_meta.json")]:
        if not meta_path.exists():
            continue
        for item in json.loads(meta_path.read_text()):
            if item.get("name") == zip_name:
                return item["folder"]
    name = zip_name.lower()
    if any(x in name for x in ("mimikatz", "ntds", "lsass", "dcsync", "dumpert", "psexec_lsa")):
        return "credential_access/host"
    if any(x in name for x in ("run_keys", "schtasks", "userinit", "persistence")):
        return "persistence/host"
    if any(
        x in name
        for x in (
            "mshta",
            "bitsadmin",
            "regsvr",
            "installutil",
            "wmic",
            "dllinjection",
            "psinject",
            "monologue",
            "powerview",
            "wuauclt",
            "auditpol",
            "eventlog",
        )
    ):
        return "defense_evasion/host"
    return "execution/host"


ATTACK_MARKERS = (
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll",
    "regsvr",
    "bitsadmin",
    "certutil",
    "schtasks",
    "mimikatz",
    "psexec",
    "ntdsutil",
    "installutil",
    "sharpview",
    "dumpert",
    "whoami",
    "wmic",
    "payload",
    "empire",
    "beacon",
)


def is_attackish(event: Event) -> bool:
    for name in (basename(event.image), basename(event.target_image), basename(event.parent_image)):
        if any(m in name for m in ATTACK_MARKERS):
            return True
    cmd = (event.command_line or "").lower()
    return any(m in cmd for m in ("encodedcommand", "-enc ", "mimikatz", "invoke-"))


def select_benign_lsass_events(events: list[Event], trigger: Event, *, max_events: int = 40) -> list[Event]:
    start = trigger.ts - timedelta(seconds=30)
    end = trigger.ts + timedelta(seconds=60)
    pool = [e for e in events if start <= e.ts <= end and not is_attackish(e)]
    chosen: list[Event] = [trigger]
    for e in pool:
        if e.kind is EventKind.PROCESS_CREATE:
            chosen.append(e)
    for e in pool:
        if e.kind is EventKind.PROCESS_ACCESS and e.pid == trigger.pid and e not in chosen:
            chosen.append(e)
        if len(chosen) >= max_events:
            break
    for e in pool:
        if e.kind in {EventKind.DNS_QUERY, EventKind.NETWORK_CONNECT, EventKind.REGISTRY_SET, EventKind.FILE_CREATE}:
            if e not in chosen:
                chosen.append(e)
        if len(chosen) >= max_events:
            break
    # Fill with nearest remaining non-attack events if still thin
    if len(chosen) < 8:
        for e in sorted(pool, key=lambda x: abs((x.ts - trigger.ts).total_seconds())):
            if e not in chosen:
                chosen.append(e)
            if len(chosen) >= 12:
                break
    return assign_evidence_ids(chosen[:max_events])


def build_benign_scenario(
    records: list[dict],
    *,
    scenario_id: str,
    split: str,
    provenance: Provenance,
    preferred_host_substring: str = "WORKSTATION",
) -> Scenario | None:
    normalized = iter_normalized(records)
    if not normalized:
        return None
    from alert2attack.dataset.build import choose_host

    host = choose_host(normalized, preferred_host_substring)
    on_host = [e for e in normalized if e.host.lower() == host.lower()]
    candidates = [
        e
        for e in on_host
        if e.kind is EventKind.PROCESS_ACCESS
        and basename(e.target_image) == "lsass.exe"
        and basename(e.image) in {"svchost.exe", "vboxservice.exe", "wininit.exe", "csrss.exe", "services.exe"}
    ]
    for trigger in candidates:
        boxed = select_benign_lsass_events(on_host, trigger)
        if len(boxed) < 5:
            continue
        if any(is_attackish(e) for e in boxed):
            continue
        # re-find trigger after id assign
        trig = next(
            e
            for e in boxed
            if e.kind is EventKind.PROCESS_ACCESS
            and e.ts == trigger.ts
            and e.pid == trigger.pid
            and basename(e.image) == basename(trigger.image)
        )
        start = min(e.ts for e in boxed)
        end = max(e.ts for e in boxed)
        if end <= start:
            end = start + timedelta(milliseconds=1)
        rule_id, rule_title = RULES["lsass"]
        root_pid = trig.pid
        pids_present = {e.pid for e in boxed if e.pid is not None}
        key_pids = [p for p in [trig.pid] if p in pids_present]
        if root_pid not in pids_present:
            root_pid = next(iter(pids_present), None)
            if root_pid is not None and root_pid not in key_pids:
                key_pids = [root_pid]
        return Scenario(
            scenario_id=scenario_id,
            split=split,  # type: ignore[arg-type]
            origin="otrf",
            description=(
                f"OTRF background window: {basename(trig.image)} accessed LSASS "
                f"(common false positive for credential-dumping rules)."
            ),
            window=Window(start=start, end=end),
            alert=Alert(
                alert_id=f"alr-{scenario_id[-8:]}",
                host=host,
                fired_at=trig.ts,
                rule_id=rule_id,
                rule_title=rule_title,
                severity=Severity.HIGH,
                trigger_event_id=trig.event_id,
            ),
            events=boxed,
            gold=Gold(
                verdict="likely_benign",
                techniques=[],
                root_pid=root_pid,
                key_pids=key_pids,
                persistence_evidence=[],
                acceptable_actions=["close_as_benign", "monitor"],
                unacceptable_actions=["isolate_host", "kill_process"],
                narrative=(
                    f"GOLD-MARKER-OTRF-BENIGN. Real OTRF telemetry slice from {provenance.catalog_id}: "
                    f"{basename(trig.image)} (pid {trig.pid}) accessed lsass.exe with "
                    f"GrantedAccess={trig.details}. No attacker LOLBIN or dump tool is present in this "
                    f"boxed window; this is a known false-positive class for LSASS-access detections."
                ),
            ),
            provenance=provenance,
        )
    return None


def build_nee_from_malicious(scenario: Scenario, records: list[dict]) -> Scenario | None:
    """Truncate using the full OTRF capture so a real parent process_create can be retained."""
    trigger = next(e for e in scenario.events if e.event_id == scenario.alert.trigger_event_id)
    normalized = iter_normalized(records)
    host = scenario.alert.host
    on_host = [e for e in normalized if e.host.lower() == host.lower()]
    # Resolve trigger in the full stream (pre-box ids differ; match by time/kind/pid/image).
    full_trigger = next(
        (
            e
            for e in on_host
            if e.ts == trigger.ts and e.kind is trigger.kind and e.pid == trigger.pid
        ),
        None,
    )
    if full_trigger is None:
        thin = truncate_to_trigger_context(scenario.events, trigger)
    else:
        thin = truncate_to_trigger_context(on_host, full_trigger)
        # If parent missing, keep the nearest prior process_create on the host (still real data).
        if len(thin) == 1 and full_trigger.kind is EventKind.PROCESS_CREATE:
            priors = [
                e
                for e in on_host
                if e.kind is EventKind.PROCESS_CREATE and e.ts < full_trigger.ts
            ]
            if priors:
                thin = assign_evidence_ids(
                    sorted([max(priors, key=lambda e: e.ts), full_trigger], key=lambda e: e.ts)
                )
            else:
                thin = assign_evidence_ids(thin)
        else:
            thin = assign_evidence_ids(thin)

    if len(thin) < 1:
        return None
    # Must be thinner than the malicious sibling.
    if len(thin) >= len(scenario.events):
        return None
    boxed = thin if all(e.event_id.startswith("ev-") for e in thin) else assign_evidence_ids(thin)
    # Ensure ids are sequential after possible double-assign
    boxed = assign_evidence_ids(boxed)
    start = min(e.ts for e in boxed)
    end = max(e.ts for e in boxed)
    if end <= start:
        end = start + timedelta(milliseconds=1)
    new_trigger = next(
        e
        for e in boxed
        if e.ts == trigger.ts and e.kind is trigger.kind and e.pid == trigger.pid
    )
    root = next(
        (e for e in boxed if e.kind is EventKind.PROCESS_CREATE and e.pid == new_trigger.ppid),
        next((e for e in boxed if e.kind is EventKind.PROCESS_CREATE and e is not new_trigger), new_trigger),
    )
    key_pids = [p for p in [root.pid, new_trigger.pid] if p is not None]
    sid = scenario.scenario_id + "_nee"
    assert scenario.provenance is not None
    return Scenario(
        scenario_id=sid,
        split=scenario.split,
        origin="otrf",
        description=(
            f"Truncated real OTRF window from {scenario.provenance.catalog_id}: "
            "trigger (+ parent when present); insufficient evidence to decide."
        ),
        window=Window(start=start, end=end),
        alert=scenario.alert.model_copy(
            update={
                "alert_id": f"alr-{sid[-8:]}",
                "trigger_event_id": new_trigger.event_id,
                "fired_at": new_trigger.ts,
            }
        ),
        events=boxed,
        gold=Gold(
            verdict="not_enough_evidence",
            techniques=list(scenario.gold.techniques) if scenario.gold else [],
            root_pid=root.pid,
            key_pids=key_pids,
            persistence_evidence=[],
            acceptable_actions=["collect_script", "collect_memory", "escalate", "monitor"],
            unacceptable_actions=["close_as_benign"],
            narrative=(
                f"GOLD-MARKER-OTRF-NEE. Same OTRF source as {scenario.scenario_id}, but the boxed "
                "window retains only the alert trigger and limited parent context. Follow-on child, "
                "network, file and registry evidence are outside the window; the correct action is "
                "to abstain and collect more telemetry."
            ),
        ),
        provenance=scenario.provenance,
    )


def main() -> None:
    zips = discover_zips()
    # Prefer a diverse malicious set (cap ~16)
    preferred = [
        "empire_launcher_vbs.zip",
        "empire_launcher_sct_regsvr32.zip",
        "cmd_mshta_javascript_getobject_sct.zip",
        "cmd_mshta_vbscript_execute_psh.zip",
        "psh_mshta_html_application_execution.zip",
        "cmd_bitsadmin_download_psh_script.zip",
        "cmd_sharpview_pcre_net.zip",
        "psh_python_webserver.zip",
        "psh_powershell_httplistener.zip",
        "cmd_userinitmprlogonscript_batch.zip",
        "empire_persistence_registry_modification_run_keys_elevated_user.zip",
        "empire_persistence_registry_modification_run_keys_standard_user.zip",
        "empire_schtasks_creation_execution_elevated_user.zip",
        "cmd_dumping_ntds_dit_file_ntdsutil.zip",
        "cmd_disable_eventlog_service_startuptype_modification_via_registry.zip",
        "auditpol_system_user_auditpolicy_modification.zip",
        "cmd_lsass_memory_dumpert_syscalls.zip",
        "cmd_psexec_lsa_secrets_dump.zip",
        "empire_mimikatz_logonpasswords.zip",
        "covenant_installutil.zip",
        "wmic_remote_xsl_jscript.zip",
        "empire_wmic_add_user_backdoor.zip",
    ]
    # Benign source zips (large background)
    benign_sources = [
        "empire_mimikatz_extract_keys.zip",
        "empire_powerview_ldap_ntsecuritydescriptor.zip",
        "empire_dllinjection_LoadLibrary_CreateRemoteThread.zip",
        "empire_persistence_registry_modification_run_keys_standard_user.zip",
        "cmd_dumping_ntds_dit_file_volume_shadow_copy.zip",
        "auditpol_system_user_auditpolicy_modification.zip",
        "empire_schtasks_creation_execution_elevated_user.zip",
        "empire_wmic_add_user_backdoor.zip",
    ]

    if SCENARIOS.exists():
        shutil.rmtree(SCENARIOS)
    SCENARIOS.mkdir(parents=True)

    catalog_entries: list[dict] = []
    malicious: list[tuple[Scenario, list[dict], Path]] = []
    written = 0

    for i, zip_name in enumerate(preferred):
        if zip_name not in zips:
            print("skip missing", zip_name)
            continue
        zip_path = zips[zip_name]
        catalog_id = catalog_id_from_zip(zip_name)
        folder = infer_folder(zip_name)
        url = otrf_url(folder, zip_name)
        digest = sha256_file(zip_path)
        techs = techniques_for(zip_name, catalog_id)
        rule_id, rule_title = rule_for(catalog_id)
        split = "test" if i % 3 == 0 else "dev"
        prov = Provenance(catalog_id=catalog_id, source_url=url, source_sha256=digest)
        catalog_entries.append(
            {
                "id": catalog_id,
                "url": url,
                "sha256": digest,
                "techniques": techs,
                "preferred_host_substring": "WORKSTATION",
                "notes": zip_name,
            }
        )
        records = load_zip_records(zip_path)
        try:
            scenario = build_scenario_from_records(
                records,
                scenario_id=f"otrf_{catalog_id}",
                split=split,
                techniques=techs,
                preferred_host_substring="WORKSTATION",
                rule_id=rule_id,
                rule_title=rule_title,
                provenance=prov,
                gold_narrative=f"GOLD-MARKER-OTRF. Derived from OTRF {zip_name} ({catalog_id}).",
                gold_verdict="malicious",
                max_events=48,
            )
        except Exception as exc:  # noqa: BLE001
            print("FAIL malicious", zip_name, exc)
            continue
        write_scenario_dir(scenario, SCENARIOS / scenario.scenario_id)
        malicious.append((scenario, records, zip_path))
        written += 1
        print("malicious", scenario.scenario_id, len(scenario.events), scenario.split)

    # NEE: truncate a subset of malicious with enough events
    nee_count = 0
    for scenario, records, _zip_path in malicious:
        if len(scenario.events) < 6:
            continue
        nee = build_nee_from_malicious(scenario, records)
        if nee is None or len(nee.events) >= len(scenario.events):
            continue
        write_scenario_dir(nee, SCENARIOS / nee.scenario_id)
        nee_count += 1
        written += 1
        print("nee", nee.scenario_id, len(nee.events))
        if nee_count >= 5:
            break

    # Benign LSASS FP slices
    benign_count = 0
    used_hosts_ts: set[tuple[str, str]] = set()
    for j, zip_name in enumerate(benign_sources):
        if zip_name not in zips:
            continue
        zip_path = zips[zip_name]
        catalog_id = catalog_id_from_zip(zip_name)
        folder = infer_folder(zip_name)
        url = otrf_url(folder, zip_name)
        digest = sha256_file(zip_path)
        if not any(e["id"] == catalog_id for e in catalog_entries):
            catalog_entries.append(
                {
                    "id": catalog_id,
                    "url": url,
                    "sha256": digest,
                    "techniques": techniques_for(zip_name, catalog_id),
                    "preferred_host_substring": "WORKSTATION",
                    "notes": zip_name,
                }
            )
        records = load_zip_records(zip_path)
        split = "test" if j % 2 == 0 else "dev"
        sid = f"otrf_{catalog_id}_benign_lsass"
        # uniqueness
        if (SCENARIOS / sid).exists():
            sid = f"{sid}_{benign_count}"
        sc = build_benign_scenario(
            records,
            scenario_id=sid,
            split=split,
            provenance=Provenance(catalog_id=catalog_id, source_url=url, source_sha256=digest),
        )
        if sc is None:
            print("no benign window", zip_name)
            continue
        key = (sc.alert.host, sc.alert.fired_at.isoformat())
        if key in used_hosts_ts:
            print("dup benign", zip_name)
            continue
        used_hosts_ts.add(key)
        write_scenario_dir(sc, SCENARIOS / sc.scenario_id)
        benign_count += 1
        written += 1
        print("benign", sc.scenario_id, len(sc.events))
        if benign_count >= 6:
            break

    CATALOG_PATH.write_text(yaml.safe_dump({"datasets": catalog_entries}, sort_keys=False), encoding="utf-8")
    print("wrote", written, "scenarios; catalog", len(catalog_entries))


if __name__ == "__main__":
    main()
