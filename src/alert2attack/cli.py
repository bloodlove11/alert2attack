"""alert2attack command line: inspect scenarios and call tools by hand."""

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario, iter_scenarios, load_scenario
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools import default_registry
from alert2attack.tools.context import EvidenceLedger, ToolContext

app = typer.Typer(no_args_is_help=True, add_completion=False)
scenarios_app = typer.Typer(no_args_is_help=True)
dataset_app = typer.Typer(no_args_is_help=True)
eval_app = typer.Typer(no_args_is_help=True)
app.add_typer(scenarios_app, name="scenarios", help="List and inspect scenarios.")
app.add_typer(dataset_app, name="dataset", help="OTRF catalog and scenario build.")
app.add_typer(eval_app, name="eval", help="Run evaluation arms and write reports.")

RootOpt = Annotated[Path, typer.Option("--root", help="Scenario root directory")]


def _find(root: Path, scenario_id: str) -> Scenario:
    path = root / scenario_id
    if not (path / "manifest.yaml").exists():
        typer.echo(f"error: scenario '{scenario_id}' not found under {root}", err=True)
        raise typer.Exit(code=2)
    return load_scenario(path)


def _parse_kv(pairs: list[str]) -> dict[str, Any]:
    args: dict[str, Any] = {}
    for pair in pairs:
        if "=" not in pair:
            typer.echo(f"error: expected key=value, got '{pair}'", err=True)
            raise typer.Exit(code=2)
        key, raw = pair.split("=", 1)
        try:
            args[key] = json.loads(raw)
        except json.JSONDecodeError:
            args[key] = raw
    return args


@scenarios_app.command("list")
def scenarios_list(root: RootOpt = SCENARIOS_ROOT) -> None:
    """One line per scenario: id, split, origin, gold verdict, event count."""
    for s in iter_scenarios(root):
        verdict = s.gold.verdict if s.gold else "-"
        typer.echo(f"{s.scenario_id:32} {s.split:5} {s.origin:9} {verdict:20} {len(s.events):4} events")


@scenarios_app.command("show")
def scenarios_show(
    scenario_id: str,
    root: RootOpt = SCENARIOS_ROOT,
    gold: Annotated[bool, typer.Option("--gold", help="Include the held-out gold block")] = False,
) -> None:
    """Print a scenario as JSON, without gold unless --gold is passed."""
    s = _find(root, scenario_id)
    view = s if gold else s.public()
    typer.echo(view.model_dump_json(indent=2, exclude_none=True))


@app.command("tools")
def tools() -> None:
    """Print the tool schemas exactly as an LLM would receive them."""
    typer.echo(json.dumps(default_registry().openai_schemas(), indent=2))


@app.command("tool")
def tool(
    name: str,
    scenario: Annotated[str, typer.Option("--scenario", help="Scenario id to open as a case")],
    kv: Annotated[list[str] | None, typer.Argument(help="Tool arguments as key=value")] = None,
    root: RootOpt = SCENARIOS_ROOT,
) -> None:
    """Call one tool against a scenario and print the result plus the evidence ledger."""
    s = _find(root, scenario).public()
    store = CaseStore()
    store.load_case(s)
    ctx = ToolContext(
        store=store, case_id=s.scenario_id, ledger=EvidenceLedger(), knowledge=KnowledgeBase.load_default()
    )
    result = default_registry().call(ctx, name, _parse_kv(kv or []))
    typer.echo(
        json.dumps(
            {"result": result.model_dump(), "ledger": sorted(ctx.ledger.ids())},
            indent=2,
            default=str,
        )
    )
    if not result.ok:
        raise typer.Exit(code=1)


@app.command("investigate")
def investigate(
    scenario_id: str,
    root: RootOpt = SCENARIOS_ROOT,
    model: Annotated[
        str,
        typer.Option("--model", help="scripted|ollama|openai (scripted requires --responses-json)"),
    ] = "ollama",
    responses_json: Annotated[
        Path | None,
        typer.Option("--responses-json", help="ScriptedChat responses JSON (CI/demo)"),
    ] = None,
    max_tools: Annotated[
        int,
        typer.Option("--max-tools", help="Tool-call cap; 0 = unbounded"),
    ] = 0,
    max_llm: Annotated[int, typer.Option("--max-llm", help="LLM-call cap; 0 = unbounded")] = 0,
    timeout_s: Annotated[float, typer.Option("--timeout-s", help="Wall-clock cap seconds; 0 = unbounded")] = 0.0,
    skip_plan: Annotated[bool, typer.Option("--skip-plan", help="Ablation: fixed plan, no planner LLM")] = False,
    max_turns: Annotated[
        int, typer.Option("--max-turns", help="Max investigate LLM turns; 0 = unbounded")
    ] = 0,
) -> None:
    """Run the LangGraph investigator and print CaseFile + trace summary."""
    import os

    from alert2attack.agent.budget import Budget
    from alert2attack.agent.investigator import Investigator
    from alert2attack.agent.llm import OllamaChat, ScriptedChat, scripted_responses_from_json

    scenario = _find(root, scenario_id)
    if responses_json is not None or model == "scripted":
        if responses_json is None:
            typer.echo("error: --model scripted requires --responses-json", err=True)
            raise typer.Exit(code=2)
        llm: Any = ScriptedChat(scripted_responses_from_json(responses_json))
    elif model in {"ollama", "local", "local-7b"}:
        llm = OllamaChat(model=os.environ.get("ALERT2ATTACK_OLLAMA_MODEL", "qwen2.5:7b-instruct"))
    elif model in {"openai", "teacher"}:
        from alert2attack.agent.teacher import teacher_chat

        try:
            llm = teacher_chat()
        except RuntimeError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
    else:
        typer.echo(f"error: unknown --model {model!r}", err=True)
        raise typer.Exit(code=2)

    result = Investigator(
        llm=llm,
        budget=Budget(
            max_tool_calls=None if max_tools <= 0 else max_tools,
            max_llm_calls=None if max_llm <= 0 else max_llm,
            timeout_s=None if timeout_s <= 0 else timeout_s,
        ),
        skip_plan=skip_plan,
        max_investigate_turns=max_turns,
    ).run_scenario(scenario)
    typer.echo(
        json.dumps(
            {
                "case_file": result.case_file.model_dump(mode="json"),
                "trace": {
                    "model": result.trace.model,
                    "budget": result.trace.budget,
                    "llm_calls": [c.model_dump() for c in result.trace.llm_calls],
                    "tool_calls": [c.model_dump() for c in result.trace.tool_calls],
                    "notes": result.trace.notes,
                },
                "verification": None if result.verification is None else result.verification.model_dump(mode="json"),
            },
            indent=2,
            default=str,
        )
    )


@eval_app.command("run")
def eval_run(
    arm: Annotated[
        str,
        typer.Option("--arm", help="b0|agent-scripted|agent-local-7b|agent-teacher|agent-noverify"),
    ],
    split: Annotated[str, typer.Option("--split")] = "dev",
    root: RootOpt = SCENARIOS_ROOT,
    out_dir: Annotated[Path, typer.Option("--out")] = Path("reports"),
    limit: Annotated[int | None, typer.Option("--limit", help="Max scenarios (debug)")] = None,
    export_distill: Annotated[
        Path | None,
        typer.Option("--export-distill", help="Append distillation JSONL (teacher/scripted)"),
    ] = None,
    responses_json: Annotated[
        Path | None,
        typer.Option("--responses-json", help="Required for agent-scripted / scripted b0 in CI"),
    ] = None,
) -> None:
    """Score an investigation arm on a gold split; write reports/<date>-<arm>-<split>.json."""
    from alert2attack.agent.llm import ScriptedChat, scripted_responses_from_json
    from alert2attack.eval.runner import run_eval

    if split not in {"dev", "test"}:
        typer.echo("error: --split must be dev|test", err=True)
        raise typer.Exit(code=2)
    if export_distill is not None and split == "test":
        typer.echo(
            "error: --export-distill is forbidden on --split test "
            "(never export held-out test for SFT)",
            err=True,
        )
        raise typer.Exit(code=2)
    if arm not in {"b0", "agent-scripted", "agent-local-7b", "agent-teacher", "agent-noverify"}:
        typer.echo(f"error: unknown arm {arm!r}", err=True)
        raise typer.Exit(code=2)

    scripted_factory = None
    llm = None
    if arm in {"agent-scripted", "agent-noverify"} or (arm == "b0" and responses_json is not None):
        if responses_json is None:
            typer.echo("error: this arm requires --responses-json in CI/offline mode", err=True)
            raise typer.Exit(code=2)
        responses = scripted_responses_from_json(responses_json)

        def _factory(_scenario: Any) -> Any:
            return ScriptedChat(responses)

        scripted_factory = _factory

    try:
        report = run_eval(
            arm=arm,  # type: ignore[arg-type]
            split=split,  # type: ignore[arg-type]
            root=root,
            out_dir=out_dir,
            limit=limit,
            llm=llm,
            scripted_factory=scripted_factory,
            export_distill=export_distill,
        )
    except RuntimeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(report.markdown_table())
    typer.echo(json.dumps({"n": report.n, "verdict_accuracy": report.verdict_accuracy}, indent=2))


@app.command("serve")
def serve(
    host: Annotated[str, typer.Option("--host")] = "0.0.0.0",
    port: Annotated[int, typer.Option("--port")] = 8000,
) -> None:
    """Run the FastAPI investigations API (uvicorn)."""
    import uvicorn

    uvicorn.run("alert2attack.api.app:app", host=host, port=port, reload=False)


@dataset_app.command("list")
def dataset_list(
    catalog: Annotated[Path, typer.Option("--catalog", help="Catalog YAML")] = Path("datasets/catalog.yaml"),
) -> None:
    """List curated OTRF sources from the catalog."""
    from alert2attack.dataset.catalog import load_catalog

    for entry in load_catalog(catalog):
        typer.echo(f"{entry.id:50} {','.join(entry.techniques)}")


@dataset_app.command("build")
def dataset_build(
    catalog_id: str,
    catalog: Annotated[Path, typer.Option("--catalog", help="Catalog YAML")] = Path("datasets/catalog.yaml"),
    raw_json: Annotated[
        Path | None, typer.Option("--from-json", help="Local OTRF JSON/JSONL (skip download)")
    ] = None,
    out: Annotated[Path, typer.Option("--out", help="Output scenarios root")] = Path("datasets/scenarios"),
) -> None:
    """Build a boxed scenario from a catalog entry (or a local OTRF JSON file)."""
    from alert2attack.dataset.build import build_scenario_from_otrf_json, download_and_extract
    from alert2attack.dataset.catalog import load_catalog
    from alert2attack.domain.scenario import Provenance

    entries = {e.id: e for e in load_catalog(catalog)}
    if catalog_id not in entries:
        typer.echo(f"error: unknown catalog id '{catalog_id}'", err=True)
        raise typer.Exit(code=2)
    entry = entries[catalog_id]
    if raw_json is None:
        dest = Path("datasets/raw") / catalog_id
        json_path = download_and_extract(str(entry.url), entry.sha256, dest)
    else:
        json_path = raw_json
    scenario_id = f"otrf_{catalog_id}"
    path = build_scenario_from_otrf_json(
        json_path,
        scenario_id=scenario_id,
        out_dir=out / scenario_id,
        techniques=list(entry.techniques),
        preferred_host_substring=entry.preferred_host_substring,
        provenance=Provenance(
            catalog_id=entry.id, source_url=str(entry.url), source_sha256=entry.sha256
        ),
        gold_narrative=f"GOLD-MARKER-OTRF. Built from catalog id {catalog_id}.",
    )
    typer.echo(str(path))
