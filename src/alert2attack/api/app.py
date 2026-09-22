"""FastAPI application for alert2attack investigations."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any, Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from alert2attack.agent.progress import DoneEvent, ErrorEvent
from alert2attack.api.auth import (
    AuthConfig,
    LoginRequest,
    Operator,
    TokenResponse,
    auth_config_from_env,
    authenticate,
    optional_operator,
    require_operator,
)
from alert2attack.api.evidence import (
    EvidenceNotInLedger,
    EvidenceResolution,
    EvidenceUnresolvable,
    resolve,
)
from alert2attack.api.factory import ChatFactory, default_chat_factory
from alert2attack.api.jobs import InMemoryJobStore, InvestigationJob, JobStore, SqliteJobStore
from alert2attack.api.metrics import RENDER_PROM
from alert2attack.api.progress_hub import ProgressHub
from alert2attack.api.reviews import (
    EvalCaseCandidate,
    InMemoryReviewStore,
    Review,
    ReviewRequest,
    ReviewStore,
    SqliteReviewStore,
    build_review,
    export_candidates,
)
from alert2attack.api.scenarios import (
    SCENARIO_ID_PATTERN,
    EventPage,
    ScenarioDetail,
    ScenarioNotFound,
    ScenarioSummary,
    case_store_for,
    detail,
    list_summaries,
)
from alert2attack.api.service import run_investigation
from alert2attack.api.sse import event_stream, parse_last_event_id
from alert2attack.domain.events import EventKind
from alert2attack.retrieval.retriever import Hit, Mode, ModeUnavailable, Retriever

DEFAULT_CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"


def cors_origins() -> list[str]:
    """Allowed browser origins, from ``ALERT2ATTACK_CORS_ORIGINS`` (comma-separated).

    Defaults to the Vite dev server on loopback. Never ``*``: these routes will
    carry an Authorization header once auth lands, and a wildcard origin plus
    credentials is the combination browsers refuse anyway.
    """
    raw = os.environ.get("ALERT2ATTACK_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def default_job_store() -> JobStore:
    """Durable when ``ALERT2ATTACK_JOBS_DB`` is set, in-memory otherwise.

    In-memory stays the default so tests and the CLI keep their current
    behaviour and no test run leaves a database file behind. Compose sets the
    env var, because a console case link must survive an API restart.
    """
    db_path = os.environ.get("ALERT2ATTACK_JOBS_DB")
    if not db_path:
        return InMemoryJobStore()
    store = SqliteJobStore(db_path)
    store.fail_stale_running()
    return store


class SearchResponse(BaseModel):
    query: str
    mode: Mode
    available_modes: list[Mode]
    hits: list[Hit]
    # Enough to tell a real result from a demo one: the vendored fallback corpus
    # is 30 techniques chosen around the answer key and says so here.
    corpus_source: str
    n_techniques: int
    catalog_revision: str | None = None
    embedder: str | None = None


class CreateInvestigationRequest(BaseModel):
    scenario_id: str = Field(min_length=1)
    model: Literal["ollama", "local-7b", "openai", "teacher", "replay", "scripted"] = "ollama"
    sync: bool = False


class InvestigationJobResponse(BaseModel):
    id: str
    status: Literal["queued", "running", "succeeded", "failed"]
    scenario_id: str
    model: str
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: str
    updated_at: str


def _job_response(job: InvestigationJob) -> InvestigationJobResponse:
    return InvestigationJobResponse(
        id=job.id,
        status=job.status,
        scenario_id=job.scenario_id,
        model=job.model,
        result=job.result,
        error=job.error,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


def default_review_store() -> ReviewStore:
    """Durable alongside the jobs DB when one is configured."""
    db_path = os.environ.get("ALERT2ATTACK_JOBS_DB")
    return SqliteReviewStore(db_path) if db_path else InMemoryReviewStore()


def create_app(
    *,
    chat_factory: ChatFactory | None = None,
    job_store: JobStore | None = None,
    review_store: ReviewStore | None = None,
    auth_config: AuthConfig | None = None,
    retriever: Retriever | None = None,
) -> FastAPI:
    """Build the FastAPI app (injectable for tests)."""

    store = job_store or default_job_store()
    reviews = review_store or default_review_store()
    hub = ProgressHub()
    auth = auth_config or auth_config_from_env()
    resolve_chat = chat_factory or default_chat_factory
    retriever_holder: dict[str, Retriever | None] = {"r": retriever}

    def get_retriever() -> Retriever:
        # Built on first use, not at startup: a dense retriever embeds the whole
        # corpus, and an API that never gets a search should not pay for it.
        if retriever_holder["r"] is None:
            from alert2attack.retrieval.factory import shared_retriever

            retriever_holder["r"] = shared_retriever()
        found = retriever_holder["r"]
        assert found is not None
        return found

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(
        title="alert2attack",
        description="Local-first EDR investigation agent API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.job_store = store
    app.state.progress_hub = hub
    app.state.review_store = reviews
    app.state.auth_config = auth
    app.state.chat_factory = resolve_chat

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Last-Event-ID"],
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics() -> Response:
        # Left open deliberately: a Prometheus scraper carries no bearer token,
        # and the published port binds to loopback.
        payload, content_type = RENDER_PROM()
        return Response(content=payload, media_type=content_type)

    # -- auth ---------------------------------------------------------------------

    @app.post("/auth/token", response_model=TokenResponse)
    def login(body: LoginRequest) -> TokenResponse:
        if not auth.enabled:
            raise HTTPException(
                status_code=409,
                detail="authentication is not configured; set CONSOLE_PASSWORD_HASH",
            )
        return authenticate(auth, body)

    @app.get("/me")
    def me(
        caller: Annotated[Operator | None, Depends(optional_operator)] = None,
    ) -> dict[str, Any]:
        """Who the bearer token says you are, and whether auth is on at all.

        Answers anonymous callers on purpose: it is how the console learns
        whether to show a sign-in. It discloses only that auth is enabled.
        """
        if caller is None:
            return {"authenticated": False, "auth_enabled": auth.enabled}
        return {"authenticated": True, "auth_enabled": True, "username": caller.username}

    # -- scenarios (read-only; see alert2attack.api.scenarios for the gold boundary) ---

    @app.get("/scenarios", response_model=list[ScenarioSummary], dependencies=[Depends(require_operator)])
    def get_scenarios(
        split: Annotated[Literal["dev", "test"] | None, Query()] = None,
        severity: Annotated[Literal["low", "medium", "high", "critical"] | None, Query()] = None,
        q: Annotated[str | None, Query(max_length=200)] = None,
    ) -> list[ScenarioSummary]:
        rows = list_summaries()
        if split is not None:
            rows = [r for r in rows if r.split == split]
        if severity is not None:
            rows = [r for r in rows if r.severity.value == severity]
        if q:
            needle = q.lower()
            rows = [
                r
                for r in rows
                if needle in r.scenario_id.lower()
                or needle in r.rule_title.lower()
                or needle in r.host.lower()
            ]
        return rows

    @app.get("/scenarios/{scenario_id}", response_model=ScenarioDetail, dependencies=[Depends(require_operator)])
    def get_scenario(
        scenario_id: Annotated[str, PathParam(pattern=SCENARIO_ID_PATTERN)],
    ) -> ScenarioDetail:
        try:
            return detail(scenario_id)
        except ScenarioNotFound as exc:
            raise HTTPException(status_code=404, detail=f"unknown scenario id={scenario_id!r}") from exc

    @app.get("/scenarios/{scenario_id}/events", response_model=EventPage, dependencies=[Depends(require_operator)])
    def get_scenario_events(
        scenario_id: Annotated[str, PathParam(pattern=SCENARIO_ID_PATTERN)],
        pid: Annotated[int | None, Query()] = None,
        kind: Annotated[list[EventKind] | None, Query()] = None,
        q: Annotated[str | None, Query(max_length=200)] = None,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> EventPage:
        try:
            store_ = case_store_for(scenario_id)
        except ScenarioNotFound as exc:
            raise HTTPException(status_code=404, detail=f"unknown scenario id={scenario_id!r}") from exc
        try:
            events, next_cursor = store_.page_events(
                scenario_id,
                kinds=kind,
                pid=pid,
                contains=q,
                after=cursor,
                limit=limit,
            )
        except ValueError as exc:
            # A malformed cursor is the caller's mistake, not a server fault.
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            store_.close()
        return EventPage(events=events, next_cursor=next_cursor, limit=limit)

    def _execute(job_id: str, scenario_id: str, model: str) -> None:
        job = store.get(job_id)
        if job is None:
            return
        progress = hub.get(job_id) or hub.create(job_id)
        job.status = "running"
        store.update(job)
        try:
            # Resolve chat per run so scripted fixtures can reset.
            chat = resolve_chat(model)
            result = run_investigation(
                scenario_id=scenario_id,
                model=model,
                chat_factory=lambda _m: chat,
                investigation_id=job_id,
                progress=progress,
            )
            job = store.get(job_id)
            if job is None:
                return
            job.status = "succeeded"
            job.result = result
            job.error = None
            store.update(job)
            # done carries no case file: the client refetches over REST so there
            # is one authoritative representation of it.
            progress.emit(DoneEvent(job_id=job_id))
        except Exception as exc:  # noqa: BLE001 — surface as job failure
            progress.emit(ErrorEvent(message=str(exc)))
            job = store.get(job_id)
            if job is None:
                return
            job.status = "failed"
            job.error = str(exc)
            store.update(job)
        finally:
            # Wakes any subscriber still waiting, including on a path that
            # emitted neither done nor error.
            progress.close()

    def _validate_request(model: str) -> None:
        # Avoid instantiating chat models here — ScriptedChat is stateful.
        if chat_factory is not None:
            return
        if model == "scripted":
            raise HTTPException(
                status_code=400,
                detail="scripted model requires an injected chat factory for tests",
            )
        if model in {"openai", "teacher"} and not (
            os.environ.get("EXPLABS_API_KEY") or os.environ.get("OPENAI_API_KEY")
        ):
            raise HTTPException(
                status_code=400,
                detail="EXPLABS_API_KEY or OPENAI_API_KEY required for openai/teacher model",
            )

    @app.post("/investigations", response_model=InvestigationJobResponse, dependencies=[Depends(require_operator)])
    def create_investigation(
        body: CreateInvestigationRequest,
        background_tasks: BackgroundTasks,
    ) -> InvestigationJobResponse | JSONResponse:
        _validate_request(body.model)
        job = store.create(scenario_id=body.scenario_id, model=body.model)
        # Created here, not in _execute: the client gets the job id back and
        # opens the stream immediately, which can beat the background task to
        # the first event.
        hub.create(job.id)

        if body.sync:
            _execute(job.id, body.scenario_id, body.model)
            done = store.get(job.id)
            assert done is not None
            if done.status == "failed":
                raise HTTPException(
                    status_code=400,
                    detail=done.error or "investigation failed",
                )
            return JSONResponse(
                status_code=200,
                content=_job_response(done).model_dump(mode="json"),
            )

        background_tasks.add_task(_execute, job.id, body.scenario_id, body.model)
        return JSONResponse(
            status_code=202,
            content=_job_response(job).model_dump(mode="json"),
        )

    @app.get(
        "/investigations/{job_id}",
        response_model=InvestigationJobResponse,
        dependencies=[Depends(require_operator)],
    )
    def get_investigation(job_id: str) -> InvestigationJobResponse:
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"unknown job id={job_id!r}")
        return _job_response(job)

    @app.get("/investigations", response_model=list[InvestigationJobResponse], dependencies=[Depends(require_operator)])
    def list_investigations(
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> list[InvestigationJobResponse]:
        return [_job_response(j) for j in store.list(limit=limit)]

    @app.get("/investigations/{job_id}/events", dependencies=[Depends(require_operator)])
    async def stream_investigation(job_id: str, request: Request) -> StreamingResponse:
        """Live progress for one investigation, as server-sent events.

        Carries progress only. The case file is fetched over REST once `done`
        arrives, so there is one authoritative representation of it.
        """
        if store.get(job_id) is None:
            raise HTTPException(status_code=404, detail=f"unknown job id={job_id!r}")
        progress = hub.get(job_id)
        if progress is None:
            # The job exists but its buffer is gone: an old job, or one evicted
            # from the hub. Nothing to stream; the result is still on REST.
            raise HTTPException(
                status_code=409,
                detail=f"no live progress for job id={job_id!r}; fetch the result instead",
            )

        after_seq = parse_last_event_id(request.headers.get("last-event-id"))
        return StreamingResponse(
            event_stream(progress, after_seq=after_seq, is_disconnected=request.is_disconnected),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                # Tells nginx and friends not to buffer, which would defeat the
                # entire point of streaming.
                "X-Accel-Buffering": "no",
            },
        )

    @app.get(
        "/investigations/{job_id}/evidence/{evidence_id}",
        response_model=EvidenceResolution,
        dependencies=[Depends(require_operator)],
    )
    def get_evidence(job_id: str, evidence_id: str) -> EvidenceResolution:
        """Resolve one citation from a finished run back to what the agent fetched."""
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"unknown job id={job_id!r}")
        if job.result is None:
            raise HTTPException(
                status_code=409,
                detail=f"investigation is {job.status}; evidence is available once it succeeds",
            )
        try:
            return resolve(
                evidence_id=evidence_id,
                scenario_id=job.scenario_id,
                trace=job.result.get("trace", {}),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except EvidenceNotInLedger as exc:
            # The verifier should have stripped this claim. A visible 404 here is a
            # bug indicator, and the console is the right place to notice it.
            raise HTTPException(
                status_code=404,
                detail=f"evidence_id={evidence_id!r} was never fetched in this run",
            ) from exc
        except EvidenceUnresolvable as exc:
            raise HTTPException(
                status_code=404,
                detail=f"evidence_id={evidence_id!r} is in the ledger but no longer resolvable",
            ) from exc

    # -- search (see alert2attack.retrieval) ------------------------------------------

    @app.get(
        "/search/techniques",
        response_model=SearchResponse,
        dependencies=[Depends(require_operator)],
    )
    def search_techniques(
        q: Annotated[str, Query(min_length=2, max_length=500)],
        mode: Annotated[Mode | None, Query()] = None,
        k: Annotated[int, Query(ge=1, le=25)] = 10,
    ) -> SearchResponse:
        """Find ATT&CK techniques by meaning, by shared words, or both.

        Defaults to hybrid when a dense channel is configured and lexical when it
        is not, so a bare checkout still answers.
        """
        found = get_retriever()
        chosen: Mode = mode or ("hybrid" if "hybrid" in found.modes else "lexical")
        try:
            hits = found.search(q, mode=chosen, k=k, kind="attack_technique")
        except ModeUnavailable as exc:
            raise HTTPException(
                status_code=409,
                detail=f"mode {chosen!r} is not available; available: {found.modes}",
            ) from exc
        return SearchResponse(
            query=q,
            mode=chosen,
            available_modes=found.modes,
            hits=hits,
            corpus_source=found.corpus.source,
            n_techniques=found.corpus.n_techniques,
            catalog_revision=found.corpus.catalog_revision,
            embedder=found.embedder_name,
        )

    # -- analyst review (append-only; see alert2attack.api.reviews) -------------------

    @app.post(
        "/investigations/{job_id}/review",
        response_model=Review,
        status_code=201,
        dependencies=[Depends(require_operator)],
    )
    def add_review(
        job_id: str,
        body: ReviewRequest,
        caller: Annotated[Operator | None, Depends(require_operator)] = None,
    ) -> Review:
        """Record agreement or disagreement with a case file.

        Never mutates the case file: a review is an observation about what the
        agent said on that run, and the run's record stays as it was.
        """
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"unknown job id={job_id!r}")
        if job.result is None:
            raise HTTPException(
                status_code=409,
                detail=f"investigation is {job.status}; there is no case file to review",
            )
        if not body.agrees and body.corrected_verdict is None:
            raise HTTPException(
                status_code=422,
                detail="a disagreement needs a corrected_verdict to be actionable",
            )
        review = build_review(
            job_id=job_id,
            scenario_id=job.scenario_id,
            agent_verdict=str(job.result.get("case_file", {}).get("verdict", "unknown")),
            request=body,
            reviewer=caller.username if caller else "anonymous",
        )
        reviews.add(review)
        return review

    @app.get("/reviews", response_model=list[Review], dependencies=[Depends(require_operator)])
    def list_reviews(
        scenario_id: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[Review]:
        return reviews.list(scenario_id=scenario_id, limit=limit)

    @app.get(
        "/reviews/export",
        response_model=list[EvalCaseCandidate],
        dependencies=[Depends(require_operator)],
    )
    def export_reviews(
        limit: Annotated[int, Query(ge=1, le=500)] = 500,
    ) -> list[EvalCaseCandidate]:
        """Candidate eval cases for a human to curate.

        Export rather than a direct write into the dev split: letting the
        agent's own output become its answer key is the contamination the eval
        protocol exists to prevent.
        """
        return export_candidates(reviews.list(limit=limit))

    @app.get("/", response_class=PlainTextResponse)
    def root() -> str:
        return "alert2attack api — see /docs"

    return app


app = create_app()
