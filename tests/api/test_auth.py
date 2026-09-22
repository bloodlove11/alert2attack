"""Single-operator authentication."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from alert2attack.api.app import create_app
from alert2attack.api.auth import (
    ALGORITHM,
    AuthConfig,
    auth_config_from_env,
    hash_password,
    issue_token,
    verify_password,
)
from alert2attack.api.factory import ChatFactory

PASSWORD = "correct horse battery staple"
SECRET = "test-secret-not-used-anywhere-real"


@pytest.fixture
def enabled_auth() -> AuthConfig:
    return AuthConfig(
        enabled=True,
        username="analyst",
        password_hash=hash_password(PASSWORD),
        secret=SECRET,
        ttl_minutes=30,
    )


@pytest.fixture
def secured(scripted_factory: ChatFactory, enabled_auth: AuthConfig) -> TestClient:
    return TestClient(create_app(chat_factory=scripted_factory, auth_config=enabled_auth))


@pytest.fixture
def open_api(scripted_factory: ChatFactory) -> TestClient:
    return TestClient(
        create_app(chat_factory=scripted_factory, auth_config=AuthConfig(enabled=False))
    )


# -- password hashing ---------------------------------------------------------


def test_hash_round_trips() -> None:
    encoded = hash_password(PASSWORD)
    assert verify_password(PASSWORD, encoded)


def test_hash_does_not_contain_the_password() -> None:
    assert PASSWORD not in hash_password(PASSWORD)


def test_hash_is_salted() -> None:
    assert hash_password(PASSWORD) != hash_password(PASSWORD)


def test_wrong_password_is_rejected() -> None:
    assert not verify_password("wrong", hash_password(PASSWORD))


@pytest.mark.parametrize(
    "bad", ["", "notahash", "scrypt$only-two", "bcrypt$c2FsdA==$aGFzaA==", "scrypt$!!!$!!!"]
)
def test_malformed_hash_is_a_failed_login_not_a_crash(bad: str) -> None:
    assert verify_password(PASSWORD, bad) is False


# -- config -------------------------------------------------------------------


def test_auth_is_off_without_a_configured_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CONSOLE_PASSWORD_HASH", raising=False)
    assert auth_config_from_env().enabled is False


def test_auth_turns_on_when_a_hash_is_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSOLE_PASSWORD_HASH", hash_password(PASSWORD))
    monkeypatch.setenv("CONSOLE_JWT_SECRET", SECRET)
    config = auth_config_from_env()
    assert config.enabled is True
    assert config.username == "analyst"


def test_missing_jwt_secret_falls_back_to_an_ephemeral_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Better than a predictable default; it just invalidates tokens on restart."""
    monkeypatch.setenv("CONSOLE_PASSWORD_HASH", hash_password(PASSWORD))
    monkeypatch.delenv("CONSOLE_JWT_SECRET", raising=False)
    first, second = auth_config_from_env(), auth_config_from_env()
    assert first.secret and second.secret
    assert first.secret != second.secret


# -- login --------------------------------------------------------------------


def test_login_returns_a_bearer_token(secured: TestClient) -> None:
    resp = secured.post("/auth/token", json={"username": "analyst", "password": PASSWORD})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 30 * 60
    claims = jwt.decode(body["access_token"], SECRET, algorithms=[ALGORITHM])
    assert claims["sub"] == "analyst"


def test_wrong_password_is_401(secured: TestClient) -> None:
    resp = secured.post("/auth/token", json={"username": "analyst", "password": "nope"})
    assert resp.status_code == 401


def test_wrong_username_is_401(secured: TestClient) -> None:
    resp = secured.post("/auth/token", json={"username": "intruder", "password": PASSWORD})
    assert resp.status_code == 401


def test_login_is_409_when_auth_is_not_configured(open_api: TestClient) -> None:
    resp = open_api.post("/auth/token", json={"username": "a", "password": "b"})
    assert resp.status_code == 409
    assert "CONSOLE_PASSWORD_HASH" in resp.json()["detail"]


# -- enforcement --------------------------------------------------------------


def _token(client: TestClient) -> str:
    resp = client.post("/auth/token", json={"username": "analyst", "password": PASSWORD})
    return str(resp.json()["access_token"])


PROTECTED = ["/scenarios", "/investigations", "/reviews"]


@pytest.mark.parametrize("path", PROTECTED)
def test_protected_routes_reject_anonymous_callers(secured: TestClient, path: str) -> None:
    resp = secured.get(path)
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


@pytest.mark.parametrize("path", PROTECTED)
def test_protected_routes_accept_a_valid_token(secured: TestClient, path: str) -> None:
    headers = {"Authorization": f"Bearer {_token(secured)}"}
    assert secured.get(path, headers=headers).status_code == 200


def test_health_stays_open_so_probes_work(secured: TestClient) -> None:
    assert secured.get("/health").status_code == 200


def test_metrics_stays_open_for_the_scraper(secured: TestClient) -> None:
    assert secured.get("/metrics").status_code == 200


def test_garbage_token_is_401(secured: TestClient) -> None:
    resp = secured.get("/scenarios", headers={"Authorization": "Bearer not-a-jwt"})
    assert resp.status_code == 401


def test_token_signed_with_another_secret_is_401(secured: TestClient) -> None:
    forged = jwt.encode({"sub": "analyst"}, "a-different-secret", algorithm=ALGORITHM)
    resp = secured.get("/scenarios", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_expired_token_is_401(secured: TestClient, enabled_auth: AuthConfig) -> None:
    past = datetime.now(UTC) - timedelta(hours=2)
    stale = jwt.encode(
        {"sub": "analyst", "iat": int(past.timestamp()), "exp": int((past + timedelta(minutes=30)).timestamp())},
        enabled_auth.secret,
        algorithm=ALGORITHM,
    )
    resp = secured.get("/scenarios", headers={"Authorization": f"Bearer {stale}"})
    assert resp.status_code == 401


def test_token_without_a_subject_is_401(secured: TestClient, enabled_auth: AuthConfig) -> None:
    anonymous = jwt.encode({"iat": 0, "exp": 9_999_999_999}, enabled_auth.secret, algorithm=ALGORITHM)
    resp = secured.get("/scenarios", headers={"Authorization": f"Bearer {anonymous}"})
    assert resp.status_code == 401


# -- the open posture ---------------------------------------------------------


def test_open_api_serves_without_a_token(open_api: TestClient) -> None:
    """The existing local-first posture, preserved when nothing is configured."""
    assert open_api.get("/scenarios").status_code == 200


def test_me_reports_the_auth_state(open_api: TestClient, secured: TestClient) -> None:
    assert open_api.get("/me").json() == {"authenticated": False, "auth_enabled": False}

    headers = {"Authorization": f"Bearer {_token(secured)}"}
    assert secured.get("/me", headers=headers).json() == {
        "authenticated": True,
        "auth_enabled": True,
        "username": "analyst",
    }


def test_me_answers_an_anonymous_caller_when_auth_is_on(secured: TestClient) -> None:
    """The regression: /me sat behind require_operator, so it 401d exactly when
    the console needed it. The client could not tell "auth is enabled" from
    "the API is down" and rendered the app instead of the sign-in."""
    resp = secured.get("/me")
    assert resp.status_code == 200
    assert resp.json() == {"authenticated": False, "auth_enabled": True}


@pytest.mark.parametrize("header", ["Bearer not-a-jwt", "Bearer ", "Basic abc"])
def test_me_treats_a_bad_token_as_anonymous_not_an_error(
    secured: TestClient, header: str
) -> None:
    resp = secured.get("/me", headers={"Authorization": header})
    assert resp.status_code == 200
    assert resp.json()["authenticated"] is False
    assert resp.json()["auth_enabled"] is True


def test_me_discloses_nothing_beyond_whether_auth_is_on(secured: TestClient) -> None:
    body = secured.get("/me").json()
    assert set(body) == {"authenticated", "auth_enabled"}


def test_issue_token_respects_the_configured_ttl(enabled_auth: AuthConfig) -> None:
    short = enabled_auth.model_copy(update={"ttl_minutes": 5})
    assert issue_token(short, username="analyst").expires_in == 300
