"""Single-operator authentication for the console.

**This is demo-grade and the README says so.** It authenticates one configured
operator against one password hash. There is no user table, no registration, no
password reset and no roles, because shipping a hand-rolled version of those
would be worse than shipping none. A real deployment puts the console behind
the organisation's OIDC provider and deletes this module.

What it does do properly:

- Passwords are verified against a ``scrypt`` hash, never a plaintext env var.
- Comparison is constant-time.
- Tokens are real HS256 JWTs (``PyJWT``), not a hand-rolled signature. In a
  repo about security, inventing token verification is the wrong instinct.
- Auth is *enforced whenever a credential is configured*. With none configured
  the API stays open, which is the existing local-first posture — and it logs a
  warning at startup so that is a decision rather than an accident.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import jwt
import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

log = structlog.get_logger("alert2attack.auth")

ALGORITHM = "HS256"
DEFAULT_TTL_MINUTES = 30

# scrypt parameters. N=2**14 keeps a login around 50-100 ms on a laptop, which
# is the point: it makes guessing the one password expensive.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class LoginRequest(BaseModel):
    username: str
    password: str


class Operator(BaseModel):
    username: str


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """``scrypt$<salt>$<hash>``, both base64url. Used by the helper below."""
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN
    )
    return f"scrypt${urlsafe_b64encode(salt).decode()}${urlsafe_b64encode(derived).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check. A malformed hash is a failed login, never a 500."""
    try:
        scheme, salt_b64, hash_b64 = encoded.split("$")
        if scheme != "scrypt":
            return False
        salt = urlsafe_b64decode(salt_b64)
        expected = urlsafe_b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    # Base64 that decodes to nothing is still a parse failure: scrypt rejects a
    # zero dklen, and an empty salt is not a hash we ever produced.
    if not salt or not expected:
        return False
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=len(expected)
    )
    return hmac.compare_digest(derived, expected)


class AuthConfig(BaseModel):
    """Resolved from the environment once, at app construction."""

    enabled: bool
    username: str = ""
    password_hash: str = ""
    secret: str = ""
    ttl_minutes: int = DEFAULT_TTL_MINUTES


def auth_config_from_env() -> AuthConfig:
    password_hash = os.environ.get("CONSOLE_PASSWORD_HASH", "").strip()
    if not password_hash:
        log.warning(
            "auth.disabled",
            reason="CONSOLE_PASSWORD_HASH is not set; the API accepts unauthenticated callers",
            hint="bind to loopback only, or set CONSOLE_USER and CONSOLE_PASSWORD_HASH",
        )
        return AuthConfig(enabled=False)

    secret = os.environ.get("CONSOLE_JWT_SECRET", "").strip()
    if not secret:
        # A random per-process secret still works; it just invalidates every
        # token on restart. Better than a predictable default.
        secret = secrets.token_urlsafe(32)
        log.warning(
            "auth.ephemeral_secret",
            reason="CONSOLE_JWT_SECRET is not set; tokens will not survive a restart",
        )
    try:
        ttl = int(os.environ.get("CONSOLE_TOKEN_TTL_MINUTES", DEFAULT_TTL_MINUTES))
    except ValueError:
        ttl = DEFAULT_TTL_MINUTES
    return AuthConfig(
        enabled=True,
        username=os.environ.get("CONSOLE_USER", "analyst"),
        password_hash=password_hash,
        secret=secret,
        ttl_minutes=max(1, ttl),
    )


def issue_token(config: AuthConfig, *, username: str) -> TokenResponse:
    ttl = timedelta(minutes=config.ttl_minutes)
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
    }
    token = jwt.encode(payload, config.secret, algorithm=ALGORITHM)
    return TokenResponse(access_token=token, expires_in=int(ttl.total_seconds()))


def decode_token(config: AuthConfig, token: str) -> Operator:
    try:
        payload = jwt.decode(token, config.secret, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token has no subject")
    return Operator(username=subject)


def authenticate(config: AuthConfig, request: LoginRequest) -> TokenResponse:
    """One operator. Both checks run even when the username is wrong, so a
    failed login costs the same either way."""
    user_ok = hmac.compare_digest(request.username, config.username)
    password_ok = verify_password(request.password, config.password_hash)
    if not (user_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return issue_token(config, username=config.username)


# auto_error=False so an unauthenticated call to an open API is not a 403 from
# the scheme before our own config has had a say.
_bearer = HTTPBearer(auto_error=False)


def optional_operator(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> Operator | None:
    """Like ``require_operator`` but never raises: no token, or a bad one, is None.

    Only ``/me`` uses this. The console asks ``/me`` whether it must sign in, so
    the route has to answer an anonymous caller. Behind ``require_operator`` it
    401s when auth is on, and the client cannot tell "auth is enabled" from
    "the API is down".
    """
    config: AuthConfig = request.app.state.auth_config
    if not config.enabled or credentials is None or not credentials.credentials:
        return None
    try:
        return decode_token(config, credentials.credentials)
    except HTTPException:
        return None


def require_operator(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> Operator | None:
    """Module-level on purpose.

    A closure built per app would be unresolvable as a forward reference under
    ``from __future__ import annotations``, because FastAPI resolves route
    annotations against module globals and never sees a local name. Reading the
    config off ``app.state`` keeps the dependency importable and still lets
    each app instance carry its own settings.
    """
    config: AuthConfig = request.app.state.auth_config
    if not config.enabled:
        return None
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return decode_token(config, credentials.credentials)


def _main() -> int:
    """``uv run python -m alert2attack.api.auth`` prints a hash for CONSOLE_PASSWORD_HASH.

    Reads the password from a prompt, not argv, so it never lands in shell
    history or a process listing.
    """
    import getpass

    first = getpass.getpass("Password: ")
    if not first:
        print("empty password refused")
        return 1
    if getpass.getpass("Again: ") != first:
        print("passwords differ")
        return 1
    print(hash_password(first))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
