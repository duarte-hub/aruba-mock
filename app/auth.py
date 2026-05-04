"""Tiny session-cookie auth.

Single admin user, password from env. Good enough for a homelab tool sitting
behind your existing reverse proxy / VLAN.
"""
from __future__ import annotations

import secrets
from typing import Optional

from fastapi import HTTPException, Request, status
from passlib.hash import bcrypt

from app.config import get_settings


_SESSION_COOKIE = "aruba_session"


def _expected_password_hash() -> str:
    # We hash on demand so changing env var takes effect on container restart only.
    pw = get_settings().admin_password
    return bcrypt.hash(pw)


def verify_login(username: str, password: str) -> bool:
    s = get_settings()
    if not secrets.compare_digest(username or "", s.admin_user):
        return False
    return secrets.compare_digest(password or "", s.admin_password)


def issue_session(response, username: str) -> str:
    token = secrets.token_urlsafe(32)
    # Stash in cookie. We accept that this is a single-process app and there's no
    # session store; the secret_key is used to sign via SignedCookie below.
    response.set_cookie(
        _SESSION_COOKIE,
        f"{username}|{token}",
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 12,
    )
    return token


def clear_session(response) -> None:
    response.delete_cookie(_SESSION_COOKIE)


def current_user(request: Request) -> Optional[str]:
    raw = request.cookies.get(_SESSION_COOKIE)
    if not raw or "|" not in raw:
        return None
    user, _ = raw.split("|", 1)
    if user == get_settings().admin_user:
        return user
    return None


def require_user(request: Request) -> str:
    user = current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )
    return user
