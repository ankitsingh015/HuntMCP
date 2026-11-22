"""Session keep-alive scheduler + health report for captured identities.

Runs inside the browser-mcp process (a daemon thread per engagement): each
identity is refreshed ~5 min before its earliest access-token expiry, and
otherwise visited every `interval_s` (default 2 h, min 30 min, +-10% jitter)
so a sliding SSO session stays alive. Survives only while browser-mcp runs.

Design: docs/superpowers/specs/2026-11-20-session-keepalive-design.md (§5).
Everything returned is non-secret (session_refresh.ALLOWED_SUMMARY_KEYS).
"""

from __future__ import annotations

import asyncio
import random
import threading
import time

import session_capture
import session_refresh as R

DEFAULT_INTERVAL_S = 7200
MIN_INTERVAL_S = 1800
REFRESH_BEFORE_EXP_S = 300
AFTER_EXP_S = 5
WARN_BEFORE_S = 48 * 3600
_JITTER = 0.10


def _now() -> float:
    return time.time()


class KeepAlive:
    def __init__(self, labels, slug, refresh_fn, interval_s: int = DEFAULT_INTERVAL_S,
                 now_fn=time.time, rand_fn=random.random):
        self.labels = list(labels)
        self.slug = slug
        self.refresh_fn = refresh_fn
        self.interval_s = max(int(interval_s), MIN_INTERVAL_S)
        self.now_fn = now_fn
        self.rand_fn = rand_fn
        self._running: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._jitter: dict[str, float] = {}

    def _jittered_interval(self, label: str) -> float:
        if label not in self._jitter:
            self._jitter[label] = self.interval_s * (1 - _JITTER + 2 * _JITTER * self.rand_fn())
        return self._jitter[label]

    def _waiting_for_human(self, label: str, st: dict) -> bool:
        if not st.get("needs_human_login"):
            return False
        captured_at = float((R._load_identity(label) or {}).get("captured_at") or 0)
        return captured_at <= float(st.get("last_attempt") or 0)

    def next_due(self, label: str) -> float:
        st = R._load_refresh_state(label)
        last = st.get("last_refresh")
        if not last:
            return self.now_fn()
        due = float(last) + self._jittered_interval(label)
        exp = st.get("access_exp")
        if exp:
            exp_due = float(exp) - REFRESH_BEFORE_EXP_S
            if float(last) >= exp_due:
                # already refreshed inside the pre-expiry window and the app kept
                # its still-valid token: wait for the expiry itself instead of
                # re-refreshing every loop until then
                exp_due = float(exp) + AFTER_EXP_S
            due = min(due, exp_due)
        return due

    def tick(self) -> list[str]:
        done = []
        for label in self.labels:
            if label in self._running or self._stop.is_set():
                continue
            st = R._load_refresh_state(label)
            if self._waiting_for_human(label, st):
                continue
            if self.next_due(label) > self.now_fn():
                continue
            self._running.add(label)
            try:
                asyncio.run(self.refresh_fn(label, self.slug))
                done.append(label)
                self._jitter.pop(label, None)
            except Exception:  # noqa: BLE001 -- one identity's failure never stops the loop
                pass
            finally:
                self._running.discard(label)
        return done

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.tick()
            dues = [self.next_due(lb) for lb in self.labels
                    if not self._waiting_for_human(lb, R._load_refresh_state(lb))]
            wait = min(dues) - self.now_fn() if dues else 600
            self._stop.wait(min(max(wait, 30), 600))

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="huntmcp-keepalive", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


_keepalives: dict[str, KeepAlive] = {}
_registry_lock = threading.Lock()


def start_keepalive(labels: list[str], interval_s: int = DEFAULT_INTERVAL_S, slug: str | None = None) -> dict:
    slug = session_capture._slug(slug)
    for label in labels or []:
        try:
            session_capture._safe_label(label)
            session_capture.roster_entry(label)
        except (ValueError, KeyError):
            return {"error": f"invalid or unknown identity label {label!r}"}
    if not labels:
        return {"error": "no identity labels given"}
    ka = KeepAlive(labels, slug, R.refresh_session, interval_s=interval_s)
    with _registry_lock:
        old = _keepalives.pop(slug, None)
        if old:
            old.stop()
        _keepalives[slug] = ka
    ka.start()
    return {"status": "running", "message": f"keep-alive for {len(labels)} identit"
                                            f"{'y' if len(labels) == 1 else 'ies'}, every ~{ka.interval_s // 60} min"}


def stop_keepalive(slug: str | None = None) -> dict:
    slug = session_capture._slug(slug)
    with _registry_lock:
        ka = _keepalives.pop(slug, None)
    if not ka:
        return {"status": "not_running"}
    ka.stop()
    return {"status": "stopped"}


def _iso(ts: float | None) -> str | None:
    return time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime(ts)) if ts else None


def session_health(labels: list[str] | None = None, slug: str | None = None) -> dict:
    if not labels:
        labels = [i["label"] for i in session_capture.list_identities()]
    now = _now()
    rows = []
    for label in labels:
        try:
            session_capture._safe_label(label)
        except ValueError as e:
            rows.append(R._summary("invalid", error=str(e)))
            continue
        st = R._load_refresh_state(label)
        estimates = [float(x) for x in (st.get("sso_expiry"), st.get("rt_expiry")) if x]
        human_at = max(estimates) if estimates else None
        warning = None
        if human_at and human_at - now < WARN_BEFORE_S:
            warning = f"manual login likely needed within {max(int((human_at - now) // 3600), 0)} h"
            if st.get("warned_day") != R._today():
                R.notify("HuntMCP: login expiring soon", f"{label}: {warning}")
                st["warned_day"] = R._today()
                R._save_refresh_state(label, st)
        exp = st.get("access_exp")
        rows.append(R._summary(
            label, status="needs_human_login" if st.get("needs_human_login") else "ok",
            last_refresh=_iso(st.get("last_refresh")), layer=st.get("last_layer"),
            access_expires_in_s=int(float(exp) - now) if exp else None,
            estimated_next_human_login=_iso(human_at), warning=warning,
            needs_human_login=bool(st.get("needs_human_login")),
            reason=st.get("last_reason")))
    running = session_capture._slug(slug) in _keepalives
    return {"keepalive_running": running, "identities": rows}
