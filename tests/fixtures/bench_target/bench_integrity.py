"""Shared SHA-256 integrity helper for benchmark fixtures (TEST-ONLY).

Each protected file has a sibling `<name>.sha256.lock`. verify() recomputes the file
hash and compares; update() is a maintainer-only action, never called by a test run.
"""
from __future__ import annotations

import hashlib
import os


def file_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def lock_path_for(path: str) -> str:
    return path + ".sha256.lock"


def read_lock(path: str) -> str | None:
    lp = lock_path_for(path)
    if not os.path.isfile(lp):
        return None
    with open(lp) as f:
        return f.read().strip()


def verify(path: str) -> tuple[bool, str]:
    actual = file_sha256(path)
    expected = read_lock(path)
    if expected is None:
        return False, f"integrity lock missing for {os.path.basename(path)}"
    if actual != expected:
        return False, f"INTEGRITY FAILURE {os.path.basename(path)}: {actual} != locked {expected}"
    return True, f"integrity OK {os.path.basename(path)} ({actual})"


def update(path: str) -> str:
    h = file_sha256(path)
    with open(lock_path_for(path), "w") as f:
        f.write(h + "\n")
    return h
