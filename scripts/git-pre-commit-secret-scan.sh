#!/usr/bin/env bash
# Pre-commit secret scan (gitleaks) -- the real guard that .gitignore cannot be:
# it scans the STAGED CONTENT of a commit (not just filenames) and blocks the
# commit if a secret is found, including a key pasted into an otherwise-normal
# source file. Install it with scripts/install-git-hooks.sh.
#
# Fail-closed on purpose: if gitleaks is missing, the commit is blocked (this is
# a security repo). Install gitleaks, or -- only when you are certain -- bypass a
# single commit with `git commit --no-verify`.
set -euo pipefail

GITLEAKS="$(command -v gitleaks || true)"
if [ -z "$GITLEAKS" ] && [ -x "$HOME/go/bin/gitleaks" ]; then
  GITLEAKS="$HOME/go/bin/gitleaks"
fi
if [ -z "$GITLEAKS" ]; then
  echo "pre-commit: gitleaks not found. Install it:" >&2
  echo "    go install github.com/gitleaks/gitleaks/v8@latest" >&2
  echo "  (or bypass this one commit with: git commit --no-verify)" >&2
  exit 1
fi

if "$GITLEAKS" protect --staged --redact --no-banner; then
  exit 0
fi

echo "" >&2
echo "pre-commit: BLOCKED -- gitleaks found a potential secret in your staged changes" >&2
echo "(value redacted above). Remove it and re-stage. If it is a genuine false" >&2
echo "positive, mark the line with '# gitleaks:allow' or add a rule to .gitleaks.toml." >&2
exit 1
