#!/usr/bin/env bash
# Install the gitleaks pre-commit secret scan into this clone's .git/hooks/.
# Run once per clone:  bash scripts/install-git-hooks.sh
# (Git hooks are per-clone and never committed, so each clone must install.)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/scripts/git-pre-commit-secret-scan.sh"
HOOKS_DIR="$(git -C "$ROOT" rev-parse --git-path hooks)"
DST="$HOOKS_DIR/pre-commit"

chmod +x "$SRC"
mkdir -p "$HOOKS_DIR"

if [ -e "$DST" ] && ! grep -q "git-pre-commit-secret-scan.sh" "$DST" 2>/dev/null; then
  cp "$DST" "$DST.pre-secretscan.bak"
  echo "Existing pre-commit hook backed up to $DST.pre-secretscan.bak"
fi

cat > "$DST" <<EOF
#!/usr/bin/env bash
# Installed by scripts/install-git-hooks.sh -- delegates to the tracked script
# so updates to the scan logic take effect without re-installing.
exec "$SRC" "\$@"
EOF
chmod +x "$DST"

echo "Installed gitleaks pre-commit secret scan -> $DST"
echo "Test it: stage a file containing a real-looking secret (e.g. a private-key"
echo "block or an AWS key) and run 'git commit' -- the hook should block it."
