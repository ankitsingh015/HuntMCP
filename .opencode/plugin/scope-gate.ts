// OpenCode port of scripts/hooks/scope_gate_hook.py's Claude Code
// PreToolUse hook. Reuses that script directly rather than reimplementing
// scope/budget/audit logic in TypeScript, so there is exactly one source of
// truth for the enforcement logic and both harnesses inherit any future fix
// to scope_guard.py/budget_guard.py/audit_log.py for free.
//
// Before this file, OpenCode had ZERO scope enforcement for any raw Bash
// Tier-2 command (curl/wget/nmap/nuclei/subfinder/httpx/katana/sqlmap/
// dalfox/ffuf) -- opencode.jsonc's `permission.bash` is a static ask/allow
// glob-pattern block, it cannot inspect a command's actual target host.
// scope_gate_hook.py already existed on the Claude Code side and was
// recently hardened to also catch raw curl/wget (see its own module
// docstring); this plugin closes the same gap on OpenCode by wiring
// OpenCode's `tool.execute.before` hook (the documented, currently-shipping
// equivalent of Claude Code's PreToolUse -- confirmed via
// @opencode-ai/plugin's shipped type definitions and opencode.ai/docs/
// plugins, which shows blocking-by-throwing as the supported pattern) to
// invoke the exact same Python script over the exact same stdin JSON
// contract Claude Code already uses.
//
// Also covers MCP-server-provided tools (subfinder-mcp, httpx-mcp,
// nuclei-mcp, etc., called as native OpenCode tools rather than raw Bash) --
// closed 2026-08-26 after confirming, empirically against this exact repo
// (not guessed), how OpenCode names them. A live `opencode run` against
// huntbrain, told to call a real MCP tool directly, produced this runtime
// validation error: `Model tried to call unavailable tool
// 'case-mcp:case_summary'` -- OpenCode names MCP tools `<server>:<tool>`
// (colon-separated), a different convention from Claude Code's
// `mcp__<server>__<tool>` (double-underscore). Translated into that
// existing double-underscore contract below so scope_gate_hook.py's
// already-working `mcp__` branch (TIER2_MCP_SERVERS check,
// _extract_hosts_from_tool_input) handles both harnesses identically with
// zero Python-side changes.
import type { Plugin } from "@opencode-ai/plugin"

export const ScopeGate: Plugin = async ({ directory }) => {
  return {
    "tool.execute.before": async (input, output) => {
      let payload

      if (input.tool === "bash") {
        const command = output.args?.command
        if (typeof command !== "string" || !command.trim()) return
        payload = JSON.stringify({ tool_name: "Bash", tool_input: { command } })
      } else if (input.tool.includes(":")) {
        const sepIndex = input.tool.indexOf(":")
        const server = input.tool.slice(0, sepIndex)
        const toolName = input.tool.slice(sepIndex + 1)
        payload = JSON.stringify({
          tool_name: `mcp__${server}__${toolName}`,
          tool_input: output.args || {},
        })
      } else {
        return
      }

      // Fail open on anything other than an explicit block (exit 2) --
      // matches scope_gate_hook.py's own "never break the session over a
      // hook-side problem" posture (e.g. malformed input, a Python
      // environment issue) rather than turning an unrelated failure into a
      // blocked tool call. This means the spawn/communicate step itself
      // must be inside the try: Bun.spawn throws synchronously if `python3`
      // isn't on PATH, and an uncaught throw inside this async hook is
      // itself treated as a block by OpenCode's plugin contract -- without
      // this try/catch, a missing/broken Python environment would fail
      // *closed* (block every bash command) instead of open, the opposite
      // of the documented and intended behavior.
      let exitCode
      let stderr
      try {
        const proc = Bun.spawn(
          ["python3", `${directory}/scripts/hooks/scope_gate_hook.py`],
          { stdin: "pipe", stdout: "pipe", stderr: "pipe" },
        )
        proc.stdin.write(payload)
        proc.stdin.end()
        ;[exitCode, stderr] = await Promise.all([
          proc.exited,
          new Response(proc.stderr).text(),
        ])
      } catch {
        return
      }

      if (exitCode === 2) {
        throw new Error(stderr.trim() || "Blocked by scope gate")
      }
    },
  }
}
