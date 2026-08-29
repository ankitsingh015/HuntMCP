// Functional test for .opencode/plugin/scope-gate.ts -- the OpenCode port
// of scripts/hooks/scope_gate_hook.py's Claude Code PreToolUse hook.
//
// No `bun` binary is assumed to be on PATH (OpenCode bundles its own Bun
// runtime internally; a bare dev/CI box may not have a standalone one), so
// this shims the one Bun API the plugin uses (`Bun.spawn`) with
// node:child_process and runs under plain `node`. This exercises the real
// plugin code against the real scope_gate_hook.py end to end -- only
// Bun.spawn's transport is mocked, not the hook's own logic.
//
// Run: node tests/test_scope_gate_plugin.mjs
import { spawn as nodeSpawn, execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { writeFile, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

globalThis.Bun = {
  spawn(args) {
    const child = nodeSpawn(args[0], args.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
    const stderrChunks = [];
    child.stderr.on("data", (d) => stderrChunks.push(d));
    const exited = new Promise((resolve) => child.on("close", (code) => resolve(code)));
    return {
      stdin: { write: (s) => child.stdin.write(s), end: () => child.stdin.end() },
      stderr: {
        [Symbol.asyncIterator]: async function* () {
          await exited;
          yield Buffer.concat(stderrChunks);
        },
      },
      exited,
    };
  },
};

globalThis.Response = class {
  constructor(streamLike) {
    this._streamLike = streamLike;
  }
  async text() {
    let out = "";
    for await (const chunk of this._streamLike) out += chunk.toString();
    return out;
  }
};

async function loadPlugin() {
  // Strip the type-only import and inline type annotation -- Node can't
  // resolve @opencode-ai/plugin (a types-only concern here) and carries no
  // runtime code from it.
  const src = readFileSync(path.join(REPO_ROOT, ".opencode/plugin/scope-gate.ts"), "utf8")
    .replace(/^import type.*$/m, "")
    .replace(/:\s*Plugin\s*=/, " =");
  const tmpModule = path.join(REPO_ROOT, "tests", ".scope-gate.tmp.mjs");
  await writeFile(tmpModule, src);
  try {
    return await import(`${tmpModule}?t=${Date.now()}`);
  } finally {
    await rm(tmpModule, { force: true });
  }
}

async function run(ScopeGate, command, cwd) {
  return runTool(ScopeGate, "bash", { command }, cwd);
}

async function runTool(ScopeGate, tool, args, cwd) {
  const hooks = await ScopeGate({ directory: REPO_ROOT });
  const before = hooks["tool.execute.before"];
  const originalCwd = process.cwd();
  if (cwd) process.chdir(cwd);
  try {
    await before({ tool, sessionID: "s1", callID: "c1" }, { args });
    return { blocked: false };
  } catch (e) {
    return { blocked: true, message: e.message };
  } finally {
    if (cwd) process.chdir(originalCwd);
  }
}

async function main() {
  const { ScopeGate } = await loadPlugin();
  const tmp = execSync("mktemp -d").toString().trim();
  // audit_log.py's no-active-engagement fallback path is anchored to
  // __file__, not cwd (unlike budget_guard.py's bare "budget.json"), so it
  // survives the subprocess's cwd change below -- without these overrides,
  // every "in-scope" case here would append a real line to the repo's own
  // data/audit.jsonl on each test run. Set before spawning; child_process
  // inherits process.env by default.
  process.env.HUNTMCP_AUDIT_LOG = path.join(tmp, "audit.jsonl");
  process.env.HUNTMCP_BUDGET_PATH = path.join(tmp, "budget.json");
  let allPass;
  try {
    execSync(
      `cat > '${tmp}/engagement.yaml' <<'EOF'\ntarget: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\nEOF`,
      { shell: "/bin/bash" },
    );

    const cases = [
      { label: "in-scope curl is allowed", command: "curl https://realtarget-corp.com/api", expectBlocked: false },
      { label: "out-of-scope curl is blocked", command: "curl https://someothersite.com/api", expectBlocked: true },
      { label: "non-tier2 command ignored", command: "git status", expectBlocked: false },
      { label: "non-bash tool call ignored", tool: "read", expectBlocked: false },
      {
        // OpenCode names MCP-provided tools "<server>:<tool>" (colon-
        // separated, confirmed empirically via a live "Invalid Tool"
        // runtime error against this exact repo -- see scope-gate.ts's own
        // comment). This regression covers the translation into
        // scope_gate_hook.py's existing mcp__<server>__<tool> contract.
        label: "in-scope Tier-2 MCP tool call is allowed",
        tool: "httpx-mcp:probe_hosts",
        args: { domains: "realtarget-corp.com" },
        expectBlocked: false,
      },
      {
        label: "out-of-scope Tier-2 MCP tool call is blocked",
        tool: "httpx-mcp:probe_hosts",
        args: { domains: "someothersite.com" },
        expectBlocked: true,
      },
      {
        label: "non-tier2 MCP server exempt (writeup-mcp is knowledge-layer)",
        tool: "writeup-mcp:fetch_cves",
        args: { keyword: "apache" },
        expectBlocked: false,
      },
      {
        // webfetch is deliberately NOT forwarded to scope_gate_hook.py at
        // all (see scope-gate.ts's own comment) -- it's not in the
        // `input.tool === "bash"` / `.includes(":")` branches, so this
        // exercises the plugin's own pass-through (the `else { return }`
        // branch), not a Python-side allow decision.
        label: "webfetch to an out-of-scope-looking host is never gated",
        tool: "webfetch",
        args: { url: "https://someothersite.com/docs" },
        expectBlocked: false,
      },
      {
        // No HOST_ARG_KEYS-matching argument -> candidates stays empty ->
        // scope_gate_hook.py's early-return at line ~212 -- must pass
        // through unblocked, not fail loud on a Tier-2 server with no
        // host-bearing arg in this particular call.
        label: "Tier-2 MCP tool call with no host-bearing arg passes through",
        tool: "nuclei-mcp:list_templates",
        args: { severity: "critical" },
        expectBlocked: false,
      },
    ];

    // Regression: Bun.spawn throws synchronously when the target binary
    // isn't found (e.g. no `python3` on PATH) -- an uncaught throw inside
    // this async hook is itself treated as a block by OpenCode's plugin
    // contract, which would fail *closed* (block every bash command) on a
    // broken Python environment instead of the documented fail-open
    // behavior. Swap Bun.spawn to simulate that failure mode directly,
    // since Node's child_process.spawn reports a missing binary via an
    // async 'error' event rather than a synchronous throw, so it can't
    // reproduce Bun's real behavior on its own.
    const realBunSpawn = globalThis.Bun.spawn;
    globalThis.Bun.spawn = () => {
      throw new Error("spawn python3 ENOENT");
    };
    let failOpenOk = false;
    try {
      const hooks = await ScopeGate({ directory: REPO_ROOT });
      await hooks["tool.execute.before"](
        { tool: "bash", sessionID: "s1", callID: "c1" },
        { args: { command: "curl https://realtarget-corp.com/api" } },
      );
      failOpenOk = true; // did not throw -- correctly failed open
    } catch (e) {
      failOpenOk = false;
    } finally {
      globalThis.Bun.spawn = realBunSpawn;
    }
    console.log(`${failOpenOk ? "PASS" : "FAIL"} :: fails open when python3/spawn is broken`);

    allPass = failOpenOk;
    for (const c of cases) {
      let result;
      if (c.tool && c.args) {
        result = await runTool(ScopeGate, c.tool, c.args, tmp);
      } else if (c.tool) {
        result = await runTool(ScopeGate, c.tool, {});
      } else {
        result = await run(ScopeGate, c.command, tmp);
      }
      const ok = result.blocked === c.expectBlocked;
      allPass = allPass && ok;
      console.log(`${ok ? "PASS" : "FAIL"} :: ${c.label}` + (result.blocked ? ` :: ${result.message}` : ""));
    }
  } finally {
    delete process.env.HUNTMCP_AUDIT_LOG;
    delete process.env.HUNTMCP_BUDGET_PATH;
    execSync(`rm -rf '${tmp}'`);
  }
  process.exit(allPass ? 0 : 1);
}

main();
