#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const codex = process.argv[2];
const output = process.argv[3];
if (process.platform !== "linux" || process.argv.length !== 4 ||
    !codex?.startsWith("/") || !output?.startsWith("/"))
  throw new Error("Usage: node scripts/verify-codex-rea-tool-roundtrip.mjs ABS_CODEX ABS_REPORT");

const sha256 = (input) => createHash("sha256").update(input).digest("hex");
const root = fileURLToPath(new URL("..", import.meta.url));
const serverEntrypoint = join(root, "scripts", "rea.mjs");
const lab = await mkdtemp(join(tmpdir(), "rea-codex-roundtrip-"));
const account = join(lab, "account");
const codexHome = join(lab, "codex");
const workspace = join(lab, "workspace");
const configPath = join(codexHome, "config.toml");
const callId = "rea_fixture_binary_session_001";
const requests = [];
let fixtureError;
let modelLoop;
let done = false;
let status = null;
const usage = {
  input_tokens: 18,
  input_tokens_details: { cached_tokens: 0 },
  output_tokens: 7,
  output_tokens_details: null,
  total_tokens: 25,
};
const modelServer = createServer(async (req, res) => {
  try {
    const endpoint = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
    if (req.method === "GET" && endpoint.endsWith("/models")) {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({
        object: "list", data: [{ id: "gpt-5.1-codex-mini", object: "model" }],
      }));
      return;
    }
    assert.equal(req.method, "POST");
    assert.equal(endpoint, "/v1/responses");
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      assert.ok(size <= 4 * 1024 * 1024, "Mock model request exceeded 4MiB");
      chunks.push(chunk);
    }
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    assert.ok(Array.isArray(body.input));
    assert.ok(Array.isArray(body.tools), "Codex omitted tool schemas");
    const names = body.tools.flatMap((tool) =>
      typeof tool?.name === "string" ? [tool.name] : []);
    const targetName = names.find((name) => name.endsWith("__binary_session"));
    assert.ok(targetName, "Codex did not advertise REA binary_session: " + JSON.stringify(names));
    const inputOutputs = body.input.filter((item) =>
      item?.type === "function_call_output" && item.call_id === callId);
    const round = requests.length + 1;
    assert.ok(round <= 2, "Codex exceeded the two-round fixture budget");
    const responseId = "resp-rea-codex-" + String(round);
    let item;
    if (round === 1) {
      assert.equal(inputOutputs.length, 0);
      item = {
        type: "function_call",
        call_id: callId,
        name: targetName,
        arguments: "{}",
      };
    } else {
      assert.equal(inputOutputs.length, 1, "Codex did not return MCP tool output to its model");
      assert.ok(String(inputOutputs[0].output).length > 15);
      item = {
        type: "message",
        role: "assistant",
        id: "msg-rea-finished",
        content: [{ type: "output_text", text: "REA_CODEX_MCP_ROUNDTRIP_OK" }],
      };
    }
    requests.push({
      round, tool_count: names.length, tool_name: targetName,
      has_function_call_output: inputOutputs.length > 0,
      actual_model: "deterministic_loopback_fixture",
      model_request_sha256: sha256(Buffer.concat(chunks)),
    });
    const events = [
      { type: "response.created", response: { id: responseId } },
      { type: "response.output_item.done", item },
      { type: "response.completed", response: { id: responseId, usage } },
    ];
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    });
    for (const event of events)
      res.write("event: " + event.type + "\ndata: " + JSON.stringify(event) + "\n\n");
    res.end();
  } catch (error) {
    fixtureError = String(error);
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { message: fixtureError, type: "invalid_request_error" } }));
  }
});
try {
  await Promise.all([
    mkdir(account, { mode: 0o700 }),
    mkdir(codexHome, { mode: 0o700 }),
    mkdir(workspace, { mode: 0o700 }),
  ]);
  await new Promise((resolve) => modelServer.listen(0, "127.0.0.1", resolve));
  const addr = modelServer.address();
  assert.ok(addr && typeof addr !== "string");
  const cfg = [
    'approval_policy = "never"',
    'sandbox_mode = "read-only"',
    'web_search = "disabled"',
    'model = "gpt-5.1-codex-mini"',
    'model_provider = "rea_fixture"',
    'model_reasoning_effort = "low"',
    '[model_providers.rea_fixture]',
    'name = "Isolated REA fixture"',
    'base_url = "http://127.0.0.1:' + addr.port + '/v1"',
    'env_key = "REA_FIXTURE_BEARER"',
    'wire_api = "responses"',
    'requires_openai_auth = false',
    'supports_websockets = false',
    'request_max_retries = 0',
    'stream_max_retries = 0',
    '[features]',
    'multi_agent = false',
    'shell_snapshot = false',
    'shell_tool = false',
    'unified_exec = false',
    'code_mode = false',
    '[history]',
    'persistence = "none"',
    '[mcp_servers.rea]',
    'command = ' + JSON.stringify(process.execPath),
    'args = ' + JSON.stringify([serverEntrypoint, "mcp"]),
    'enabled_tools = ["binary_session"]',
    'startup_timeout_sec = 30',
    'tool_timeout_sec = 60',
    '[mcp_servers.rea.env]',
    'REA_MCP_TOOL_FAMILIES = "session"',
    'REA_MCP_INPUT_SCHEMA_PROFILE = "compact"',
    'REA_LOG_LEVEL = "silent"',
    'HOPPER_LAUNCHER_PATH = "/rea-unconfigured-hopper/hopper"',
    '',
  ].join("\n");
  await writeFile(configPath, cfg, { flag: "wx", mode: 0o600 });
  const env = {
    HOME: account,
    CODEX_HOME: codexHome,
    XDG_CONFIG_HOME: join(account, ".config"),
    XDG_CACHE_HOME: join(account, ".cache"),
    XDG_DATA_HOME: join(account, ".local", "share"),
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    REA_FIXTURE_BEARER: "inert-fixture-value-only",
    RUST_LOG: "warn",
    CI: "true",
  };
  const args = [
    "exec", "--strict-config", "--ephemeral", "--skip-git-repo-check",
    "--ignore-rules", "--json", "--color", "never", "-C", workspace, "-",
  ];
  const proc = spawn(codex, args, {
    env, cwd: workspace, stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  proc.stdout.setEncoding("utf8");
  proc.stderr.setEncoding("utf8");
  proc.stdout.on("data", (data) => {
    stdout += data;
    if (stdout.length > 8 * 1024 * 1024) proc.kill("SIGKILL");
  });
  proc.stderr.on("data", (data) => {
    stderr = (stderr + data.toString()).slice(-65536);
  });
  proc.stdin.end(
    "Call only the REA MCP binary_session tool and report the observed session status. " +
    "Do not open any target, execute files, use the shell, or invoke other tools.\n",
  );
  const result = await Promise.race([
    new Promise((resolve, reject) => {
      proc.once("error", reject);
      proc.once("close", (code, signal) => resolve({ code, signal }));
    }),
    new Promise((_, reject) => {
      setTimeout(() => {
        proc.kill("SIGKILL");
        reject(new Error("Isolated Codex tool roundtrip timed out after 65 seconds"));
      }, 65000).unref();
    }),
  ]);
  const events = stdout.split("\n").filter(Boolean).flatMap((line) => {
    try { return [JSON.parse(line)]; } catch { return []; }
  });
  const completed = events.filter((evt) =>
    evt.type === "item.completed" &&
    evt.item?.type === "mcp_tool_call" &&
    evt.item?.server === "rea" &&
    evt.item?.tool === "binary_session");
  assert.equal(result.code, 0, "Codex exit " + JSON.stringify(result) + ": " + stderr.slice(-3000));
  assert.equal(fixtureError, undefined, "Loopback fixture error");
  assert.equal(requests.length, 2);
  assert.ok(completed.length >= 1, "Codex did not complete MCP tool roundtrip");
  assert.equal(completed.at(-1).item.status, "completed");
  assert.ok(stdout.includes("REA_CODEX_MCP_ROUNDTRIP_OK"), "Codex final scripted answer missing");
  status = {
    status: "passed",
    codex_cli: "0.163.0",
    source: "REA production MCP server with isolated Codex CLI 0.163.0",
    real_codex_tool_invocations: completed.length,
    called_tool: "binary_session",
    actual_llm_called: false,
    scripted_model_roundtrips: requests.length,
    tool_output_present_in_next_response: requests[1].has_function_call_output,
    request_fingerprints: requests,
    isolated_config_digest: sha256(cfg),
    user_settings_changed: false,
    model_billing: "none",
    limitations: [
      "The scripted mock chooses binary_session; no autonomous tool selection is measured.",
      "No live Ghidra target or PSP game binary is opened.",
      "This verifies Codex harness tool dispatch, not model-quality or token economy.",
    ],
  };
} catch (error) {
  status = {
    status: "blocked",
    error: String(error),
    fixture_error: fixtureError ?? null,
    rounds_completed: requests.length,
    first_request_tool_names: [],
    user_settings_changed: false,
  };
  process.exitCode = 1;
} finally {
  await new Promise((resolve) => modelServer.close(resolve));
  await rm(lab, { recursive: true, force: true });
}
await writeFile(output, JSON.stringify(status, null, 2) + "\n", {
  mode: 0o600, flag: "wx",
});
process.stdout.write(JSON.stringify(status, null, 2) + "\n");
