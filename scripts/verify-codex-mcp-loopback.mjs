#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createVerifierRun,
  completeVerifierRun,
  assertVerifierCleanupComplete,
} from "./lib/verifier-run.mjs";

const cli = process.argv[2];
const reportFile = process.argv[3];
if (process.platform !== "linux" || process.argv.length !== 4 ||
    !cli?.startsWith("/") || !reportFile?.startsWith("/"))
  throw new Error("Usage: node scripts/verify-codex-mcp-loopback.mjs ABS_CODEX_BIN ABS_REPORT.json");

const sha = (input) => createHash("sha256").update(input).digest("hex");
const run = createVerifierRun();
const scratch = await mkdtemp(join(tmpdir(), "rea-codex-loopback-"));
const codexHome = join(scratch, "codex-home");
const home = join(scratch, "account");
const serverScript = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const events = [];
const modelRequests = [];
let serverFailure;
let transcript = "";
let cliStderr = "";
const fixture = createServer(async (req, res) => {
  try {
    const path = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
    if (req.method === "GET" && path === "/v1/models") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ object: "list", data: [
        { id: "rea-loopback", object: "model", owned_by: "local-synthetic-fixture" },
      ] }));
      return;
    }
    if (req.method !== "POST" || path !== "/v1/responses") {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "Local fixture only implements Responses API" }));
      return;
    }
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
      total += chunk.length;
      assert.ok(total < 4 * 1024 * 1024, "Unbounded model request");
      chunks.push(chunk);
    }
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const index = modelRequests.length + 1;
    assert.ok(index <= 2, "Unexpected additional synthetic model requests");
    const names = Array.isArray(body.tools)
      ? body.tools.map((t) => t.name ?? t.function?.name).filter(Boolean)
      : [];
    modelRequests.push({
      turn: index,
      requested_model: body.model,
      advertised_tools: names,
      request_sha256: sha(JSON.stringify(body)),
    });
    const responseId = "resp-rea-loopback-" + index;
    const outputs = [];
    if (index === 1) {
      assert.ok(names.includes("mcp__rea__binary_session"),
        "The real Codex model request omitted REA binary_session");
      outputs.push({
        type: "response.output_item.done",
        item: {
          type: "function_call",
          call_id: "call_rea_binary_session_1",
          name: "mcp__rea__binary_session",
          arguments: "{}",
        },
      });
    } else {
      const prior = JSON.stringify(body.input ?? []);
      assert.ok(prior.includes("call_rea_binary_session_1"),
        "Codex did not return the preceding MCP result to the synthetic model");
      assert.ok(prior.includes("open"),
        "The synthetic model did not receive binary_session's open-state result");
      outputs.push({
        type: "response.output_item.done",
        item: {
          type: "message",
          role: "assistant",
          id: "msg-rea-loopback",
          content: [{ type: "output_text",
            text: "REA's binary_session tool confirms that no binary is currently open." }],
        },
      });
    }
    const all = [
      { type: "response.created", response: { id: responseId } },
      ...outputs,
      { type: "response.completed", response: { id: responseId,
        usage: { input_tokens: 0, input_tokens_details: null,
          output_tokens: 0, output_tokens_details: null, total_tokens: 0 } } },
    ];
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "close",
    });
    res.end(all.map((event) =>
      "event: " + event.type + "\ndata: " + JSON.stringify(event) + "\n\n"
    ).join(""));
  } catch (error) {
    serverFailure = String(error);
    res.statusCode = 400;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ error: { message: serverFailure, type: "invalid_request_error" } }));
  }
});
await new Promise((resolve) => fixture.listen(0, "127.0.0.1", resolve));
const address = fixture.address();
assert.ok(address && typeof address !== "string");
let finalReport;
try {
  await mkdir(codexHome, { mode: 0o700 });
  await mkdir(home, { mode: 0o700 });
  const configuration = [
    'model = "rea-loopback"',
    'model_provider = "rea_fixture"',
    'approval_policy = "never"',
    'sandbox_mode = "read-only"',
    'web_search = "disabled"',
    'suppress_unstable_features_warning = true',
    '[features]',
    'multi_agent = false',
    'shell_snapshot = false',
    'shell_tool = false',
    'unified_exec = false',
    'code_mode = false',
    'code_mode_only = false',
    '[mcp_servers.rea]',
    'command = ' + JSON.stringify(process.execPath),
    'args = ' + JSON.stringify([serverScript, "mcp"]),
    'enabled_tools = ["binary_session"]',
    'startup_timeout_sec = 30',
    'tool_timeout_sec = 120',
    '[mcp_servers.rea.env]',
    'REA_MCP_TOOL_FAMILIES = "session"',
    'REA_MCP_INPUT_SCHEMA_PROFILE = "compact"',
    'REA_LOG_LEVEL = "silent"',
    'HOPPER_LAUNCHER_PATH = "/rea-nonexistent-hopper/hopper"',
    '[model_providers.rea_fixture]',
    'name = "Local deterministic Responses fixture"',
    'base_url = ' + JSON.stringify("http://127.0.0.1:" + address.port + "/v1"),
    'wire_api = "responses"',
    'requires_openai_auth = false',
    'request_max_retries = 0',
    'stream_max_retries = 0',
    "",
  ].join("\n");
  await writeFile(join(codexHome, "config.toml"), configuration, {
    mode: 0o600, flag: "wx",
  });
  const env = {
    ...process.env,
    CODEX_HOME: codexHome,
    HOME: home,
    XDG_CONFIG_HOME: join(home, ".config"),
    REA_PROCESS_RUN_ID: run.run_id,
    NO_PROXY: "127.0.0.1,localhost",
    no_proxy: "127.0.0.1,localhost",
  };
  for (const name of ["OPENAI_API_KEY", "CODEX_API_KEY",
    "CHATGPT_SESSION_TOKEN", "OPENAI_BASE_URL", "AZURE_OPENAI_API_KEY"])
    delete env[name];
  const outputFile = join(scratch, "answer.txt");
  const args = [
    "--no-daemon", "exec", "--strict-config", "--ephemeral",
    "--skip-git-repo-check", "--ignore-rules", "--json", "--color", "never",
    "-C", scratch, "--output-last-message", outputFile, "-",
  ];
  const child = spawn(cli, args, {
    cwd: scratch, env, stdio: ["pipe", "pipe", "pipe"],
  });
  child.stdin.end(
    "Call REA binary_session exactly once and report whether a binary is open. " +
    "Do not use any other tools or access files.\n",
  );
  const bounded = (previous, bytes) => {
    const next = previous + bytes.toString("utf8");
    assert.ok(next.length < 4 * 1024 * 1024, "Unbounded Codex transcript");
    return next;
  };
  child.stdout.on("data", (chunk) => { transcript = bounded(transcript, chunk); });
  child.stderr.on("data", (chunk) => { cliStderr = bounded(cliStderr, chunk); });
  let timedOut = false;
  const deadline = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, 110000);
  let exit;
  try {
    exit = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
  } finally {
    clearTimeout(deadline);
  }
  assert.equal(timedOut, false, "Codex loopback tool routing timed out");
  assert.equal(exit.code, 0,
    "Codex fixture failed: " + cliStderr.slice(-4500) + " / " +
    transcript.slice(-3500) + " / " + (serverFailure ?? ""));
  assert.equal(serverFailure, undefined, "Mock Responses API error");
  assert.equal(modelRequests.length, 2, "Codex did not perform the expected two model turns");
  const parsed = transcript.split("\n").filter(Boolean).map(JSON.parse);
  const mcpCalls = parsed.filter((item) =>
    item.type === "item.completed" &&
    item.item?.type === "mcp_tool_call");
  assert.ok(mcpCalls.some((item) =>
    item.item.tool === "mcp__rea__binary_session" &&
    item.item.status === "completed"),
    "Codex transcript did not contain an authenticated completed REA MCP tool call");
  assert.equal(mcpCalls.filter((item) =>
    item.item.tool === "mcp__rea__binary_session").length, 1);
  const answer = await readFile(outputFile, "utf8");
  assert.match(answer, /no binary is currently open/iu);
  finalReport = {
    status: "passed",
    fixture: "local synthetic Responses API, no real language model",
    real_codex_executable: true,
    real_codex_mcp_call: true,
    real_rea_stdio_server: true,
    model_calls_to_loopback_fixture: modelRequests.length,
    paid_model_calls: 0,
    actual_model_reasoning_quality_measured: false,
    effective_billed_model_tokens: null,
    response_usage_fields_are_synthetic: true,
    mcp_calls: mcpCalls.map((item) => ({
      tool: item.item.tool,
      status: item.item.status,
    })),
    codex_config_sha256: sha(configuration),
    codex_home_isolated: true,
    user_codex_configuration_modified: false,
    result_contains_expected_no_open_binary: true,
    cleanup: "pending",
    caveat: "Local scripted model tool selection proves Codex wire/tool routing, not autonomous model behavior.",
  };
} catch (error) {
  console.error(JSON.stringify({
    error: String(error),
    mock_error: serverFailure ?? null,
    requests: modelRequests.map(({ turn, advertised_tools }) => ({
      turn, advertised_tools: advertised_tools.slice(0, 25),
    })),
    codex_stderr_tail: cliStderr.slice(-1500),
    codex_stdout_tail: transcript.slice(-2200),
  }));
  throw error;
} finally {
  await new Promise((resolve) => fixture.close(resolve));
  await rm(scratch, { recursive: true, force: true });
}
const completed = await completeVerifierRun(run);
assertVerifierCleanupComplete(completed.process_lineage);
assert.ok(finalReport);
finalReport.cleanup = "complete";
await writeFile(reportFile, JSON.stringify(finalReport, null, 2) + "\n", {
  flag: "wx", mode: 0o600,
});
process.stdout.write(JSON.stringify(finalReport, null, 2) + "\n");
