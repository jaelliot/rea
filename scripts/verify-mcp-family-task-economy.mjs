#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, copyFile, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { estimateTokenCount } from "tokenx";
import { parseEvidence } from "../dist/domain/evidence.js";
import { TOOL_CONTRACTS } from "../dist/contracts/toolContracts.js";
import { toolFamilyId } from "../dist/contracts/toolFamilies.js";
import {
  createVerifierRun,
  completeVerifierRun,
  assertVerifierCleanupComplete,
} from "./lib/verifier-run.mjs";

const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const byteCount = (value) => Buffer.byteLength(JSON.stringify(value));
const approxTokens = (value) => estimateTokenCount(JSON.stringify(value));
const ENTRY = "0x140001000";
const ROOT = fileURLToPath(new URL("..", import.meta.url));
const fixtureBuilder = join(ROOT, "scripts", "create-ghidra-windows-fixture.mjs");
const output = process.argv[2];

if (process.platform !== "linux" || process.argv.length !== 3 || !output?.startsWith("/"))
  throw new Error("Usage: node scripts/verify-mcp-family-task-economy.mjs ABS_OUTPUT.json (Linux)");
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error("Bring an existing Ghidra with GHIDRA_INSTALL_DIR; no tool installation here.");

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea3026-task-"));
const runtimeDir = join(workspace, "runtime");
const target = join(workspace, "Fixture.exe");
const cases = [
  { id: "full-A", scope: null, schema: "full" },
  { id: "scoped-A", scope: "session,direct", schema: "full" },
  { id: "compact-A", scope: "session,direct", schema: "compact" },
  { id: "compact-B", scope: "session,direct", schema: "compact" },
  { id: "scoped-B", scope: "session,direct", schema: "full" },
  { id: "full-B", scope: null, schema: "full" },
];
const results = [];
const failures = [];
const expectedAllNames = TOOL_CONTRACTS.map(({ name }) => name).sort();
const expectedScopedNames = TOOL_CONTRACTS
  .filter(({ name }) => ["session", "direct"].includes(toolFamilyId(name)))
  .map(({ name }) => name).sort();
let sourceSha = null;

try {
  await mkdir(runtimeDir);
  await promisify(execFile)(process.execPath, [fixtureBuilder]);
  await copyFile(join(ROOT, "build", "fixtures", "rea-ghidra-windows.exe"), target);
  sourceSha = sha256(await readFile(target));

  for (const test of cases) {
    const record = { id: test.id, scope: test.scope, schema: test.schema };
    let client;
    let transport;
    let opened = false;
    const began = performance.now();
    try {
      const environment = { ...process.env };
      delete environment.REA_MCP_TOOL_FAMILIES;
      delete environment.REA_MCP_INPUT_SCHEMA_PROFILE;
      delete environment.REA_GHIDRA_EXISTING_PROJECT;
      delete environment.REA_GHIDRA_EXISTING_PROGRAM;
      environment.REA_ANALYSIS_PROVIDER = "ghidra";
      environment.REA_LOG_LEVEL = "silent";
      environment.REA_PROCESS_RUN_ID = run.run_id;
      environment.TMPDIR = runtimeDir;
      environment.HOPPER_LAUNCHER_PATH = "/rea-unconfigured-deep-provider/hopper";
      if (test.scope !== null) environment.REA_MCP_TOOL_FAMILIES = test.scope;
      if (test.schema === "compact") environment.REA_MCP_INPUT_SCHEMA_PROFILE = "compact";

      transport = new StdioClientTransport({
        command: process.execPath,
        args: [join(ROOT, "scripts", "rea.mjs"), "mcp"],
        env: environment,
        stderr: "pipe",
      });
      client = new Client({ name: "rea3026-task-efficiency", version: "1" });
      await client.connect(transport);
      const advertised = (await client.listTools()).tools;
      const names = advertised.map(({ name }) => name).sort();
      assert.deepEqual(
        names, test.scope === null ? expectedAllNames : expectedScopedNames,
        "The live tools/list must match the selected published family inventory",
      );
      for (const needed of ["open_binary", "list_procedures", "procedure_pseudo_code", "close_binary"])
        assert.ok(names.includes(needed), "Analyst task tool missing from selected scope: " + needed);
      record.catalog = {
        tool_count: advertised.length,
        schema_json_utf8_bytes: byteCount(advertised),
        estimated_tokenx_tokens: approxTokens(advertised),
        names_sha256: sha256(JSON.stringify(names)),
      };

      const calls = [];
      const call = async (name, args) => {
        const started = performance.now();
        const reply = await client.callTool(
          { name, arguments: args },
          { timeout: 600000 },
        );
        calls.push({
          name,
          duration_ms: Math.round(performance.now() - started),
          request_response_utf8_bytes: byteCount({ name, arguments: args, reply }),
          estimated_tokenx_tokens: approxTokens({ name, arguments: args, reply }),
          is_error: reply.isError === true,
        });
        assert.notEqual(reply.isError, true, name + ": " + JSON.stringify(reply.structuredContent ?? reply.content));
        return reply.structuredContent;
      };

      await call("open_binary", { path: target, provider_id: "ghidra" });
      opened = true;
      const inventory = parseEvidence(await call("list_procedures", {}));
      assert.equal(inventory.subject.digest.sha256, sourceSha);
      assert.ok(Array.isArray(inventory.normalized_result) && inventory.normalized_result.length > 0);
      const pseudocode = parseEvidence(await call("procedure_pseudo_code", { procedure: ENTRY }));
      assert.equal(pseudocode.subject.digest.sha256, sourceSha);
      assert.equal(pseudocode.provider.id, "ghidra");
      assert.equal(typeof pseudocode.normalized_result, "string");
      assert.match(pseudocode.normalized_result, /return\s+0\s*;/u);

      await call("close_binary", {});
      opened = false;
      record.calls = calls;
      record.task = {
        correct: true,
        source_sha256: sourceSha,
        provider: pseudocode.provider.id,
        profile_digest: pseudocode.analysis_profile.digest,
        procedure_count: inventory.normalized_result.length,
        procedure_inventory_sha256: sha256(JSON.stringify(inventory.normalized_result)),
        pseudocode_sha256: sha256(pseudocode.normalized_result),
        pseudocode_contains_expected_return: true,
        calls_count: calls.length,
        request_response_utf8_bytes: calls.reduce((sum, item) => sum + item.request_response_utf8_bytes, 0),
        estimated_tokenx_request_response_tokens: calls.reduce((sum, item) => sum + item.estimated_tokenx_tokens, 0),
      };
    } catch (error) {
      record.task = { correct: false, error: String(error) };
      failures.push({ id: test.id, error: String(error) });
    } finally {
      record.wall_ms = Math.round(performance.now() - began);
      if (opened && client !== undefined) {
        try { await client.callTool({ name: "close_binary", arguments: {} }, { timeout: 60000 }); }
        catch (error) { failures.push({ id: test.id, cleanup_error: String(error) }); }
      }
      if (client !== undefined) await client.close();
      if (transport !== undefined) await transport.close();
      results.push(record);
    }
  }
  const controls = results.filter((x) => x.task?.correct);
  const oracleFields = ["source_sha256", "provider", "profile_digest", "procedure_count", "procedure_inventory_sha256", "pseudocode_sha256"];
  if (controls.length !== cases.length) failures.push({ reason: "Incomplete task coverage" });
  if (controls.length === cases.length) {
    for (const field of oracleFields) {
      const values = new Set(controls.map((c) => c.task[field]));
      if (values.size !== 1) failures.push({ reason: "Cross-scope oracle diverged", field, values: [...values] });
    }
    const full = controls[0].catalog;
    const compact = controls[2].catalog;
    if (!(compact.tool_count < full.tool_count && compact.schema_json_utf8_bytes < full.schema_json_utf8_bytes))
      failures.push({ reason: "Compact scope did not reduce advertised schema surface" });
  }
} finally {
  await rm(workspace, { recursive: true, force: true });
}

let cleanup = null;
try {
  const final = await completeVerifierRun(run);
  assertVerifierCleanupComplete(final.process_lineage);
  cleanup = "complete";
} catch (error) {
  cleanup = "incomplete: " + String(error);
  failures.push({ reason: "Owned process cleanup not verified", error: String(error) });
}

const report = {
  experiment: "RE-LAB-REA3026-TASK-EFFICIENCY-019",
  basis: "production MCP stdio and real Ghidra on a source-owned PE fixture",
  task: "Inspect the actual recovered procedures and decompile the PE entry; verify an observed return of zero",
  source_sha256: sourceSha,
  design: "A / B / C / C / B / A, each arm has a new MCP server, same target, same question and Ghidra toolchain",
  model_calls: 0,
  billed_model_tokens: null,
  token_interpretation: "tokenx approximate advertisement and request/reply serialization, not Qwen-tokenizer or billed model usage",
  scope_limitations: "Does not test model tool-selection, response caching in agent context, or tokens to reach a successful model answer. Durations include cold provider startup and host noise.",
  node: process.versions.node,
  cases: results,
  cleanup,
  failures,
  passed: failures.length === 0,
};
await writeFile(output, JSON.stringify(report, null, 2) + "\n", { flag: "wx", mode: 0o600 });
process.stdout.write(JSON.stringify({
  report_path: output,
  status: report.passed ? "PASS" : "FAIL",
  cases: results.map((x) => ({
    id: x.id, correct: x.task?.correct, tools: x.catalog?.tool_count,
    estimated_advertisement_tokens: x.catalog?.estimated_tokenx_tokens,
    wall_ms: x.wall_ms,
  })),
  failures,
  cleanup,
}, null, 2) + "\n");
if (!report.passed) process.exitCode = 1;
