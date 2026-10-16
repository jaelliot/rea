#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { TOOL_CONTRACTS, toolContract } from "../dist/contracts/toolContracts.js";
import { toolFamilyId } from "../dist/contracts/toolFamilies.js";

const execute = promisify(execFile);
const hash = (value) => createHash("sha256").update(value).digest("hex");
const script = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const codex = process.argv[2];
const reportPath = process.argv[3];
if (process.platform !== "linux" || process.argv.length !== 4 ||
    !codex?.startsWith("/") || !reportPath?.startsWith("/"))
  throw new Error("Usage: node scripts/verify-codex-rea-mcp.mjs ABS_CODEX_BIN ABS_OUTPUT_JSON");

const families = ["session", "direct", "enhanced"];
const enabledTools = [
  "open_binary", "close_binary", "binary_session",
  "list_procedures", "inspect_native_instruction", "analyze_function",
  "inspect_native_api", "export_evidence_bundle", "get_evidence_bundle",
];
const advertisedNames = TOOL_CONTRACTS
  .filter(({ name }) => families.includes(toolFamilyId(name)))
  .map(({ name }) => name).sort();
for (const name of enabledTools)
  assert.ok(advertisedNames.includes(name), "Codex allowlist is outside REA scope: " + name);

const dir = await mkdtemp(join(tmpdir(), "rea-codex-"));
const codexHome = join(dir, "codex");
const accountHome = join(dir, "account");
const configFile = join(codexHome, "config.toml");
const envSettings = {
  REA_MCP_TOOL_FAMILIES: families.join(","),
  REA_MCP_INPUT_SCHEMA_PROFILE: "compact",
  REA_LOG_LEVEL: "silent",
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-hopper/hopper",
};
const options = {
  command: process.execPath,
  args: [script, "mcp"],
  enabled_tools: enabledTools,
  startup_timeout_sec: 30,
  tool_timeout_sec: 240,
};
const config = [
  "[mcp_servers.rea]",
  "command = " + JSON.stringify(options.command),
  "args = " + JSON.stringify(options.args),
  "enabled_tools = " + JSON.stringify(options.enabled_tools),
  "startup_timeout_sec = " + String(options.startup_timeout_sec),
  "tool_timeout_sec = " + String(options.tool_timeout_sec),
  "[mcp_servers.rea.env]",
  ...Object.entries(envSettings).map(([key,value]) => key + " = " + JSON.stringify(value)),
  "",
].join("\n");

let report;
let client;
let transport;
try {
  await mkdir(codexHome, { mode: 0o700 });
  await mkdir(accountHome, { mode: 0o700 });
  await writeFile(configFile, config, { flag: "wx", mode: 0o600 });
  const isolated = {
    ...process.env,
    CODEX_HOME: codexHome,
    HOME: accountHome,
    XDG_CONFIG_HOME: join(accountHome, ".config"),
  };
  for (const key of ["OPENAI_API_KEY", "CODEX_API_KEY", "CHATGPT_SESSION_TOKEN"])
    delete isolated[key];
  const execCodex = async (...args) =>
    (await execute(codex, args, {
      cwd: dir, env: isolated, timeout: 30000, maxBuffer: 3 * 1024 * 1024,
    })).stdout.trim();

  const version = await execCodex("--version");
  assert.match(version, /0\.163\.0/u);
  const listing = JSON.parse(await execCodex("mcp", "list", "--json"));
  assert.ok(Array.isArray(listing));
  const registration = listing.find(({ name }) => name === "rea");
  assert.ok(registration, "Codex did not discover isolated REA registration");
  assert.equal(registration.enabled, true);
  assert.equal(registration.transport.type, "stdio");
  assert.equal(registration.transport.command, process.execPath);
  const details = JSON.parse(await execCodex("mcp", "get", "rea", "--json"));
  assert.equal(details.name, "rea");
  assert.equal(details.enabled, true);
  assert.deepEqual(details.transport.args, [script, "mcp"]);
  assert.deepEqual(details.enabled_tools, enabledTools);
  assert.equal(details.startup_timeout_sec, 30);
  assert.equal(details.tool_timeout_sec, 240);
  for (const [key,value] of Object.entries(envSettings))
    assert.equal(details.transport.env?.[key], value);

  // Real Codex CLI validated the configuration above. This separate MCP SDK
  // client probes live REA. It is not a real Codex model-driven tool invocation.
  transport = new StdioClientTransport({
    command: options.command,
    args: options.args,
    env: { ...isolated, ...envSettings },
    stderr: "pipe",
  });
  client = new Client({ name: "rea-codex-mcp-acceptance", version: "1" });
  await client.connect(transport);
  const names = (await client.listTools()).tools.map(({ name }) => name).sort();
  assert.deepEqual(names, advertisedNames);
  assert.deepEqual(
    (await client.listTools()).tools.map(({ name }) => name).sort(),
    names,
  );
  for (const name of enabledTools) assert.ok(names.includes(name));
  const status = await client.callTool({
    name: "binary_session", arguments: {},
  });
  assert.notEqual(status.isError, true);
  assert.equal(toolContract("binary_session").outputSchema.parse(
    status.structuredContent,
  ).result.open, false);
  const noTarget = await client.callTool({
    name: "inspect_native_api",
    arguments: { procedure: "0x1000" },
  });
  assert.equal(noTarget.isError, true);
  assert.ok(noTarget.structuredContent?.error ?? noTarget.content,
    "Missing typed no-target MCP error");
  await assert.rejects(
    () => client.callTool({
      name: "inspect_macho", arguments: { path: "/no-commercial-game-assets" },
    }),
    /disabled/u,
  );
  report = {
    status: "passed",
    codex_version: version,
    codex_config_sha256: hash(config),
    codex_config_commands: ["mcp list --json", "mcp get rea --json"],
    codex_registration_loaded: true,
    registered_families: families,
    codex_enabled_tools: enabledTools,
    live_rea_advertised_tools: names.length,
    live_rea_discovery_sha256: hash(JSON.stringify(names)),
    repeated_discovery_identical: true,
    no_target_refusal: true,
    disabled_family_refusal: true,
    actual_codex_model_calls: 0,
    actual_codex_tool_invocations: 0,
    user_codex_config_modified: false,
    model_token_usage: null,
    limitations: [
      "Codex CLI reads the isolated registration; actual Codex LLM tool routing is not established",
      "MCP live transport/validation is tested through the official SDK",
      "No Ghidra provider/PSP file was opened in this integration smoke",
      "No model context or billed token savings are claimed",
    ],
  };
} finally {
  if (client !== undefined) await client.close();
  if (transport !== undefined) await transport.close();
  await rm(dir, { recursive: true, force: true });
}
assert.ok(report);
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n",
  { flag: "wx", mode: 0o600 });
process.stdout.write(JSON.stringify(report, null, 2) + "\n");
