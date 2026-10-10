#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { createAnalysisProfile } from "../dist/domain/analysisProfile.js";
import { resolveGhidraAnalysisProfile } from "../dist/ghidra/GhidraAnalysisProfile.js";
import { GhidraClient } from "../dist/ghidra/GhidraClient.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { GhidraHeadlessLauncher } from "../dist/ghidra/GhidraLauncher.js";
import { GHIDRA_PROVIDER_IDENTITY } from "../dist/ghidra/GhidraProviderCapabilities.js";
import {
  isGhidraInventoryOperation,
  parseGhidraInventoryInput,
  parseGhidraInventoryResult,
} from "../dist/ghidra/GhidraInventoryValues.js";
import {
  parseGhidraFunctionInput,
  parseGhidraFunctionResult,
} from "../dist/ghidra/GhidraFunctionValues.js";
import { buildPspFixture } from "../tests/conformance/ghidra/psp-fixture.mjs";
import { requireMcpToolError } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// This is a bridge compatibility experiment, not production PSP admission.
assert.equal(
  process.argv.length,
  2,
  "Usage: node scripts/verify-ghidra-psp-spike.mjs",
);
assert.equal(process.platform, "linux", "This spike verifies Linux x64 only");
assert.equal(process.arch, "x64", "This spike verifies Linux x64 only");
assert.ok(
  process.env.GHIDRA_INSTALL_DIR,
  "Caller-supplied GHIDRA_INSTALL_DIR required",
);
const installation = inspectGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  javaHome: process.env.JAVA_HOME,
});
assert.equal(installation.status, "available", JSON.stringify(installation));
assert.equal(
  installation.providerVersion,
  "12.1.3",
  "Spike requires Ghidra 12.1.3",
);
const extensionRoot = join(
  installation.installDir,
  "Ghidra/Extensions/ghidra-allegrex",
);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const extension = {};
try {
  for (const name of [
    "extension.properties",
    "data/languages/allegrex.ldefs",
  ]) {
    const bytes = await readFile(join(extensionRoot, name));
    extension[name] = { sha256: sha256(bytes), text: bytes.toString("utf8") };
  }
  const jars = (await readdir(join(extensionRoot, "lib"))).filter((name) =>
    name.endsWith(".jar"),
  );
  assert.ok(jars.length > 0, "Extension has no JAR");
  for (const name of jars.sort())
    extension[`lib/${name}`] = {
      sha256: sha256(await readFile(join(extensionRoot, "lib", name))),
    };
} catch (cause) {
  throw new Error(
    `PSP_EXTENSION_UNAVAILABLE: install a compatible caller-supplied ghidra-allegrex in ${extensionRoot}; this verifier does not install it`,
    { cause },
  );
}
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-psp-spike-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  JAVA_HOME: installation.javaHome,
  GHIDRA_INSTALL_DIR: installation.installDir,
  REA_PROCESS_RUN_ID: run.run_id,
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_LOG_LEVEL: "silent",
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
};
const execute = promisify(execFile);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const unsupportedReason = /Machine-specific MIPS variants/u;
let bridge;
let report;
let failure;
try {
  const fixture = await buildPspFixture(workspace);
  const parsedTarget = await parseBinaryTarget(fixture.path);
  assert.ok(parsedTarget.ok, JSON.stringify(parsedTarget));
  const target = parsedTarget.value;
  assert.equal(target.architecture, "mips");
  assert.equal(target.sha256, fixture.sha256);
  const productionProfile = await resolveGhidraAnalysisProfile(
    target,
    GHIDRA_PROVIDER_IDENTITY,
    installation,
  );
  assert.equal(
    productionProfile.ok,
    false,
    "The spike must not introduce production admission",
  );
  assert.match(productionProfile.error.message, unsupportedReason);
  const publicRejection = await verifyPublicRejection(fixture.path);

  // Deliberately test-only identity. Never publish this as a production profile.
  const profile = createAnalysisProfile(
    { ...GHIDRA_PROVIDER_IDENTITY, version: installation.providerVersion },
    {
      experiment: "psp-allegrex-bridge-spike-v1",
      public_psp_admission: "unsupported",
      expected_language: "Allegrex:LE:32:default",
      expected_compiler: "default",
      extension,
    },
  );
  bridge = new GhidraClient({
    launcher: new GhidraHeadlessLauncher({
      environment: env,
      analyzeHeadlessPath: installation.analyzeHeadlessPath,
      javaHome: installation.javaHome,
      platform: installation.platform,
      bridgeScriptPath: fileURLToPath(
        new URL("../bridge/ghidra/ReaGhidraBridge.java", import.meta.url),
      ),
    }),
    runId: run.run_id,
    platform: installation.platform,
    targetPath: fixture.path,
    targetSha256: fixture.sha256,
    providerVersion: installation.providerVersion,
    profileDigest: profile.digest,
    expectedLanguageId: "Allegrex:LE:32:default",
    expectedCompilerSpecId: "default",
    startupTimeoutMs: 180000,
  });
  const started = await bridge.start(AbortSignal.timeout(180000));
  assert.ok(started.ok, JSON.stringify(started));
  assert.equal(started.value.analysis_complete, true);
  const loaded = await call("inspect_native_load_image", {});
  assert.equal(loaded.executable_format, "PSP Executable (ELF)");
  assert.equal(loaded.language_id, "Allegrex:LE:32:default");
  assert.equal(loaded.compiler_spec_id, "default");
  assert.equal(loaded.source_files.length, 1);
  assert.equal(loaded.source_files[0].original_sha256, fixture.sha256);
  assert.equal(loaded.source_files[0].modified_sha256, fixture.sha256);
  const procedures = await call("list_procedures", {});
  for (const name of ["rea_psp_entry", "rea_psp_leaf", "rea_psp_probe"]) {
    const found = procedures.filter((item) => item.value === name);
    assert.equal(found.length, 1, `Expected one procedure: ${name}`);
    assert.equal(BigInt(found[0].address), BigInt(fixture.symbols[name]));
  }
  const callees = await call("procedure_callees", {
    procedure: fixture.symbols.rea_psp_entry,
  });
  assert.ok(
    callees.some(
      (address) => BigInt(address) === BigInt(fixture.symbols.rea_psp_leaf),
    ),
  );
  const immediate = await call("inspect_native_instruction", {
    address: fixture.symbols.rea_psp_probe,
  });
  assert.equal(immediate.status, "decoded");
  assert.equal(immediate.length, 4);
  assert.equal(immediate.bytes, "34120224");
  assert.ok(
    immediate.operands.some((operand) =>
      operand.components.some(
        (part) =>
          part.kind === "immediate" &&
          part.value !== null &&
          BigInt(part.value) === 0x1234n,
      ),
    ),
  );
  const bitrev = await call("inspect_native_instruction", {
    address: `0x${(BigInt(fixture.symbols.rea_psp_probe) + 4n).toString(16)}`,
  });
  assert.equal(bitrev.status, "decoded");
  assert.equal(bitrev.length, 4);
  assert.match(bitrev.mnemonic, /^bitrev$/iu);
  const data = await call("read_bytes", {
    address: fixture.symbols.rea_psp_global,
    length: 4,
  });
  assert.equal(data.complete, true);
  assert.equal(data.bytes_hex, "07000000");
  const marker = Buffer.from("rea-psp-source-owned-fixture\0");
  const string = await call("read_bytes", {
    address: fixture.symbols.rea_psp_marker,
    length: marker.length,
  });
  assert.equal(string.complete, true);
  assert.equal(string.bytes_hex, marker.toString("hex"));
  const offset = await call("address_to_file_offset", {
    address: fixture.symbols.rea_psp_probe,
  });
  assert.ok(
    Number.isSafeInteger(offset.file_offset) && offset.file_offset >= 0,
  );
  const original = await readFile(fixture.path);
  assert.equal(
    original
      .subarray(offset.file_offset, offset.file_offset + 8)
      .toString("hex"),
    immediate.bytes + bitrev.bytes,
  );
  const pseudocode = await call("procedure_pseudo_code", {
    procedure: fixture.symbols.rea_psp_entry,
  });
  assert.ok(typeof pseudocode === "string" && pseudocode.trim().length > 0);
  assert.equal(sha256(await readFile(fixture.path)), fixture.sha256);
  report = {
    status: "bridge_compatibility_verified_public_admission_pending",
    fixture,
    extension,
    public_rejection: publicRejection,
    handshake: started.value,
    load_image_observations: loaded,
    immediate,
    bitrev,
    known_direct_callees: callees,
    pseudocode_liveness: true,
    limitations: [
      "The direct bridge uses a test-only profile; production PSP CLI/MCP admission remains unsupported.",
      "No target execution, PRX relocations, VFPU semantics or behavioral equivalence were verified.",
      "Source mappings are observations, not REA independent ELF load-image verification.",
      "This experiment covers Linux x64 with the caller-supplied Ghidra 12.1.3 installation only.",
    ],
  };
} catch (cause) {
  failure = cause;
} finally {
  if (bridge !== undefined) {
    const closed = await bridge.close();
    if (!closed.ok)
      failure = new AggregateError(
        [failure, closed.error].filter(Boolean),
        "PSP bridge cleanup failed",
      );
  }
}
const completed = await completeVerifierRun(run);
if (
  completed.process_lineage.status !== "verified" ||
  completed.process_lineage.descendants.length !== 0
)
  failure = new AggregateError(
    [failure].filter(Boolean),
    `PSP cleanup unverified: ${JSON.stringify(completed)}`,
  );
if (failure !== undefined)
  throw new Error(
    `PSP spike failed; diagnostic workspace retained: ${workspace}`,
    { cause: failure },
  );
await rm(workspace, { recursive: true, force: true });
console.log(JSON.stringify({ ...report, ...completed }, null, 2));

async function call(operation, parameters) {
  const inventory = isGhidraInventoryOperation(operation);
  const input = (
    inventory ? parseGhidraInventoryInput : parseGhidraFunctionInput
  )(operation, parameters);
  assert.ok(input.ok, JSON.stringify(input));
  const reply = await bridge.callTool(operation, input.value, {
    signal: AbortSignal.timeout(60000),
  });
  assert.ok(reply.ok, JSON.stringify(reply));
  const parsed = (
    inventory ? parseGhidraInventoryResult : parseGhidraFunctionResult
  )(operation, reply.value);
  assert.ok(parsed.ok, JSON.stringify(parsed));
  return parsed.value;
}

async function verifyPublicRejection(path) {
  let cliFailure;
  try {
    await execute(
      process.execPath,
      [
        entrypoint,
        "function",
        path,
        "rea_psp_entry",
        "--provider",
        "ghidra",
        "--json",
      ],
      { env, timeout: 60000, maxBuffer: 1024 * 1024 },
    );
  } catch (cause) {
    cliFailure = cause;
  }
  assert.ok(
    cliFailure && Number.isInteger(cliFailure.code) && cliFailure.code !== 0,
    "Public CLI must reject PSP, not succeed or time out",
  );
  assert.match(`${cliFailure.stdout}\n${cliFailure.stderr}`, unsupportedReason);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env,
    stderr: "pipe",
  });
  const client = new Client({ name: "rea-psp-rejection-spike", version: "1" });
  let diagnostic = "";
  transport.stderr?.on("data", (chunk) => {
    diagnostic = (diagnostic + chunk.toString()).slice(-65536);
  });
  try {
    await client.connect(transport);
    const result = await client.callTool(
      { name: "open_binary", arguments: { path, provider_id: "ghidra" } },
      undefined,
      { timeout: 60000 },
    );
    const error = requireMcpToolError(result);
    assert.match(JSON.stringify(error), unsupportedReason);
    return {
      cli_exit_code: cliFailure.code,
      cli_stdout: cliFailure.stdout,
      mcp_error: error,
    };
  } catch (cause) {
    throw new Error(`Public PSP rejection failed; MCP stderr: ${diagnostic}`, {
      cause,
    });
  } finally {
    try {
      await client.close();
    } finally {
      await transport.close();
    }
  }
}
