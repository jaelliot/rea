#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { cleanupOwnedProcessGroup } from "../dist/process/ProcessOwnership.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
} from "../dist/process/ProviderProcess.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import {
  assertVerifierCleanupComplete,
  completeVerifierRun,
  createVerifierRun,
} from "./lib/verifier-run.mjs";

// Real static Ghidra experiment: REA's original target never executes.
// Only a source-owned PE fixture and two caller-prepared project states exist.
if (process.argv.length !== 2 || process.platform !== "linux")
  throw new Error("Run only on a Linux verification host, with no arguments.");
const install = inspectGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (install.status !== "available")
  throw new Error("Real Ghidra prerequisite unavailable: " + JSON.stringify(install));

const root = fileURLToPath(new URL("..", import.meta.url));
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-copy-restart-"));
const projectDir = join(workspace, "saved-project");
const runtime = join(workspace, "rea-runtime");
const entry = "0x140001000";
const originalName = "saved_first_version";
const updatedName = "saved_second_version";
const scriptPath = join(root, "tests", "conformance", "ghidra");
let client;
let transport;
let report;
let stderr = "";

try {
  await mkdir(projectDir);
  await mkdir(runtime);
  await promisify(execFile)(process.execPath, [
    join(root, "scripts", "create-ghidra-windows-fixture.mjs"),
  ]);
  const targetPath = join(workspace, "Fixture.exe");
  await copyFile(
    join(root, "build", "fixtures", "rea-ghidra-windows.exe"),
    targetPath,
  );
  const originalDigest = sha256(await readFile(targetPath));

  const initialPrep = await headless([
    projectDir, "rea-project", "-import", targetPath,
    "-scriptPath", scriptPath,
    "-postScript", "ReaExistingCopyRename.java", entry, originalName,
  ]);
  assert.ok(initialPrep.includes("REA_EXISTING_COPY_RENAMED " + originalName), initialPrep);

  const env = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    TMPDIR: runtime,
    REA_LOG_LEVEL: "silent",
    REA_ANALYSIS_PROVIDER: "ghidra",
    REA_PROCESS_RUN_ID: run.run_id,
    GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
    REA_GHIDRA_EXISTING_PROJECT: projectDir,
    REA_GHIDRA_EXISTING_PROGRAM: "Fixture.exe",
    HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
    ...(process.env.JAVA_HOME === undefined
      ? {}
      : { JAVA_HOME: process.env.JAVA_HOME }),
  };
  transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(root, "scripts", "rea.mjs"), "mcp"],
    env,
    stderr: "pipe",
  });
  client = new Client({ name: "rea-copy-restart", version: "1" });
  await client.connect(transport);
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });

  await call("open_binary", {
    path: targetPath,
    provider_id: "ghidra",
  });
  const first = parseEvidence(await call("procedure_pseudo_code", {
    procedure: entry,
  }));
  assert.equal(first.subject.digest.sha256, originalDigest);
  assert.equal(first.analysis_profile.parameters.import_mode, "existing-project-copy");
  assert.match(first.normalized_result, /saved_first_version/u);

  const status = await call("binary_session");
  const beforeRunId = status.analysis_run?.run_id;
  const lineage = status.analysis_run?.process_lineage;
  const ghidra = lineage?.snapshots?.find(
    (snapshot) => snapshot.provider.id === "ghidra",
  );
  const pid = ghidra?.observation?.launcher_pid;
  if (!Number.isSafeInteger(pid) || pid < 2 || pid === process.pid ||
      pid === process.ppid)
    throw new Error("Cannot independently identify REA's Ghidra child: " +
      JSON.stringify(lineage));
  // Check the exact current PID's command before deliberately ending the
  // source-owned provider process on this disposable runner.
  const cmdline = await readFile("/proc/" + pid + "/cmdline", "utf8");
  assert.match(cmdline, /java|ghidra/iu);
  assert.match(cmdline, /Ghidra|ghidra/iu);

  // Mutate only the *external caller-owned* saved project. REA has copied it
  // into a private runtime, so this cannot change its first live analysis.
  const updatedPrep = await headless([
    projectDir, "rea-project", "-process", "Fixture.exe", "-noanalysis",
    "-scriptPath", scriptPath,
    "-postScript", "ReaExistingCopyRename.java", entry, updatedName,
  ]);
  assert.ok(updatedPrep.includes("REA_EXISTING_COPY_RENAMED " + updatedName), updatedPrep);

  process.kill(pid, "SIGKILL");
  await new Promise((resolve) => setTimeout(resolve, 400));
  await call("open_binary", { path: targetPath });
  const second = parseEvidence(await call("procedure_pseudo_code", {
    procedure: entry,
  }));
  assert.equal(second.subject.digest.sha256, originalDigest);
  assert.match(second.normalized_result, /saved_second_version/u);
  assert.doesNotMatch(second.normalized_result, /saved_first_version/u);
  assert.notEqual(second.analysis_profile.digest, first.analysis_profile.digest);
  assert.equal(second.analysis_profile.provider.id, first.analysis_profile.provider.id);
  const freshStatus = await call("binary_session");
  assert.notEqual(freshStatus.analysis_run?.run_id, beforeRunId);
  assert.equal(sha256(await readFile(targetPath)), originalDigest);
  await call("close_binary");
  report = {
    ghidra_version: install.providerVersion,
    target_sha256: originalDigest,
    old_name: originalName,
    new_name: updatedName,
    old_profile_digest: first.analysis_profile.digest,
    new_profile_digest: second.analysis_profile.digest,
    copy_profile_changed: true,
    reselected_provider: false,
    source_bytes_unchanged: true,
    cleanup: "complete",
  };
} catch (error) {
  if (stderr) console.error(stderr);
  throw error;
} finally {
  if (client !== undefined) await client.close();
  if (transport !== undefined) await transport.close();
  await rm(workspace, { recursive: true, force: true });
}
const verifierRun = await completeVerifierRun(run);
assertVerifierCleanupComplete(verifierRun.process_lineage);
assert.ok(report, "No real Ghidra restart report produced");
process.stdout.write(JSON.stringify({ verifier_run: verifierRun, ...report }, null, 2) + "\n");

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function call(name, args = {}) {
  const response = await client.callTool(
    { name, arguments: args },
    { timeout: 600000 },
  );
  if (response.isError === true)
    throw new Error(name + ": " + JSON.stringify(response.structuredContent ?? response.content));
  return response.structuredContent;
}

async function headless(args) {
  const spawn = await spawnOwnedProviderProcess({
    command: join(process.env.GHIDRA_INSTALL_DIR, "support", "analyzeHeadless"),
    arguments: args,
    runId: run.run_id,
    expectedCommand: null,
  });
  const supervisor = new ProviderProcessSupervisor({
    ...spawn,
    ownsProcessLifetime: true,
    cleanup: () => cleanupOwnedProcessGroup(spawn.ownership),
  });
  try {
    assert.ok(
      await supervisor.waitForExit(600000),
      "Ghidra saved project preparation deadline elapsed",
    );
    const snap = supervisor.snapshot();
    const combined = snap.stdout.text + "\n" + snap.stderr.text;
    assert.equal(snap.exitCode, 0, combined);
    return combined;
  } finally {
    const result = await supervisor.stop();
    assert.notEqual(result.status, "incomplete", JSON.stringify(result));
    supervisor.dispose();
  }
}
