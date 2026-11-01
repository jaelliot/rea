import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import { GhidraProvider } from "./GhidraProvider.js";

// The indirect-branch inventory changes Ghidra analysis results and intentionally
// invalidates older raw-profile snapshots. Pin the revised profile digests so
// incidental changes to these result-affecting commitments remain visible.
const RAW_DIGESTS = {
  "6502": "bf9b7739459155d9bfe796acf90eb640d4ea69c1ea702a685fdaae3400aeeb8e",
  "x86-disabled-analyzer":
    "9fcf47acfe448d2ee50f0d675dff4861f5c2b0c22d5d9f9438562af86f4b9cfa",
} as const;

const configFor = (environment: NodeJS.ProcessEnv) => {
  const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra", ...environment });
  if (!parsed.ok) throw parsed.error;
  return parsed.value;
};

const raw = (architecture: "6502" | "x86", entryPoint: string): BinaryTarget =>
  ({
    path: "/tmp/raw.bin",
    sha256: "a".repeat(64),
    kind: "executable",
    format: "raw-binary",
    architecture,
    availableArchitectures: [architecture],
    entryPoint,
    entryPointSource: entryPoint,
  }) as unknown as BinaryTarget;

describe("raw-binary analysis profile digest", () => {
  it("pins the 6502 raw profile after the indirect-branch inventory change", async () => {
    const ghidra = new GhidraProvider(configFor({}), silentLogger, {}, host);
    const resolved = await ghidra.resolveAnalysisProfile(raw("6502", "0x8001"));
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile?.digest).toBe(RAW_DIGESTS["6502"]);
    expect(resolved.value.profile?.parameters).toMatchObject({
      target_format: "raw-binary",
      loader: "BinaryLoader",
      language_id: "6502:LE:16:default",
      language_selection: "caller-supplied-v1",
      load_image_evidence: "independent-raw-mapping-context-v4",
      analyzer_preset: "ghidra-default",
      indirect_branch_inventory:
        "listing-computed-jumps-decompiler-comment-warnings-bounded-v2",
    });
  });

  it("pins the disabled-analyzer raw digest and its analysis options", async () => {
    const ghidra = new GhidraProvider(
      configFor({
        REA_GHIDRA_DISABLED_ANALYZERS: "Aggressive Instruction Finder",
      }),
      silentLogger,
      {},
      host,
    );
    const resolved = await ghidra.resolveAnalysisProfile(raw("x86", "0x1000"));
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile?.digest).toBe(
      RAW_DIGESTS["x86-disabled-analyzer"],
    );
    expect(resolved.value.profile?.parameters).toMatchObject({
      analysis_options: {
        disabled_analyzers: ["Aggressive Instruction Finder"],
      },
      indirect_branch_inventory:
        "listing-computed-jumps-decompiler-comment-warnings-bounded-v2",
    });
  });
});
