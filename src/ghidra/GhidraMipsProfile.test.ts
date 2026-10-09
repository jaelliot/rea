import { describe, expect, it } from "vitest";
import { parseConfig } from "../config/parseConfig.js";
import type {
  BinaryTarget,
  MipsElfMetadata,
} from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import { HopperProvider } from "../hopper/HopperProvider.js";
import { hopperLoaderArgsForTarget } from "../hopper/HopperAnalysisProfile.js";
import { IdaProvider } from "../ida/IdaProvider.js";
import { GhidraProvider } from "./GhidraProvider.js";
import type { GhidraInstallationHost } from "./GhidraInstallation.js";

// Fake installation inspection tests admission/profile contracts, not Ghidra.
const host: GhidraInstallationHost = {
  platform: "linux",
  architecture: "x64",
  readText: () => "application.version=12.1.4\n",
  executable: () => true,
  probeJava: () => ({
    version: "21.0.11",
    major: 21,
    home: "/jdk-21",
    bits: 64,
    runtime: "jdk",
  }),
};
const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra" });
if (!parsed.ok) throw parsed.error;
const config = parsed.value;
const target = (change: Partial<MipsElfMetadata> = {}): BinaryTarget => ({
  path: "/fixture.elf",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "mips",
  availableArchitectures: ["mips"],
  mips: {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    flags: 0x70001001,
    ...change,
  },
});

describe("bounded Ghidra MIPS admission", () => {
  it("binds endian and flags without widening Windows P0", async () => {
    const ghidra = new GhidraProvider(config, silentLogger, {}, host);
    const little = target();
    const big = target({ byteOrder: "big" });
    expect(ghidra.inspectTargetSupport(little).status).toBe("supported");
    expect(ghidra.inspectTargetSupport(big).status).toBe("supported");
    const left = await ghidra.resolveAnalysisProfile(little);
    const right = await ghidra.resolveAnalysisProfile(big);
    if (!left.ok) throw left.error;
    if (!right.ok) throw right.error;
    expect(left.value.profile?.parameters.mips_elf).toEqual({
      elf_class: 32,
      byte_order: "little",
      type: 2,
      flags: 0x70001001,
    });
    expect(left.value.profile?.digest).not.toBe(right.value.profile?.digest);
    const windows = new GhidraProvider(config, silentLogger, {}, {
      ...host,
      platform: "win32",
    });
    expect(windows.inspectTargetSupport(little).status).toBe("unsupported");
  });

  it.each([
    [{ elfClass: 64 }, "ELF32"],
    [{ type: 1 }, "ET_EXEC"],
    [{ type: 3 }, "ET_EXEC"],
    [{ flags: 0x70001021 }, "o32"],
    [{ flags: 0x70000001 }, "o32"],
    [{ flags: 0x72001001 }, "ASE"],
    [{ flags: 0x74001001 }, "ASE"],
    [{ flags: 0x70911001 }, "Machine-specific"],
    [{ flags: 0x60001001 }, "32R2"],
  ] satisfies [Partial<MipsElfMetadata>, string][])(
    "refuses an unverified MIPS interpretation %j",
    async (change, reason) => {
      const ghidra = new GhidraProvider(config, silentLogger, {}, host);
      const value = target(change);
      expect(ghidra.inspectTargetSupport(value)).toMatchObject({
        status: "unsupported",
        reason: expect.stringContaining(reason),
      });
      const resolved = await ghidra.resolveAnalysisProfile(value);
      expect(resolved.ok).toBe(false);
    },
  );

  it("keeps MIPS out of unverified Hopper and IDA adapter lanes", () => {
    const hopper = new HopperProvider(config, silentLogger, {}, "linux");
    expect(hopper.inspectTargetSupport(target()).status).toBe("unsupported");
    expect(hopperLoaderArgsForTarget(target()).ok).toBe(false);
    const ida = new IdaProvider(config, {});
    expect(ida.inspectTargetSupport(target()).status).toBe("unsupported");
  });
});
