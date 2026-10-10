import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { ghidraMipsUnsupportedReason } from "./GhidraMipsProfile.js";

/** Allegrex's ELF machine declaration, not a filename or inferred instruction. */
export const isGhidraPspTarget = (target: BinaryTarget): boolean =>
  target.kind === "executable" &&
  target.format === "elf" &&
  target.architecture === "mips" &&
  target.mips !== undefined &&
  (target.mips.flags & 0x00ff0000) === 0x00a20000;

/** PSP has its own verified interpretation; generic MIPS rules remain unchanged. */
export const ghidraProcessorUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (
    target.kind !== "executable" ||
    target.architecture !== "mips" ||
    !isGhidraPspTarget(target)
  )
    return ghidraMipsUnsupportedReason(target);
  const metadata = target.mips;
  if (metadata === undefined) return "PSP analysis requires ELF metadata.";
  if (metadata.elfClass !== 32 || metadata.byteOrder !== "little")
    return "The PSP Allegrex profile requires little-endian ELF32.";
  if (metadata.type !== 2)
    return "The PSP Allegrex profile supports static ET_EXEC only; PRX, shared and relocatable images require separate verification.";
  // PSPSDK emits MIPS-II / Allegrex / EABI32 with NOREORDER. Do not accept
  // unknown producer flags or treat this as proof of instruction semantics.
  if (metadata.flags !== 0x10a23001)
    return "The PSP Allegrex profile requires the verified PSPSDK ELF declaration 0x10a23001; other ISA/ABI/ASE flags are not inferred.";
  if (metadata.abiFlags !== undefined && metadata.abiFlags !== null)
    return "PSP ELF with a separate MIPS ABI flags record requires verification of that record; the initial PSPSDK profile has no such declaration.";
  return null;
};

/** Propagated with every PSP observation, including successful decompilation. */
export const GHIDRA_PSP_LIMITATIONS = [
  "PSP/Allegrex analysis uses the caller-installed ghidra-allegrex extension. ELF declarations and selected instruction checks are not proof of runtime semantics.",
  "ghidra-allegrex does not model VFPU prefix effects completely in decompiled output. Verify vector behavior independently; pseudocode is not an execution oracle.",
  "This PSP profile covers static ELF32 ET_EXEC only. PRX relocations, PBP/ISO containers, live overlays and PSP emulation are outside this verified lane.",
] as const;
