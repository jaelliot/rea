import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";

/** Keep family recognition separate from the deliberately bounded Ghidra lane. */
export const ghidraMipsUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (target.kind !== "executable" || target.architecture !== "mips")
    return null;
  const metadata = target.mips;
  if (target.format !== "elf" || metadata === undefined)
    return "MIPS analysis requires ELF header metadata; a family name alone does not select an ISA or ABI.";
  if (metadata.elfClass !== 32)
    return "This Ghidra MIPS lane supports ELF32 only; MIPS64 and n64 remain unsupported.";
  if (metadata.type !== 2)
    return "This Ghidra MIPS lane supports ET_EXEC only; relocatable objects, shared images and PSP PRX need separate load verification.";
  if ((metadata.flags & 0x0f000000) !== 0)
    return "MIPS16, microMIPS and other ASE encodings are outside this standard-instruction MIPS lane.";
  if ((metadata.flags & 0x00ff0000) !== 0)
    return "Machine-specific MIPS variants, including PSP Allegrex, need a separately supported processor profile.";
  if ((metadata.flags & 0xf0000000) !== 0x70000000)
    return "This Ghidra MIPS lane requires EF_MIPS_ARCH_32R2; other ISA revisions need separate verification.";
  if (
    (metadata.flags & 0x0000f000) !== 0x00001000 ||
    (metadata.flags & 0x20) !== 0
  )
    return "This Ghidra MIPS lane requires an explicit o32 ABI; unspecified, n32 and EABI targets remain unsupported.";
  // These modes change floating-point interpretation independently of o32/ISA.
  // Do not admit them based solely on the integer-only conformance fixture.
  if ((metadata.flags & 0x00000200) !== 0)
    return "EF_MIPS_FP64 requires separate verification of 64-bit floating-point register semantics in this Ghidra lane.";
  if ((metadata.flags & 0x00000400) !== 0)
    return "EF_MIPS_NAN2008 requires separate verification of NaN encoding semantics in this Ghidra lane.";
  return null;
};

/** Commit source ELF interpretation without confusing target ISA with host CPU. */
export const ghidraMipsProfileParameters = (
  target: BinaryTarget,
): Readonly<Record<string, JsonValue>> => {
  if (
    target.kind !== "executable" ||
    target.architecture !== "mips" ||
    target.mips === undefined
  )
    return {};
  return {
    mips_elf: {
      elf_class: target.mips.elfClass,
      byte_order: target.mips.byteOrder,
      type: target.mips.type,
      flags: target.mips.flags,
    },
    mips_support_lane: "elf32-exec-o32-arch32r2-standard-v2",
  };
};
