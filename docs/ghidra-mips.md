# MIPS ELF analysis through Ghidra

This lane extends native ELF analysis; it does not execute MIPS code or rehost
firmware. It advances the generic-MIPS portion of
[#718](https://github.com/morluto/rea/issues/718), not the whole firmware roadmap.
PSP/Allegrex remains a separate specialization tracked in
[#1330](https://github.com/morluto/rea/issues/1330).

## Admission boundary

ELF `EM_MIPS` is retained as the provider-neutral `mips` family. The target also
retains class, byte order, `e_type`, and raw `e_flags`. Recognition does not mean
every provider or MIPS variant is supported. Existing PE, managed and Mach-O
architecture sets are unchanged.

The first Ghidra lane admits ELF32 `ET_EXEC`, little or big endian, with explicit
o32 and `EF_MIPS_ARCH_32R2` flags and no machine-specific or ASE encoding flags.
These are header declarations, not proof that every instruction conforms to
that ISA. ELF64, n32/n64, unspecified ABI, MIPS16/microMIPS, machine-specific
variants, shared/relocatable objects and PSP PRX are not covered by this lane.
Their family may be identified, but provider selection returns the specific
unsupported constraint rather than guessing a compatible profile.

Explicit `EF_MIPS_FP64` and `EF_MIPS_NAN2008` declarations are also refused:
the integer-only fixture does not establish those floating-point semantics.
Their absence is not a complete floating-point ABI check; toolchains can carry
additional ABI information in `.MIPS.abiflags`. This lane does not yet inspect
that section or claim floating-point conformance.

MIPS facts are committed in the analysis profile so interpretation changes
invalidate profile-bound snapshots. Evidence, lifecycle outputs and saved
snapshots preserve the `mips` family. Hopper and IDA adapters do not implicitly
gain MIPS support. Windows Ghidra P0 remains PE x86/x86-64 only.

## Use

With a caller-installed Ghidra and compatible JDK on a supported Linux/macOS host:

```bash
rea analyze /absolute/path/to/mips.elf --provider ghidra --json
rea function /absolute/path/to/mips.elf function_name --provider ghidra --json
```

MCP uses the existing tools, including `open_binary` with an absolute path and
`provider_id: "ghidra"`. No MIPS-specific tool catalog or emulator is introduced.
Inspect instructions, caller relationships and data alongside pseudocode. In
particular, delay-slot semantics are supplied by Ghidra, not reconstructed by
REA's ELF parser.

## Verification

The source-owned freestanding fixture is `tests/conformance/c/mips.c`. The
optional cross-target lane requires a caller-supplied Clang with MIPS targets,
LLD, Ghidra and its compatible JDK; ordinary host-native checks do not acquire
these tools. `REA_MIPS_CLANG` can select the Clang executable.

```bash
npm run build:cached
GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra \
  node scripts/verify-real-ghidra-mips.mjs
```

The lane compiles both byte orders, never executes the targets, checks real
CLI/MCP discovery and decompilation, references, target hashes, profile/Evidence
identity, snapshot round-trip and final process cleanup. Parser/profile tests
are narrower checks, not substitutes for this real-provider run. A contribution
must report the actual lanes run and leave unexecuted provider verification
explicitly pending.
