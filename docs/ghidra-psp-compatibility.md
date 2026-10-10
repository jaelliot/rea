# PSP/Allegrex bridge compatibility experiment

This is a separate experiment for [#1330](https://github.com/morluto/rea/issues/1330),
built on the generic MIPS contribution in
[#1362](https://github.com/morluto/rea/pull/1362). It does **not** add production PSP
admission. The generic MIPS32r2/o32 policy, provider routing and public contracts
remain unchanged. Do not interpret a passing experiment as PSP support in
`rea analyze`, `rea function` or MCP `open_binary`.

## Question and boundary

Can the existing REA Ghidra launcher, authenticated bridge and structured result
readers inspect a source-built PSP static ELF using an already installed
`ghidra-allegrex`, without new processor semantics or a specialist MCP server?

The verifier first confirms the existing production profile and public CLI/MCP
reject the PSP machine variant with the intended reason. It then exercises
`GhidraClient` directly using an explicitly test-only profile, outside production
admission. That profile is not an approved product profile or a public Evidence
support claim. The experiment does not implement PSP cache/snapshot binding.

## Reproducible prerequisites

The first verification configuration is Linux x64, Ghidra **12.1.3**,
`ghidra-allegrex` **v21.4** and PSPDEV **v20261001**. The extension's published
v21.4 archive targets Ghidra 12.1.3; Ghidra 12.1.4 compatibility is not inferred.

Install tools yourself or provision a disposable verification runner. This
verifier never downloads or installs tools. Supply `GHIDRA_INSTALL_DIR` and a
compatible `JAVA_HOME`, plus `make`, `psp-config`, `psp-gcc`, `psp-readelf` and
`psp-objdump` on `PATH` and the toolchain's `PSPDEV` environment setting.

For this experiment the extension must be installed under
`$GHIDRA_INSTALL_DIR/Ghidra/Extensions/ghidra-allegrex`. REA isolates its analysis
home, so installation in the operator's home is not assumed to be visible. The
verifier records extension metadata, language-definition and JAR digests; a
missing installation produces `PSP_EXTENSION_UNAVAILABLE`, Presence is only a
preflight, not proof of compatibility: the real handshake and operations must
also pass.

Published archive SHA-256 digests for the initial runner:

```text
ghidra_12.1.3_PUBLIC_20260817.zip
93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54

ghidra_12.1.3_PUBLIC_20260825_ghidra-allegrex.zip
62e829fa9e6ed6f2bd343763fb339a3f8812b02a4e0ed5a9409b14007b408243

pspdev-ubuntu-latest-x86_64.tar.gz (v20261001)
a86efe624e770005290919617859e9df24bd8fcd3e364f4587f23ec7364b0acd
```

Sources: [Ghidra release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build),
[extension release](https://github.com/kotcrab/ghidra-allegrex/releases/tag/v21.4),
[PSPDEV release](https://github.com/pspdev/pspdev/releases/tag/v20261001).

```bash
npm ci
npm run build:cached
node scripts/verify-ghidra-psp-spike.mjs
# Separately retain real generic MIPS coverage with this extension installed:
npm run verify:ghidra:mips
```

The spike is an explicit Knip entry point, not an ignored file. Its prerequisites
are not added to the ordinary deterministic suite. Fork-only orchestration is
kept on a separate CI branch rather than making tool installation a product
feature or widening the upstream platform matrix.

## What a passing result establishes

`tests/conformance/psp/` contains the maintained C, assembly and Makefile sources.
The builder copies them into a private temporary directory and invokes PSPSDK's
normal non-PRX build. It checks ELF32, little-endian, `ET_EXEC`, `EM_MIPS` and
`e_flags=0x10a23001`. It does not relabel generic MIPS flags or guess a missing ABI.

GNU PSP readelf supplies defined function/data symbol addresses independently of
Ghidra. PSP objdump must recognize the source-owned `bitrev` probe. Subprocesses
use a C locale, bounded time/output and checked exit status; diagnostics are
retained in the report rather than discarded.

The direct bridge checks the observed `PSP Executable (ELF)` loader result,
`Allegrex:LE:32:default` language, `default` compiler specification, target hashes,
source function addresses, a direct call, fixed ADDIU bytes and immediate,
Allegrex BITREV decoding, known global/string bytes and original file-offset
correspondence. Pseudocode presence is only a liveness check. Existing provider
cleanup and verifier process-lineage observations are reused.

A separate run of the existing real MIPS verifier checks that installing the
extension does not turn the generic little/big-endian fixtures into PSP targets.
Neither the PSP nor generic MIPS targets are executed. Reports must distinguish
which commands actually ran; script existence does not establish a passing run.

## Remaining product work

After compatibility is observed, implement a justified PSP-specific profile and
extension availability/version identity at their owning boundaries. Do not
weaken the generic MIPS guard. Production CLI/MCP admission, actionable product
extension errors, Evidence limitations and profile-bound snapshot/cache behavior
need their own implementation and real-provider acceptance.

PRX relocation support, ISO/CSO/PBP handling, game-specific analysis, emulation,
complete VFPU semantics and behavioral equivalence are outside this experiment.
The extension documents VFPU decompilation limitations, including unmodeled
prefix semantics; this integer fixture does not resolve them. See its
[README](https://github.com/kotcrab/ghidra-allegrex/blob/v21.4/README.md).

## Research-derived acceptance boundaries for the follow-on

This source review informs the next product slice; it adds no implemented
capability or passing runtime test. Keep the generic MIPS contribution bounded
and do not make whole-game reconstruction a completion gate for #1330.

Two relevant precedents are the [MHP2G module configuration](https://github.com/tclamb/mhp2g-decomp/blob/1d81fcb047e92bf0750c1735dd2eef2074606aff/configure.py)
and [Yakumo's runtime/profile boundary](https://github.com/TeamGDB/Yakumo/blob/bbf8f09d8b7937c28ce546d686bdf93adfaf6bc2/docs/ARCHITECTURE.md).
The former separates module sources, symbols and relocations; the latter
invalidates generated functions when different code occupies an address range.
These are different target projects, not evidence that REA implements either
workflow. The portable lesson is that an address alone cannot identify code.

Apply that lesson through existing REA contracts before introducing abstractions:

- **Target/profile binding:** use two fresh source-owned static fixtures with
  different bytes at the same procedure address. Open/query A, then B, then A;
  inspect target hashes, observed instructions and Evidence identity. Returning
  A's result for B is a failure. Reuse the existing session/snapshot verifiers;
  add only missing cases. This tests target switching, not live overlay support.
- **Representation boundary:** raw overlays, PRX relocation and simultaneous
  base-plus-overlay views remain separate work. A refusal of an unsupported
  representation must not become an analysis-success count. Do not manufacture
  ELF headers, relabel generic MIPS as PSP, or add Monster Hunter load addresses
  to get a positive test. Verify mappings only when an existing contract actually
  accepts and reports them.
- **Partial facts:** unknown indirect targets, types and unmodeled VFPU effects
  must remain unknown. Nonempty pseudocode does not recover an entire function's
  behavior. An observed processor/loader and a successful decompilation query
  establish narrower facts than reconstruction or runtime equivalence.
- **Independent expectations:** keep the controlled fixture and published-program
  compatibility cases separate. Derive assertions from maintained source or
  independently inspected bytes, not the decompiler output being judged. Freeze
  a held-out target before tuning against it and report every limitation/failure.

[ModKit's package boundary and source ancestry](https://github.com/MHFU-ModKit/modkit/blob/394f2a2328f5e1e27d849cdf22ee123ceacdf774/packages/mhp-formats/README.md)
are another reason to avoid copying title-specific format code. Archive intake,
address maps, hooks, PPSSPP state control and reconstruction/pattern-mining queues
belong to callers or specialist projects. REA should provide the reusable
inspection, identity, lifecycle and failure contracts that those workflows use.
Related projects that share code or recovered symbols are not independent oracles.

[Yakumo's synthetic archive regressions](https://github.com/TeamGDB/Yakumo/blob/bbf8f09d8b7937c28ce546d686bdf93adfaf6bc2/profiles/mhp3rd/tests/tool_security_tests.py)
illustrate testing malformed inputs without game content. Reuse the failure-class
idea at a boundary REA owns, not that project's extractor or gameplay runtime.
These proposed additions need their own executable validation; the earlier
compatibility run did not test them. No automatic installation, new provider,
public tool, commercial fixture, or emulator integration is requested here.
