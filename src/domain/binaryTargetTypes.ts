/** Provider-neutral CPU families detected from supported executable headers. */
export const BINARY_ARCHITECTURES = [
  "x86",
  "x86_64",
  "arm",
  "arm64",
  "mips",
] as const;
export type BinaryArchitecture = (typeof BINARY_ARCHITECTURES)[number];

/** Raw ELF facts; family recognition does not establish ISA or ABI support. */
export interface MipsElfMetadata {
  readonly elfClass: 32 | 64;
  readonly byteOrder: "little" | "big";
  readonly type: number;
  readonly flags: number;
}

interface BinaryTargetIdentity {
  readonly path: string;
  readonly sourcePath?: string;
  /** Info.plist of the app bundle the target was resolved from. */
  readonly bundleInfoPlist?: string;
  readonly sha256: string;
}

type NonExecutableMetadata = {
  readonly architecture?: never;
  readonly availableArchitectures?: never;
  readonly executableRole?: never;
  readonly managed?: never;
};

type ExecutableTarget = BinaryTargetIdentity & {
  readonly kind: "executable";
  readonly architecture: Exclude<BinaryArchitecture, "mips">;
  readonly availableArchitectures: readonly Exclude<
    BinaryArchitecture,
    "mips"
  >[];
};

/**
 * Canonical local target identity and provider-neutral file classification.
 * Each variant carries only metadata established for that exact file kind.
 */
export type BinaryTarget =
  | (BinaryTargetIdentity & {
      readonly kind: "executable";
      readonly format: "elf";
      readonly architecture: "mips";
      readonly availableArchitectures: readonly "mips"[];
      readonly mips: MipsElfMetadata;
      readonly executableRole?: never;
      readonly managed?: never;
    })
  | (ExecutableTarget & {
      readonly format: "mach-o" | "elf" | "dos-mz" | "dos-com";
      readonly executableRole?: never;
      readonly managed?: never;
    })
  | (ExecutableTarget & {
      readonly format: "pe";
      /** Provider-neutral PE image role observed from COFF characteristics. */
      readonly executableRole:
        | "application"
        | "shared-library"
        | "non-executable";
      /** Whether the PE declares a non-empty CLI header data-directory entry. */
      readonly managed: boolean;
    })
  | (BinaryTargetIdentity &
      NonExecutableMetadata & {
        readonly kind: "database";
        readonly format: "analysis-database";
      })
  | (BinaryTargetIdentity &
      NonExecutableMetadata & {
        readonly kind: "archive";
        readonly format:
          | "zip"
          | "ipa"
          | "apk"
          | "msix"
          | "appx"
          | "asar"
          | "dmg"
          | "pkg";
      })
  | (BinaryTargetIdentity &
      NonExecutableMetadata & {
        readonly kind: "artifact";
        readonly format: "plist" | "javascript" | "source-map";
      });
