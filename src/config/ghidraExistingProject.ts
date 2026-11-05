import { isAbsolute, basename } from "node:path";
import { z } from "zod";

/** A single expanded local project marker; archives must be restored first. */
export const ghidraProjectPathSchema = z
  .string()
  .min(1)
  .refine(isAbsolute, "Ghidra project path must be absolute")
  .refine(
    (path) => path.endsWith(".gpr") && basename(path).length > 4,
    "Select an expanded .gpr project marker; restore .grez archives first",
  )
  .refine(
    (path) => process.platform === "win32" || !path.includes("\\"),
    "Ghidra project path cannot contain backslashes on POSIX",
  );

/** Headless -process accepts globs and flags; this workflow selects one program in one folder. */
export const ghidraProgramNameSchema = z
  .string()
  .min(1)
  .refine(
    (name) =>
      name.trim().length > 0 &&
      !name.startsWith("-") &&
      !/[\\/\0*?]/u.test(name),
    "Select one exact program name in the selected project folder, without paths, flags or wildcards",
  );

const MAX_GHIDRA_PROGRAM_FOLDER_LENGTH = 4096;

/**
 * A non-root project folder such as `/firmware/v2`. analyzeHeadless reads it
 * from `<project_name>/<folder_path>`; one spelling per folder keeps the
 * committed profile canonical, so the root is selected by omitting the folder.
 */
export const ghidraProgramFolderSchema = z
  .string()
  .min(2)
  .max(MAX_GHIDRA_PROGRAM_FOLDER_LENGTH)
  .refine(
    (folder) =>
      folder.startsWith("/") &&
      // Backslashes become separators and * ? are patterns in analyzeHeadless.
      !/[\\*?\p{Cc}]/u.test(folder) &&
      folder
        .slice(1)
        .split("/")
        .every(
          (segment) =>
            segment.length > 0 &&
            segment !== "." &&
            segment !== ".." &&
            segment.trim() === segment,
        ),
    "Select one absolute project folder such as /firmware/v2, without a trailing slash, wildcards, backslashes, or empty, dot or padded segments; omit the folder for the project root",
  );

export interface GhidraProjectSelection {
  readonly path: string;
  readonly programName?: string;
  /** Non-root project folder holding the program; absent selects the root. */
  readonly programFolder?: string;
}
