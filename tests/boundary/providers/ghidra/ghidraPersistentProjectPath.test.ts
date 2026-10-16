import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  ghidraPersistentProjectLocation,
  ghidraProjectFileSchema,
} from "../../../src/config/ghidraPersistentProject.js";

describe("persistent Ghidra project marker identity", () => {
  it.skipIf(process.platform === "win32")(
    "refuses a POSIX project basename containing a backslash",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "rea-persistent-path-"));
      try {
        const marker = join(root, "prefix\\Game.gpr");
        await writeFile(marker, "");
        const actual = await realpath(marker);
        expect(ghidraProjectFileSchema.safeParse(actual).success).toBe(false);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  it.skipIf(process.platform === "win32")(
    "refuses a POSIX project directory containing a backslash",
    () => {
      expect(
        ghidraProjectFileSchema.safeParse("/tmp/part\\dir/Fixture.gpr").success,
      ).toBe(false);
    },
  );

  it.skipIf(process.platform === "win32")(
    "preserves an ordinary project and selected Program",
    () => {
      const projectFile = "/tmp/rea-fixture/Fixture.gpr";
      expect(ghidraProjectFileSchema.safeParse(projectFile).success).toBe(true);
      expect(
        ghidraPersistentProjectLocation(
          { projectFile, program: "/folder/Fixture.exe" },
          "linux",
        ),
      ).toEqual({
        projectLocation: "/tmp/rea-fixture",
        projectName: "Fixture",
        folderPath: "/folder",
        programName: "Fixture.exe",
      });
    },
  );
});
