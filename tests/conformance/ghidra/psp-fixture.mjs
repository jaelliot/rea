import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Build one PSPSDK static ELF in a caller-owned directory; never execute it. */
export async function buildPspFixture(directory) {
  const options = {
    cwd: directory,
    env: { ...process.env, LC_ALL: "C", LANG: "C" },
    timeout: 10000,
    maxBuffer: 1024 * 1024,
  };
  const versions = {};
  for (const command of ["make", "psp-gcc", "psp-readelf", "psp-objdump"]) {
    try {
      versions[command] = (
        await execute(command, ["--version"], options)
      ).stdout.trim();
    } catch (cause) {
      throw new Error(`PSP fixture prerequisite unavailable: ${command}`, {
        cause,
      });
    }
  }
  const sdk = await execute("psp-config", ["--pspsdk-path"], options);
  assert.ok(sdk.stdout.trim(), "psp-config did not report a PSPSDK path");
  const sources = {};
  for (const name of ["main.c", "probe.S", "Makefile"]) {
    const source = new URL(`../psp/${name}`, import.meta.url);
    sources[name] = sha256(await readFile(source));
    await copyFile(source, join(directory, name));
  }
  const build = await execute("make", ["rea_psp_fixture.elf"], {
    ...options,
    timeout: 60000,
  });
  const path = join(directory, "rea_psp_fixture.elf");
  const bytes = await readFile(path);
  assert.ok(bytes.length >= 52, "PSP fixture has a truncated ELF header");
  assert.equal(bytes.toString("hex", 0, 6), "7f454c460101");
  assert.equal(bytes.readUInt16LE(16), 2, "Fixture must be ET_EXEC, not PRX");
  assert.equal(bytes.readUInt16LE(18), 8, "Fixture must declare EM_MIPS");
  assert.equal(bytes.readUInt32LE(36), 0x10a23001, "PSP flags changed");

  const readelf = await execute(
    "psp-readelf",
    ["-h", "-A", "-sW", path],
    options,
  );
  assert.equal(readelf.stderr.trim(), "", "Unexpected readelf diagnostic");
  assert.match(readelf.stdout, /Class:\s+ELF32/u);
  assert.match(readelf.stdout, /Data:\s+2's complement, little endian/u);
  assert.match(readelf.stdout, /Type:\s+EXEC\b/u);
  assert.match(readelf.stdout, /Flags:\s+0x10a23001\b/u);
  const symbols = {};
  for (const [name, type] of [
    ["rea_psp_entry", "FUNC"],
    ["rea_psp_leaf", "FUNC"],
    ["rea_psp_probe", "FUNC"],
    ["rea_psp_global", "OBJECT"],
    ["rea_psp_marker", "OBJECT"],
  ]) {
    const rows = readelf.stdout.split("\n").filter((line) => {
      const fields = line.trim().split(/\s+/u);
      return fields.length === 8 && fields[7] === name;
    });
    assert.equal(
      rows.length,
      1,
      `Expected one independently read symbol: ${name}`,
    );
    const fields = rows[0].trim().split(/\s+/u);
    assert.match(fields[1], /^[0-9a-fA-F]{8}$/u);
    assert.equal(fields[3], type);
    assert.equal(fields[4], "GLOBAL");
    assert.match(
      fields[6],
      /^\d+$/u,
      "Symbol must belong to a defined section",
    );
    symbols[name] = `0x${Number.parseInt(fields[1], 16).toString(16)}`;
  }
  const disassembly = await execute(
    "psp-objdump",
    ["-d", "--disassemble=rea_psp_probe", path],
    options,
  );
  assert.equal(disassembly.stderr.trim(), "", "Unexpected objdump diagnostic");
  assert.match(disassembly.stdout, /\bbitrev\b/u);
  return {
    path,
    sha256: sha256(bytes),
    source_sha256: sources,
    symbols,
    flags: "0x10a23001",
    sdk_path: sdk.stdout.trim(),
    versions,
    build_stdout: build.stdout,
    build_stderr: build.stderr,
    readelf: readelf.stdout,
    objdump: disassembly.stdout,
  };
}
