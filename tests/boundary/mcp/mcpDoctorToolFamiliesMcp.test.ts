import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { SESSION_TOOL_CONTRACTS } from "../../../src/contracts/sessionToolContracts.js";
import { TOOL_FAMILY_DEFINITIONS } from "../../../src/contracts/toolFamilies.js";
import { runProductionMcpDoctor } from "../../../src/mcpDoctor.js";

const expectedFamilyCount = (...families: string[]): number =>
  TOOL_FAMILY_DEFINITIONS.filter(({ id }) => families.includes(id)).reduce(
    (count, { contracts }) => count + contracts.length,
    0,
  );

/** Exercise the real child process, SDK tools/list, binary_session, and cleanup. */
const runScopedDoctor = (selection: string) =>
  runProductionMcpDoctor({
    command: process.execPath,
    args: [resolve("scripts/rea.mjs"), "mcp"],
    cwd: process.cwd(),
    environment: {
      ...process.env,
      REA_MCP_TOOL_FAMILIES: selection,
    },
  });

describe("production MCP doctor with an intentional tool-family scope", () => {
  it("accepts the session-only inventory without treating disabled tools as missing", async () => {
    const result = await runScopedDoctor("session");
    expect(result.healthy).toBe(true);
    expect(result.inventory?.tools).toMatchObject({
      expected: SESSION_TOOL_CONTRACTS.length,
      observed: SESSION_TOOL_CONTRACTS.length,
      missing: [],
      unexpected: [],
      duplicates: [],
    });
    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "inventory:tools", ok: true }),
        expect.objectContaining({ name: "server-identity", ok: true }),
        expect.objectContaining({ name: "request-flow", ok: true }),
      ]),
    );
  }, 30_000);

  it("accepts the union of the session and direct families", async () => {
    const result = await runScopedDoctor("session,direct");
    const expected = expectedFamilyCount("session", "direct");
    expect(result.healthy).toBe(true);
    expect(result.inventory?.tools).toMatchObject({
      expected,
      observed: expected,
      missing: [],
      unexpected: [],
      duplicates: [],
    });
    expect(result.request_flow.ok).toBe(true);
  }, 30_000);
});
