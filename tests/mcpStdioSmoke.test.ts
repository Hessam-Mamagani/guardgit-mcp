import { describe, it } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..", "..");

async function runSmokeAgainstEntry(entryRelativePath: string): Promise<void> {
  const entryAbs = path.join(ROOT_DIR, entryRelativePath);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entryAbs, "--stdio"],
    cwd: ROOT_DIR,
  });

  const client = new Client(
    { name: "guardgit-smoke-client", version: "1.0.0" },
    { capabilities: {} },
  );

  await client.connect(transport);
  try {
    // 1. Verify tools/list & SEP-1865 UI metadata + Antigravity entrypoints
    const toolsRes = await client.listTools();
    const names = toolsRes.tools.map((t) => t.name);
    for (const expected of [
      "open_guardgit_cockpit",
      "scan_precommit_guard",
      "diff_structural_json",
      "analyze_blast_radius",
      "plan_atomic_commits",
    ]) {
      assert.ok(names.includes(expected), `Missing tool ${expected} in ${entryRelativePath}`);
    }

    for (const tool of toolsRes.tools) {
      const meta = tool._meta as Record<string, unknown> | undefined;
      const ui = meta?.ui as Record<string, unknown> | undefined;
      assert.equal(ui?.resourceUri, "ui://guardgit/cockpit.html");
    }

    const cockpitTool = toolsRes.tools.find((t) => t.name === "open_guardgit_cockpit");
    const agyUi = (cockpitTool?._meta as Record<string, unknown> | undefined)?.[
      "com.google.antigravity/ui"
    ] as { entrypoints?: Array<{ type: string; title: string }> } | undefined;
    assert.ok(Array.isArray(agyUi?.entrypoints));
    assert.ok(agyUi!.entrypoints!.some((e) => e.type === "aux_pane" && e.title === "GuardGit Cockpit"));
    assert.ok(agyUi!.entrypoints!.some((e) => e.type === "global" && e.title === "GuardGit Cockpit"));

    // 2. Verify resources/list & resources/read for single-file SEP-1865 HTML
    const resourcesRes = await client.listResources();
    const uiRes = resourcesRes.resources.find((r) => r.uri === "ui://guardgit/cockpit.html");
    assert.ok(uiRes, "Missing ui://guardgit/cockpit.html resource");
    assert.equal(uiRes.mimeType, "text/html;profile=mcp-app");

    const readRes = await client.readResource({ uri: "ui://guardgit/cockpit.html" });
    assert.equal(readRes.contents.length, 1);
    const contentItem = readRes.contents[0] as {
      uri: string;
      mimeType?: string;
      text?: string;
      _meta?: { ui?: { prefersBorder?: boolean } };
    };
    assert.equal(contentItem.mimeType, "text/html;profile=mcp-app");
    assert.equal(contentItem._meta?.ui?.prefersBorder, false);
    assert.ok(contentItem.text && contentItem.text.length > 5000, "Single-file UI HTML unexpectedly small");
    assert.ok(contentItem.text.toLowerCase().includes("<!doctype html>"));
    assert.ok(contentItem.text.includes("<script"), "Missing bundled inline script");
    assert.equal(/<script[^>]+src=["']https?:\/\//i.test(contentItem.text), false, "External script CDN disallowed");

    // 3. Call all 5 tools with empty {} arguments (Antigravity entrypoint contract)
    for (const name of [
      "open_guardgit_cockpit",
      "scan_precommit_guard",
      "diff_structural_json",
      "analyze_blast_radius",
      "plan_atomic_commits",
    ]) {
      const callRes = await client.callTool({ name, arguments: {} });
      assert.notEqual(callRes.isError, true, `Tool ${name} errored on {}`);
      assert.ok(Array.isArray(callRes.content) && callRes.content.length > 0);
      assert.ok(callRes.structuredContent && typeof callRes.structuredContent === "object");
    }

    // 4. Verify scan_precommit_guard masks secrets over MCP
    const fakeSecret = "sk-ant-api03-" + "1234567890abcdefghijklmnopQRSTUVWXYZ";
    const scanRes = await client.callTool({
      name: "scan_precommit_guard",
      arguments: {
        files: [{ path: "src/leak.ts", status: "A", content: `const k = "${fakeSecret}";` }],
      },
    });
    const sc = scanRes.structuredContent as { guard?: { verdict?: string } };
    assert.equal(sc.guard?.verdict, "BLOCK");
    assert.equal(JSON.stringify(scanRes).includes(fakeSecret), false);
  } finally {
    await client.close();
  }
}

describe("GuardGit MCP Stdio Server Smoke Tests", () => {
  it("passes full SEP-1865 handshake, tools, resources, and {} calls via dist/cli.js", async () => {
    await runSmokeAgainstEntry("dist/cli.js");
  });

  it("passes full SEP-1865 handshake, tools, resources, and {} calls via standalone plugin/bin/guardgit-mcp.cjs", async () => {
    await runSmokeAgainstEntry("plugin/bin/guardgit-mcp.cjs");
  });
});
