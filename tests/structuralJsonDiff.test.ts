import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { diffJsonStrings, structuralJsonDiff } from "../src/core/structuralJsonDiff.js";

describe("structuralJsonDiff — Semantic JSON & Config Diff Engine", () => {
  it("reports semantic equality when only whitespace or key order changed", () => {
    const oldJson = JSON.stringify({ b: 2, a: { x: 1, y: 2 } }, null, 2);
    const newJson = '{"a":{"y":2,"x":1},"b":2}';
    const res = diffJsonStrings(oldJson, newJson, "config.json");
    assert.equal(res.semanticallyEqual, true);
    assert.equal(res.stats.totalNodes, 0);
    assert.equal(res.stats.breakingCount, 0);
  });

  it("flags breaking changes in package.json, tsconfig.json, and i18n locale files", () => {
    const oldPkg = JSON.stringify({
      name: "demo",
      dependencies: { react: "^18.3.1", zod: "^3.23.0" },
      scripts: { build: "tsc", test: "node --test" },
    });
    const newPkg = JSON.stringify({
      name: "demo",
      dependencies: { react: "^19.0.0", zod: "^3.24.0" },
      scripts: { build: "tsc" },
    });
    const pkgDiff = diffJsonStrings(oldPkg, newPkg, "package.json");
    assert.equal(pkgDiff.semanticallyEqual, false);
    assert.ok(pkgDiff.breakingChanges.some((b) => b.path === "dependencies.react"));
    assert.ok(pkgDiff.breakingChanges.some((b) => b.path === "scripts.test"));
    // Minor bump on zod should NOT be marked breaking
    assert.equal(pkgDiff.breakingChanges.some((b) => b.path === "dependencies.zod"), false);

    const tsDiff = diffJsonStrings(
      JSON.stringify({ compilerOptions: { strict: true, target: "ES2022" } }),
      JSON.stringify({ compilerOptions: { strict: false, target: "ES2022" } }),
      "tsconfig.json",
    );
    assert.equal(tsDiff.stats.breakingCount, 1);
    assert.equal(tsDiff.breakingChanges[0].path, "compilerOptions.strict");

    const i18nDiff = diffJsonStrings(
      JSON.stringify({ nav: { home: "Ana Sayfa", billing: "Fatura" } }),
      JSON.stringify({ nav: { home: "Ana Sayfa" } }),
      "locales/tr.json",
    );
    assert.equal(i18nDiff.stats.breakingCount, 1);
    assert.equal(i18nDiff.breakingChanges[0].path, "nav.billing");
  });

  it("handles large minified single-line JSON with keyed arrays and bulk-shift noise separation", async () => {
    const oldNodes = Array.from({ length: 40 }, (_, i) => ({
      id: `node-${i}`,
      name: `Service ${i}`,
      cluster: 1,
      status: "ok",
    }));
    const newNodes = oldNodes.map((n, i) => ({
      ...n,
      cluster: 2, // noisy bulk shift across all 40 nodes
      status: i === 5 ? "degraded" : "ok", // real substantive change
    }));
    newNodes.push({ id: "node-40", name: "Service 40", cluster: 2, status: "ok" });

    const oldMinified = JSON.stringify({ nodes: oldNodes });
    const newMinified = JSON.stringify({ nodes: newNodes });

    const res = await structuralJsonDiff({
      oldJson: oldMinified,
      newJson: newMinified,
      filePath: "graph.json",
    });

    assert.equal(res.isMinified, true);
    assert.equal(res.nodes.length, 1);
    const arrNode = res.nodes[0];
    assert.equal(arrNode.path, "nodes");
    assert.equal(arrNode.arraySummary?.strategy, "key");
    assert.equal(arrNode.arraySummary?.keyName, "id");
    assert.equal(arrNode.arraySummary?.addedCount, 1);
    assert.equal(arrNode.arraySummary?.modifiedCount, 40);
    assert.ok(arrNode.arraySummary?.bulkShiftedFields.includes("cluster"));
    assert.ok(arrNode.arraySummary?.modifiedSamples.some((s) => s.includes("Service 5") && s.includes("status")));
  });

  it("detects type changes cleanly and handles malformed JSON gracefully", () => {
    const typeDiff = diffJsonStrings('{"timeout": 30}', '{"timeout": "30s"}', "app.json");
    assert.equal(typeDiff.stats.typeChanged, 1);
    assert.equal(typeDiff.stats.breakingCount, 1);

    const errDiff = diffJsonStrings("{invalid", '{"ok":true}', "broken.json");
    assert.ok(errDiff.error?.includes("Invalid old JSON"));
  });
});
