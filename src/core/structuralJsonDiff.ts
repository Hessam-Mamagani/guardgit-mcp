import fs from "node:fs";
import path from "node:path";
import {
  createExecGitRunner,
  formatBytes,
  type GitRunner,
  normalizeRelPath,
} from "./gitRunner.js";
import type {
  JsonArrayDiffSummary,
  JsonDiffNode,
  StructuralJsonDiffInput,
  StructuralJsonDiffResult,
} from "./types.js";

const MINIFIED_LINE_THRESHOLD = 1000;
const DEFAULT_MAX_NODES = 200;

type ArrayStrategy =
  | { mode: "primitive" }
  | { mode: "key"; keyName: string }
  | { mode: "edge" }
  | { mode: "hash" };

function isPlainObject(val: unknown): val is Record<string, unknown> {
  return val !== null && typeof val === "object" && !Array.isArray(val);
}

function getJsonType(val: unknown): string {
  if (val === null) return "null";
  if (Array.isArray(val)) return "array";
  return typeof val;
}

export function fastDeepEqual(a: unknown, b: unknown, depth = 0): boolean {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== typeof b) return false;
  if (typeof a !== "object") return false;
  if (depth > 25) return false;

  const aIsArr = Array.isArray(a);
  if (aIsArr !== Array.isArray(b)) return false;

  if (aIsArr) {
    const arrA = a as unknown[];
    const arrB = b as unknown[];
    if (arrA.length !== arrB.length) return false;
    for (let i = 0; i < arrA.length; i++) {
      if (!fastDeepEqual(arrA[i], arrB[i], depth + 1)) return false;
    }
    return true;
  }

  const objA = a as Record<string, unknown>;
  const objB = b as Record<string, unknown>;
  const keysA = Object.keys(objA);
  const keysB = Object.keys(objB);
  if (keysA.length !== keysB.length) return false;
  for (let i = 0; i < keysA.length; i++) {
    const k = keysA[i];
    if (!Object.prototype.hasOwnProperty.call(objB, k)) return false;
    if (!fastDeepEqual(objA[k], objB[k], depth + 1)) return false;
  }
  return true;
}

export function formatScalarPreview(val: unknown, maxLen = 90): string {
  if (val === null) return "null";
  if (val === undefined) return "undefined";
  if (typeof val === "string") {
    const clean = val.replace(/\s+/g, " ");
    return clean.length > maxLen ? `"${clean.slice(0, maxLen)}..."` : `"${clean}"`;
  }
  if (typeof val === "number" || typeof val === "boolean") {
    return String(val);
  }
  if (Array.isArray(val)) {
    return `[Array(${val.length})]`;
  }
  if (isPlainObject(val)) {
    const keys = Object.keys(val);
    const preview = keys.slice(0, 5).join(", ");
    return `{${preview}${keys.length > 5 ? `, +${keys.length - 5} more` : ""}}`;
  }
  return String(val);
}

function hasUltraLongLine(text: string, threshold = MINIFIED_LINE_THRESHOLD): boolean {
  if (!text) return false;
  let lineStart = 0;
  for (let i = 0; i <= text.length; i++) {
    if (i === text.length || text.charCodeAt(i) === 10) {
      if (i - lineStart > threshold) return true;
      lineStart = i + 1;
    }
  }
  return false;
}

function detectArrayStrategy(arrA: unknown[], arrB: unknown[]): ArrayStrategy {
  const sampleOne = (arr: unknown[], limit: number): unknown[] => {
    const out: unknown[] = [];
    if (arr.length === 0) return out;
    const step = Math.max(1, Math.floor(arr.length / limit));
    for (let i = 0; i < arr.length && out.length < limit; i += step) {
      out.push(arr[i]);
    }
    return out;
  };
  const sampleA = sampleOne(arrA, 30);
  const sampleB = sampleOne(arrB, 30);
  const sample = [...sampleA, ...sampleB];

  if (sample.length === 0) return { mode: "primitive" };

  let objCount = 0;
  let primCount = 0;
  for (const item of sample) {
    if (isPlainObject(item)) objCount++;
    else if (item === null || typeof item !== "object") primCount++;
  }

  if (primCount / sample.length >= 0.85) return { mode: "primitive" };
  if (objCount / sample.length < 0.8) return { mode: "hash" };

  const keyCandidates = ["id", "key", "uuid", "uid", "$id", "name", "slug", "code", "path", "url"];
  const checkKeyInSample = (items: unknown[], candidate: string): boolean => {
    const objs = items.filter(isPlainObject);
    if (objs.length === 0) return true;
    let present = 0;
    const seen = new Set<string>();
    for (const item of objs) {
      const v = item[candidate];
      if (typeof v === "string" || typeof v === "number") {
        present++;
        seen.add(String(v));
      }
    }
    return present > 0 && present / objs.length >= 0.85 && seen.size / present >= 0.75;
  };

  for (const candidate of keyCandidates) {
    if (checkKeyInSample(sampleA, candidate) && checkKeyInSample(sampleB, candidate)) {
      return { mode: "key", keyName: candidate };
    }
  }

  let edgeCount = 0;
  for (const item of sample) {
    if (
      isPlainObject(item) &&
      (typeof item.source === "string" || typeof item.source === "number") &&
      (typeof item.target === "string" || typeof item.target === "number")
    ) {
      edgeCount++;
    }
  }
  if (objCount > 0 && edgeCount / objCount >= 0.85) {
    return { mode: "edge" };
  }

  return { mode: "hash" };
}

function getArrayItemKey(item: unknown, strategy: ArrayStrategy): string {
  if (strategy.mode === "key" && isPlainObject(item)) {
    const v = item[strategy.keyName];
    if (typeof v === "string" || typeof v === "number") return String(v);
  }
  if (strategy.mode === "edge" && isPlainObject(item)) {
    if (item.source !== undefined && item.target !== undefined) {
      const rel = item.relation || item.type || "";
      return rel ? `${item.source} -> ${item.target} [${rel}]` : `${item.source} -> ${item.target}`;
    }
  }
  try {
    return JSON.stringify(item);
  } catch {
    return String(item);
  }
}

function formatArrayItemLabel(item: unknown, fallbackKey: string, strategy: ArrayStrategy): string {
  if (!isPlainObject(item)) return formatScalarPreview(item, 90);
  if (strategy.mode === "edge" && item.source !== undefined && item.target !== undefined) {
    const rel = item.relation || item.type || "";
    return `${item.source} -> ${item.target}${rel ? ` (${rel})` : ""}`.slice(0, 120);
  }
  const primary = item.label || item.name || item.title || item.id || item.key || fallbackKey;
  return String(primary).slice(0, 120);
}

function indexArrayToMap(arr: unknown[], strategy: ArrayStrategy): Map<string, unknown> {
  const map = new Map<string, unknown>();
  const dupCounts = new Map<string, number>();
  for (const item of arr) {
    const baseKey = getArrayItemKey(item, strategy);
    let finalKey = baseKey;
    if (map.has(finalKey)) {
      const nextCount = (dupCounts.get(baseKey) ?? 1) + 1;
      dupCounts.set(baseKey, nextCount);
      finalKey = `${baseKey}#${nextCount}`;
    }
    map.set(finalKey, item);
  }
  return map;
}

function getChangedObjectFields(oldObj: unknown, newObj: unknown): string[] {
  if (!isPlainObject(oldObj) || !isPlainObject(newObj)) return [];
  const keys = new Set([...Object.keys(oldObj), ...Object.keys(newObj)]);
  const changed: string[] = [];
  for (const k of keys) {
    if (!fastDeepEqual(oldObj[k], newObj[k], 0)) changed.push(k);
  }
  return changed;
}

function extractMajorVersion(ver: unknown): number | null {
  if (typeof ver !== "string") return null;
  const m = ver.trim().match(/^(?:[\^~>=<]+\s*)?(\d+)\./);
  return m ? parseInt(m[1], 10) : null;
}

function evaluateBreakingChange(
  filePath: string,
  jsonPath: string,
  kind: JsonDiffNode["kind"],
  oldVal: unknown,
  newVal: unknown,
): { breaking: boolean; reason?: string } {
  const baseLower = path.basename(filePath).toLowerCase();
  const pathLower = jsonPath.toLowerCase();

  if (kind === "type_changed") {
    return {
      breaking: true,
      reason: `Schema type changed (${getJsonType(oldVal)} -> ${getJsonType(newVal)})`,
    };
  }

  // package.json breaking heuristics
  if (baseLower === "package.json") {
    if (kind === "removed" && /^(dependencies|peerDependencies|exports|bin|main|types|scripts)\b/.test(jsonPath)) {
      return {
        breaking: true,
        reason: `Removed package contract entry (${jsonPath})`,
      };
    }
    if (kind === "modified" && /^(dependencies|peerDependencies|devDependencies)\./.test(jsonPath)) {
      const oldMaj = extractMajorVersion(oldVal);
      const newMaj = extractMajorVersion(newVal);
      if (oldMaj !== null && newMaj !== null && newMaj !== oldMaj) {
        return {
          breaking: true,
          reason: `Major dependency version change (${String(oldVal)} -> ${String(newVal)})`,
        };
      }
    }
    if (kind === "modified" && /^engines\./.test(jsonPath)) {
      return {
        breaking: true,
        reason: `Runtime engine requirement changed (${jsonPath})`,
      };
    }
  }

  // tsconfig.json compiler strictness / module changes
  if (baseLower.startsWith("tsconfig") && baseLower.endsWith(".json")) {
    const strictFlags = [
      "compileroptions.strict",
      "compileroptions.noimplicitany",
      "compileroptions.strictnullchecks",
    ];
    if (strictFlags.includes(pathLower) && oldVal === true && newVal === false) {
      return {
        breaking: true,
        reason: `TypeScript safety flag weakened (${jsonPath}: true -> false)`,
      };
    }
    if (
      ["compileroptions.module", "compileroptions.moduleresolution", "compileroptions.target"].includes(pathLower) &&
      kind === "modified"
    ) {
      return {
        breaking: true,
        reason: `Compiler output contract changed (${jsonPath})`,
      };
    }
  }

  // i18n locale files (e.g., en.json, tr.json, locales/*.json)
  const isLocaleFile =
    /(?:^|\/)(?:locales?|i18n|translations?)\//i.test(filePath) ||
    /^[a-z]{2}(?:-[a-z]{2})?\.json$/i.test(baseLower);
  if (isLocaleFile && kind === "removed") {
    return {
      breaking: true,
      reason: `Removed i18n translation key (${jsonPath}) may break UI lookups`,
    };
  }

  // Infrastructure / Kubernetes / Terraform JSON
  if (
    /(?:^|\.)(?:replicas|securitycontext|ports|ingress|policy|acl|publicaccess|iam|containers|image|database|connectionstring)(?:\.|$)/i.test(
      pathLower,
    )
  ) {
    return {
      breaking: true,
      reason: `Critical infrastructure or security configuration mutated (${jsonPath})`,
    };
  }

  // Generic removed config key
  if (kind === "removed") {
    return {
      breaking: true,
      reason: `Key removed (${jsonPath}) — verify downstream consumers`,
    };
  }

  return { breaking: false };
}

function diffArraysStructured(
  filePath: string,
  jsonPath: string,
  oldArr: unknown[],
  newArr: unknown[],
  nodes: JsonDiffNode[],
): void {
  const strategy = detectArrayStrategy(oldArr, newArr);

  if (strategy.mode === "primitive") {
    const oldCounts = new Map<string, number>();
    const newCounts = new Map<string, number>();
    for (const v of oldArr) {
      const k = JSON.stringify(v);
      oldCounts.set(k, (oldCounts.get(k) ?? 0) + 1);
    }
    for (const v of newArr) {
      const k = JSON.stringify(v);
      newCounts.set(k, (newCounts.get(k) ?? 0) + 1);
    }
    const added: string[] = [];
    const removed: string[] = [];
    for (const [k, count] of newCounts.entries()) {
      if (count > (oldCounts.get(k) ?? 0)) added.push(k);
    }
    for (const [k, count] of oldCounts.entries()) {
      if (count > (newCounts.get(k) ?? 0)) removed.push(k);
    }
    if (added.length === 0 && removed.length === 0) return;

    const summary: JsonArrayDiffSummary = {
      strategy: "primitive",
      oldLength: oldArr.length,
      newLength: newArr.length,
      addedCount: added.length,
      removedCount: removed.length,
      modifiedCount: 0,
      addedSamples: added.slice(0, 8),
      removedSamples: removed.slice(0, 8),
      modifiedSamples: [],
      bulkShiftedFields: [],
    };
    const brk = evaluateBreakingChange(filePath, jsonPath, removed.length > 0 ? "removed" : "modified", oldArr, newArr);
    nodes.push({
      path: jsonPath,
      kind: "modified",
      oldType: "array",
      newType: "array",
      oldPreview: `Array(${oldArr.length})`,
      newPreview: `Array(${newArr.length}) [+${added.length}/-${removed.length}]`,
      arraySummary: summary,
      breaking: brk.breaking && removed.length > 0,
      breakingReason: brk.breaking && removed.length > 0 ? brk.reason : undefined,
    });
    return;
  }

  const oldMap = indexArrayToMap(oldArr, strategy);
  const newMap = indexArrayToMap(newArr, strategy);

  const added: Array<{ key: string; item: unknown }> = [];
  const removed: Array<{ key: string; item: unknown }> = [];
  const modified: Array<{ key: string; oldItem: unknown; newItem: unknown; changedFields: string[] }> = [];
  const fieldChangeFreq = new Map<string, number>();

  for (const [key, newItem] of newMap.entries()) {
    if (!oldMap.has(key)) {
      added.push({ key, item: newItem });
    } else {
      const oldItem = oldMap.get(key);
      if (!fastDeepEqual(oldItem, newItem, 0)) {
        const changedFields = getChangedObjectFields(oldItem, newItem);
        for (const f of changedFields) {
          fieldChangeFreq.set(f, (fieldChangeFreq.get(f) ?? 0) + 1);
        }
        modified.push({ key, oldItem, newItem, changedFields });
      }
    }
  }
  for (const [key, oldItem] of oldMap.entries()) {
    if (!newMap.has(key)) {
      removed.push({ key, item: oldItem });
    }
  }

  if (added.length === 0 && removed.length === 0 && modified.length === 0) return;

  const sortedFields = Array.from(fieldChangeFreq.entries()).sort((a, b) => b[1] - a[1]);
  const bulkFields = new Set<string>();
  if (modified.length >= 20) {
    for (const [f, count] of sortedFields) {
      if (count / modified.length >= 0.5) bulkFields.add(f);
    }
  }

  const substantive =
    bulkFields.size > 0
      ? modified.filter((m) => m.changedFields.some((f) => !bulkFields.has(f)))
      : modified;
  const toShow = substantive.length > 0 ? substantive : modified;

  const modifiedSamples = toShow.slice(0, 8).map((m) => {
    const label = formatArrayItemLabel(m.newItem, m.key, strategy);
    const fields =
      bulkFields.size > 0 && substantive.length > 0
        ? m.changedFields.filter((f) => !bulkFields.has(f))
        : m.changedFields;
    const oldRec = isPlainObject(m.oldItem) ? m.oldItem : {};
    const newRec = isPlainObject(m.newItem) ? m.newItem : {};
    const deltas = fields
      .slice(0, 3)
      .map((f) => `${f}: ${formatScalarPreview(oldRec[f], 30)} -> ${formatScalarPreview(newRec[f], 30)}`)
      .join(", ");
    return `${label} [${deltas}]`;
  });

  const summary: JsonArrayDiffSummary = {
    strategy: strategy.mode,
    keyName: strategy.mode === "key" ? strategy.keyName : undefined,
    oldLength: oldArr.length,
    newLength: newArr.length,
    addedCount: added.length,
    removedCount: removed.length,
    modifiedCount: modified.length,
    addedSamples: added.slice(0, 8).map((e) => formatArrayItemLabel(e.item, e.key, strategy)),
    removedSamples: removed.slice(0, 8).map((e) => formatArrayItemLabel(e.item, e.key, strategy)),
    modifiedSamples,
    bulkShiftedFields: Array.from(bulkFields),
  };

  const brk = evaluateBreakingChange(
    filePath,
    jsonPath,
    removed.length > 0 ? "removed" : "modified",
    oldArr,
    newArr,
  );

  nodes.push({
    path: jsonPath,
    kind: "modified",
    oldType: "array",
    newType: "array",
    oldPreview: `Array(${oldArr.length})`,
    newPreview: `Array(${newArr.length}) [+${added.length}/-${removed.length}/~${modified.length}]`,
    arraySummary: summary,
    breaking: brk.breaking && (removed.length > 0 || /ports|containers|policy|security/i.test(jsonPath)),
    breakingReason: brk.breaking ? brk.reason : undefined,
  });
}

function diffValuesRecursive(
  filePath: string,
  pathPrefix: string,
  oldVal: unknown,
  newVal: unknown,
  nodes: JsonDiffNode[],
  maxNodes: number,
  depth = 0,
): void {
  if (nodes.length >= maxNodes) return;
  if (oldVal === newVal) return;

  const oldType = getJsonType(oldVal);
  const newType = getJsonType(newVal);

  if (oldType !== newType) {
    const brk = evaluateBreakingChange(filePath, pathPrefix || "(root)", "type_changed", oldVal, newVal);
    nodes.push({
      path: pathPrefix || "(root)",
      kind: "type_changed",
      oldType,
      newType,
      oldPreview: formatScalarPreview(oldVal),
      newPreview: formatScalarPreview(newVal),
      breaking: brk.breaking,
      breakingReason: brk.reason,
    });
    return;
  }

  if (Array.isArray(oldVal) && Array.isArray(newVal)) {
    diffArraysStructured(filePath, pathPrefix || "(root)", oldVal, newVal, nodes);
    return;
  }

  if (isPlainObject(oldVal) && isPlainObject(newVal)) {
    const oldKeys = Object.keys(oldVal);
    const newKeys = Object.keys(newVal);
    const oldSet = new Set(oldKeys);
    const newSet = new Set(newKeys);

    for (const k of newKeys) {
      if (nodes.length >= maxNodes) break;
      if (!oldSet.has(k)) {
        const fullKey = pathPrefix ? `${pathPrefix}.${k}` : k;
        const brk = evaluateBreakingChange(filePath, fullKey, "added", undefined, newVal[k]);
        nodes.push({
          path: fullKey,
          kind: "added",
          newType: getJsonType(newVal[k]),
          newPreview: formatScalarPreview(newVal[k]),
          breaking: brk.breaking,
          breakingReason: brk.reason,
        });
      }
    }

    for (const k of oldKeys) {
      if (nodes.length >= maxNodes) break;
      if (!newSet.has(k)) {
        const fullKey = pathPrefix ? `${pathPrefix}.${k}` : k;
        const brk = evaluateBreakingChange(filePath, fullKey, "removed", oldVal[k], undefined);
        nodes.push({
          path: fullKey,
          kind: "removed",
          oldType: getJsonType(oldVal[k]),
          oldPreview: formatScalarPreview(oldVal[k]),
          breaking: brk.breaking,
          breakingReason: brk.reason,
        });
      }
    }

    for (const k of newKeys) {
      if (nodes.length >= maxNodes) break;
      if (!oldSet.has(k)) continue;
      const a = oldVal[k];
      const b = newVal[k];
      if (a === b) continue;
      const fullKey = pathPrefix ? `${pathPrefix}.${k}` : k;

      if (depth < 8 && ((isPlainObject(a) && isPlainObject(b)) || (Array.isArray(a) && Array.isArray(b)))) {
        diffValuesRecursive(filePath, fullKey, a, b, nodes, maxNodes, depth + 1);
      } else if (!fastDeepEqual(a, b, 0)) {
        const kind = getJsonType(a) !== getJsonType(b) ? "type_changed" : "modified";
        const brk = evaluateBreakingChange(filePath, fullKey, kind, a, b);
        nodes.push({
          path: fullKey,
          kind,
          oldType: getJsonType(a),
          newType: getJsonType(b),
          oldPreview: formatScalarPreview(a),
          newPreview: formatScalarPreview(b),
          breaking: brk.breaking,
          breakingReason: brk.reason,
        });
      }
    }
    return;
  }

  const brk = evaluateBreakingChange(filePath, pathPrefix || "(root)", "modified", oldVal, newVal);
  nodes.push({
    path: pathPrefix || "(root)",
    kind: "modified",
    oldType,
    newType,
    oldPreview: formatScalarPreview(oldVal),
    newPreview: formatScalarPreview(newVal),
    breaking: brk.breaking,
    breakingReason: brk.reason,
  });
}

function buildTextSummary(
  filePath: string,
  oldBytes: number,
  newBytes: number,
  metadataHints: string[],
  nodes: JsonDiffNode[],
): string {
  const lines: string[] = [
    `=== STRUCTURAL JSON DIFF: ${filePath} (${formatBytes(oldBytes)} -> ${formatBytes(newBytes)}) ===`,
  ];
  if (metadataHints.length > 0) {
    lines.push(`Metadata: ${metadataHints.join(", ")}`);
  }
  if (nodes.length === 0) {
    lines.push("No semantic JSON differences detected (formatting or key ordering only).");
    return lines.join("\n");
  }
  for (const n of nodes.slice(0, 60)) {
    const flag = n.breaking ? " [BREAKING]" : "";
    if (n.kind === "added") {
      lines.push(`+ ${n.path}: ${n.newPreview}${flag}`);
    } else if (n.kind === "removed") {
      lines.push(`- ${n.path}: ${n.oldPreview}${flag}`);
    } else if (n.arraySummary) {
      const s = n.arraySummary;
      lines.push(
        `~ ${n.path} (${s.oldLength} -> ${s.newLength} items, key=${s.keyName ?? s.strategy}): +${s.addedCount} -${s.removedCount} ~${s.modifiedCount}${flag}`,
      );
      if (s.addedSamples.length > 0) lines.push(`    + ${s.addedSamples.slice(0, 5).join("; ")}`);
      if (s.removedSamples.length > 0) lines.push(`    - ${s.removedSamples.slice(0, 5).join("; ")}`);
      if (s.modifiedSamples.length > 0) lines.push(`    ~ ${s.modifiedSamples.slice(0, 5).join("; ")}`);
    } else {
      lines.push(`~ ${n.path}: ${n.oldPreview} -> ${n.newPreview}${flag}`);
    }
  }
  if (nodes.length > 60) {
    lines.push(`... (+${nodes.length - 60} more semantic changes)`);
  }
  return lines.join("\n");
}

export function diffJsonStrings(
  oldJson: string,
  newJson: string,
  filePath = "config.json",
  maxNodes = DEFAULT_MAX_NODES,
): StructuralJsonDiffResult {
  const oldBytes = Buffer.byteLength(oldJson ?? "", "utf8");
  const newBytes = Buffer.byteLength(newJson ?? "", "utf8");
  const isMinified = hasUltraLongLine(oldJson) || hasUltraLongLine(newJson);

  let parsedOld: unknown;
  let parsedNew: unknown;
  try {
    parsedOld = JSON.parse(oldJson);
  } catch (err) {
    return {
      filePath,
      oldBytes,
      newBytes,
      isMinified,
      semanticallyEqual: false,
      stats: { added: 0, removed: 0, modified: 0, typeChanged: 0, breakingCount: 0, totalNodes: 0 },
      metadataHints: [],
      nodes: [],
      breakingChanges: [],
      textSummary: `Failed to parse old JSON for ${filePath}: ${(err as Error).message}`,
      error: `Invalid old JSON: ${(err as Error).message}`,
    };
  }

  try {
    parsedNew = JSON.parse(newJson);
  } catch (err) {
    return {
      filePath,
      oldBytes,
      newBytes,
      isMinified,
      semanticallyEqual: false,
      stats: { added: 0, removed: 0, modified: 0, typeChanged: 0, breakingCount: 0, totalNodes: 0 },
      metadataHints: [],
      nodes: [],
      breakingChanges: [],
      textSummary: `Failed to parse new JSON for ${filePath}: ${(err as Error).message}`,
      error: `Invalid new JSON: ${(err as Error).message}`,
    };
  }

  const nodes: JsonDiffNode[] = [];
  diffValuesRecursive(filePath, "", parsedOld, parsedNew, nodes, maxNodes, 0);

  const metadataHints: string[] = [];
  if (isPlainObject(parsedNew)) {
    if (typeof parsedNew.name === "string" && parsedNew.name.length < 60) {
      metadataHints.push(`name="${parsedNew.name}"`);
    }
    if (typeof parsedNew.version === "string" && parsedNew.version.length < 30) {
      metadataHints.push(`version="${parsedNew.version}"`);
    }
  }

  let added = 0;
  let removed = 0;
  let modified = 0;
  let typeChanged = 0;
  for (const n of nodes) {
    if (n.kind === "added") added++;
    else if (n.kind === "removed") removed++;
    else if (n.kind === "type_changed") typeChanged++;
    else modified++;
  }

  const breakingChanges = nodes.filter((n) => n.breaking);

  return {
    filePath,
    oldBytes,
    newBytes,
    isMinified,
    semanticallyEqual: nodes.length === 0,
    stats: {
      added,
      removed,
      modified,
      typeChanged,
      breakingCount: breakingChanges.length,
      totalNodes: nodes.length,
    },
    metadataHints,
    nodes,
    breakingChanges,
    textSummary: buildTextSummary(filePath, oldBytes, newBytes, metadataHints, nodes),
  };
}

export async function structuralJsonDiff(
  input: StructuralJsonDiffInput = {},
  runGit: GitRunner = createExecGitRunner(),
): Promise<StructuralJsonDiffResult> {
  const maxNodes = input.maxNodes ?? DEFAULT_MAX_NODES;

  if (typeof input.oldJson === "string" && typeof input.newJson === "string") {
    return diffJsonStrings(input.oldJson, input.newJson, input.filePath || "inline.json", maxNodes);
  }

  const cwd = path.resolve(input.repoPath || process.cwd());
  const relPath = input.filePath ? normalizeRelPath(input.filePath) : "";

  if (!relPath) {
    return {
      filePath: "(none)",
      oldBytes: 0,
      newBytes: 0,
      isMinified: false,
      semanticallyEqual: true,
      stats: { added: 0, removed: 0, modified: 0, typeChanged: 0, breakingCount: 0, totalNodes: 0 },
      metadataHints: [],
      nodes: [],
      breakingChanges: [],
      textSummary: "No JSON file path or JSON payloads provided.",
    };
  }

  const baseRef = input.baseRef || "HEAD";
  const oldBlobRes = await runGit(["show", `${baseRef}:${relPath}`], cwd, {
    allowNonZeroExit: true,
  });
  const oldJson = oldBlobRes.exitCode === 0 ? oldBlobRes.stdout : "{}";

  const fullPath = path.join(cwd, relPath);
  let newJson = "{}";
  if (fs.existsSync(fullPath)) {
    newJson = fs.readFileSync(fullPath, "utf8");
  } else {
    const stagedBlob = await runGit(["show", `:${relPath}`], cwd, {
      allowNonZeroExit: true,
    });
    if (stagedBlob.exitCode === 0) newJson = stagedBlob.stdout;
  }

  return diffJsonStrings(oldJson, newJson, relPath, maxNodes);
}
