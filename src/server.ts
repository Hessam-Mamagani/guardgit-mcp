import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  registerAppResource,
  registerAppTool,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import {
  analyzeBlastRadius,
  createExecGitRunner,
  formatBytes,
  getCurrentBranch,
  type GitRunner,
  guardScan,
  isGitRepository,
  planAtomicCommits,
  structuralJsonDiff,
  type CockpitSnapshot,
  type GuardScanResult,
  type StructuralJsonDiffResult,
  type BlastRadiusResult,
  type AtomicCommitPlanResult,
} from "./core/index.js";

export const COCKPIT_RESOURCE_URI = "ui://guardgit/cockpit.html";
export const SERVER_NAME = "guardgit-mcp";
export const SERVER_VERSION = "1.0.0";

const SAMPLE_OLD_JSON = JSON.stringify(
  {
    name: "example-service",
    version: "1.4.0",
    scripts: { dev: "vite", build: "tsc && vite build", test: "vitest run" },
    dependencies: { express: "^4.19.2", zod: "^3.23.0" },
    compilerOptions: { strict: true, target: "ES2022" },
    locales: { loginTitle: "Sign In", logoutBtn: "Sign Out", dashboardHeading: "Overview" },
  },
  null,
  2,
);

const SAMPLE_NEW_JSON = JSON.stringify(
  {
    name: "example-service",
    version: "2.0.0",
    scripts: { dev: "vite", build: "tsc && vite build", test: "node --test" },
    dependencies: { express: "^5.1.0", zod: "^3.25.0" },
    compilerOptions: { strict: false, target: "ES2022", skipLibCheck: true },
    locales: { loginTitle: "Sign In", dashboardHeading: "Control Plane", guardLabel: "Pre-Commit Guard" },
  },
  null,
  2,
);

function resolveRuntimeDir(): string {
  try {
    if (typeof __dirname === "string" && __dirname.length > 0) {
      return __dirname;
    }
  } catch {
    // ESM runtime without __dirname
  }
  try {
    if (typeof import.meta?.url === "string" && import.meta.url.startsWith("file:")) {
      return path.dirname(fileURLToPath(import.meta.url));
    }
  } catch {
    // fallback below
  }
  return process.cwd();
}

export function loadCockpitHtml(): string {
  const envHtml = process.env.GUARDGIT_APP_HTML;
  const runtimeDir = resolveRuntimeDir();
  const candidates = [
    envHtml,
    path.resolve(runtimeDir, "ui", "cockpit.html"),
    path.resolve(runtimeDir, "..", "ui", "cockpit.html"),
    path.resolve(runtimeDir, "..", "dist", "ui", "cockpit.html"),
    path.resolve(process.cwd(), "dist", "ui", "cockpit.html"),
  ].filter((p): p is string => typeof p === "string" && p.length > 0);

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return fs.readFileSync(candidate, "utf8");
    }
  }

  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>GuardGit Cockpit</title></head>
<body style="font-family:system-ui,sans-serif;padding:24px;">
  <h1>GuardGit Cockpit</h1>
  <p>UI bundle not found. Run <code>npm run build</code> in guardgit-mcp to generate <code>dist/ui/cockpit.html</code>.</p>
</body>
</html>`;
}

function summarizeGuardForModel(result: GuardScanResult): string {
  const lines = [
    `GuardGit Pre-Commit Scan — Verdict: ${result.verdict} (Risk Score: ${result.riskScore}/100)`,
    `Source: ${result.source}${result.branch ? ` | Branch: ${result.branch}` : ""} | Files scanned: ${result.summary.filesScanned}`,
    `Findings: ${result.summary.totalFindings} (Critical: ${result.summary.critical}, High: ${result.summary.high}, Medium: ${result.summary.medium}, Low: ${result.summary.low})`,
  ];

  for (const f of result.findings.slice(0, 15)) {
    const loc = f.line ? `${f.path}:${f.line}` : f.path;
    const masked = f.maskedSnippet ? ` [${f.maskedSnippet}]` : "";
    lines.push(`- [${f.severity.toUpperCase()}] ${f.title} at ${loc}${masked} -> ${f.remediationCommands[0] ?? f.gitignoreRule}`);
  }
  if (result.findings.length > 15) {
    lines.push(`... and ${result.findings.length - 15} more finding(s) visible in GuardGit Cockpit.`);
  }
  return lines.join("\n");
}

function summarizeBlastForModel(result: BlastRadiusResult): string {
  const lines = [
    `GuardGit Blast-Radius Analysis — Band: ${result.band} (Score: ${result.score}/100) on branch "${result.branch}"`,
    `Scope: ${result.totals.filesChanged} files (+${result.totals.additions}/-${result.totals.deletions} lines) across ${result.totals.directoriesTouched} directories`,
    `Merge Dry-Run (${result.mergeAdvice.targetBranch}): ${result.mergeAdvice.hasConflicts ? `CONFLICT (${result.mergeAdvice.conflictedFiles.join(", ")})` : result.mergeAdvice.note}`,
  ];
  for (const rec of result.recommendations) {
    lines.push(`- ${rec}`);
  }
  return lines.join("\n");
}

function summarizeAtomicPlanForModel(result: AtomicCommitPlanResult): string {
  const lines = [
    `GuardGit Atomic Commit Plan — ${result.summaryNote}`,
  ];
  for (const g of result.groups) {
    lines.push(`${g.order}. ${g.suggestedMessage} (${g.files.length} file(s), +${g.totalAdditions}/-${g.totalDeletions})`);
  }
  if (result.excludedRiskyFiles.length > 0) {
    lines.push(
      `Withheld risky files: ${result.excludedRiskyFiles.map((e) => `${e.path} (${e.reason})`).join("; ")}`,
    );
  }
  return lines.join("\n");
}

function trimSnapshotForPayload(snapshot: CockpitSnapshot): Record<string, unknown> {
  return {
    ...snapshot,
    guard: {
      ...snapshot.guard,
      findings: snapshot.guard.findings.slice(0, 150),
    },
    blastRadius: {
      ...snapshot.blastRadius,
      files: snapshot.blastRadius.files.slice(0, 200),
      heatmap: snapshot.blastRadius.heatmap.slice(0, 40),
    },
    jsonDiff: snapshot.jsonDiff
      ? {
          ...snapshot.jsonDiff,
          nodes: snapshot.jsonDiff.nodes.slice(0, 150),
          breakingChanges: snapshot.jsonDiff.breakingChanges.slice(0, 50),
        }
      : undefined,
  };
}

export async function buildCockpitSnapshot(
  options: {
    repoPath?: string;
    targetBranch?: string;
    jsonFilePath?: string;
    view?: CockpitSnapshot["view"];
  } = {},
  runGit: GitRunner = createExecGitRunner(),
): Promise<CockpitSnapshot> {
  const cwd = path.resolve(options.repoPath || process.cwd());
  const isRepo = fs.existsSync(cwd) ? await isGitRepository(cwd, runGit) : false;
  const branch = isRepo ? await getCurrentBranch(cwd, runGit) : "no-git";

  const [guard, blastRadius, atomicPlan] = await Promise.all([
    guardScan({ repoPath: cwd }, runGit),
    analyzeBlastRadius({ repoPath: cwd, targetBranch: options.targetBranch }, runGit),
    planAtomicCommits({ repoPath: cwd }, runGit),
  ]);

  const modifiedJsonFiles = blastRadius.files
    .map((f) => f.path)
    .filter((p) => p.toLowerCase().endsWith(".json"));

  let jsonDiff: StructuralJsonDiffResult | undefined;
  const targetJson = options.jsonFilePath || modifiedJsonFiles[0];
  if (targetJson && isRepo) {
    jsonDiff = await structuralJsonDiff({ repoPath: cwd, filePath: targetJson, baseRef: "HEAD" }, runGit);
  } else {
    jsonDiff = await structuralJsonDiff({
      oldJson: SAMPLE_OLD_JSON,
      newJson: SAMPLE_NEW_JSON,
      filePath: "sample/package.json (demo comparison)",
    });
  }

  return {
    view: options.view ?? "overview",
    repoPath: cwd,
    isGitRepo: isRepo,
    branch,
    guard,
    blastRadius,
    atomicPlan,
    jsonDiff,
    modifiedJsonFiles,
    generatedAt: new Date().toISOString(),
  };
}

export function createGuardGitServer(
  runGit: GitRunner = createExecGitRunner(),
): McpServer {
  const server = new McpServer(
    {
      name: SERVER_NAME,
      version: SERVER_VERSION,
    },
    {
      capabilities: {
        tools: {},
        resources: {},
      },
    },
  );

  registerAppResource(
    server,
    "GuardGit Cockpit",
    COCKPIT_RESOURCE_URI,
    {
      description:
        "Interactive SEP-1865 Pre-Commit DevSecOps, Structural JSON Diff, Blast-Radius Heatmap, and Atomic Commit Cockpit.",
      mimeType: RESOURCE_MIME_TYPE,
      _meta: {
        ui: {
          prefersBorder: false,
        },
      },
    },
    async () => ({
      contents: [
        {
          uri: COCKPIT_RESOURCE_URI,
          mimeType: RESOURCE_MIME_TYPE,
          text: loadCockpitHtml(),
          _meta: {
            ui: {
              prefersBorder: false,
            },
          },
        },
      ],
    }),
  );

  // 1. open_guardgit_cockpit (Primary entrypoint for aux_pane & global sidebar)
  registerAppTool(
    server,
    "open_guardgit_cockpit",
    {
      title: "GuardGit Cockpit",
      description:
        "Open the interactive GuardGit DevSecOps Cockpit for a repository: runs pre-commit secret/artifact guard, blast-radius + read-only git merge-tree conflict check, atomic commit splitter, and structural JSON diff.",
      inputSchema: {
        repoPath: z
          .string()
          .optional()
          .describe("Absolute or relative path to the Git repository. Defaults to current working directory."),
        targetBranch: z
          .string()
          .optional()
          .describe("Target branch for read-only git merge-tree conflict dry-run (e.g. main, origin/main)."),
        jsonFilePath: z
          .string()
          .optional()
          .describe("Optional JSON file relative path to diff against HEAD."),
      },
      _meta: {
        ui: {
          resourceUri: COCKPIT_RESOURCE_URI,
        },
        "com.google.antigravity/ui": {
          entrypoints: [
            { type: "aux_pane", title: "GuardGit Cockpit" },
            { type: "global", title: "GuardGit Cockpit" },
          ],
        },
      },
    },
    async (args) => {
      const snapshot = await buildCockpitSnapshot(
        {
          repoPath: args?.repoPath,
          targetBranch: args?.targetBranch,
          jsonFilePath: args?.jsonFilePath,
          view: "overview",
        },
        runGit,
      );

      const text = [
        `GuardGit Cockpit Ready — ${snapshot.repoPath} (branch: ${snapshot.branch})`,
        summarizeGuardForModel(snapshot.guard),
        "",
        summarizeBlastForModel(snapshot.blastRadius),
        "",
        summarizeAtomicPlanForModel(snapshot.atomicPlan),
      ].join("\n");

      return {
        content: [{ type: "text", text }],
        structuredContent: trimSnapshotForPayload(snapshot),
      };
    },
  );

  // 2. scan_precommit_guard
  registerAppTool(
    server,
    "scan_precommit_guard",
    {
      title: "Pre-Commit Secret & Artifact Guard",
      description:
        "Scan a repository, unified diff, or file list for leaked .env files, cloud/LLM API keys, JWTs, private keys, high-entropy secrets, large/binary blobs, local DBs, and build artifacts. Returns masked findings, 0-100 risk score, PASS/WARN/BLOCK verdict, and remediation commands.",
      inputSchema: {
        repoPath: z
          .string()
          .optional()
          .describe("Repository path to scan (read-only). Defaults to current working directory if diff and files are omitted."),
        diff: z
          .string()
          .optional()
          .describe("Optional raw unified diff text to scan in memory."),
        files: z
          .array(
            z.object({
              path: z.string(),
              status: z.string().optional(),
              content: z.string().optional(),
              sizeBytes: z.number().optional(),
              isBinary: z.boolean().optional(),
            }),
          )
          .optional()
          .describe("Optional array of files and contents to scan in memory."),
        largeFileThresholdBytes: z
          .number()
          .int()
          .nonnegative()
          .optional()
          .describe("Large blob warning threshold in bytes (default: 1048576 = 1 MiB)."),
        allowedPaths: z
          .array(z.string())
          .optional()
          .describe("Optional allowlisted relative paths to skip."),
        includeUntracked: z
          .boolean()
          .optional()
          .describe("Include untracked files in repository scans (default: true)."),
      },
      _meta: {
        ui: {
          resourceUri: COCKPIT_RESOURCE_URI,
        },
      },
    },
    async (args) => {
      const guard = await guardScan(
        {
          repoPath: args?.repoPath,
          diff: args?.diff,
          files: args?.files,
          largeFileThresholdBytes: args?.largeFileThresholdBytes,
          allowedPaths: args?.allowedPaths,
          includeUntracked: args?.includeUntracked,
        },
        runGit,
      );

      return {
        content: [{ type: "text", text: summarizeGuardForModel(guard) }],
        structuredContent: {
          view: "guard",
          repoPath: guard.repoPath ?? process.cwd(),
          branch: guard.branch ?? "in-memory",
          guard: {
            ...guard,
            findings: guard.findings.slice(0, 150),
          },
          generatedAt: guard.scannedAt,
        },
      };
    },
  );

  // 3. diff_structural_json
  registerAppTool(
    server,
    "diff_structural_json",
    {
      title: "Structural JSON Diff Engine",
      description:
        "Compute a semantic key-level and keyed-array diff with automatic breaking-change detection for two JSON payloads or a tracked JSON file against HEAD.",
      inputSchema: {
        oldJson: z.string().optional().describe("Baseline JSON text."),
        newJson: z.string().optional().describe("Updated JSON text."),
        filePath: z
          .string()
          .optional()
          .describe("Label or repository-relative JSON path (e.g. package.json, tsconfig.json, locales/tr.json)."),
        repoPath: z
          .string()
          .optional()
          .describe("Repository path when diffing a tracked JSON file against baseRef."),
        baseRef: z
          .string()
          .optional()
          .describe("Git ref for the baseline blob (default: HEAD)."),
        maxNodes: z
          .number()
          .int()
          .positive()
          .max(500)
          .optional()
          .describe("Maximum semantic diff nodes to return (default: 200)."),
      },
      _meta: {
        ui: {
          resourceUri: COCKPIT_RESOURCE_URI,
        },
      },
    },
    async (args) => {
      let jsonDiff: StructuralJsonDiffResult;

      if (typeof args?.oldJson === "string" && typeof args?.newJson === "string") {
        jsonDiff = await structuralJsonDiff(
          {
            oldJson: args.oldJson,
            newJson: args.newJson,
            filePath: args.filePath || "inline.json",
            maxNodes: args.maxNodes,
          },
          runGit,
        );
      } else if (args?.filePath) {
        jsonDiff = await structuralJsonDiff(
          {
            repoPath: args.repoPath,
            filePath: args.filePath,
            baseRef: args.baseRef,
            maxNodes: args.maxNodes,
          },
          runGit,
        );
      } else {
        const cwd = path.resolve(args?.repoPath || process.cwd());
        const blast = await analyzeBlastRadius({ repoPath: cwd }, runGit);
        const firstJson = blast.files.find((f) => f.path.toLowerCase().endsWith(".json"));
        if (firstJson) {
          jsonDiff = await structuralJsonDiff(
            { repoPath: cwd, filePath: firstJson.path, baseRef: args?.baseRef || "HEAD" },
            runGit,
          );
        } else {
          jsonDiff = await structuralJsonDiff({
            oldJson: SAMPLE_OLD_JSON,
            newJson: SAMPLE_NEW_JSON,
            filePath: "sample/package.json (demo comparison)",
          });
        }
      }

      const headline = `${jsonDiff.filePath} (${formatBytes(jsonDiff.oldBytes)} -> ${formatBytes(jsonDiff.newBytes)}) | +${jsonDiff.stats.added} -${jsonDiff.stats.removed} ~${jsonDiff.stats.modified} | Breaking: ${jsonDiff.stats.breakingCount}`;

      return {
        content: [{ type: "text", text: `${headline}\n\n${jsonDiff.textSummary}` }],
        structuredContent: {
          view: "json-diff",
          repoPath: args?.repoPath ? path.resolve(args.repoPath) : process.cwd(),
          jsonDiff: {
            ...jsonDiff,
            nodes: jsonDiff.nodes.slice(0, 150),
            breakingChanges: jsonDiff.breakingChanges.slice(0, 50),
          },
          generatedAt: new Date().toISOString(),
        },
      };
    },
  );

  // 4. analyze_blast_radius
  registerAppTool(
    server,
    "analyze_blast_radius",
    {
      title: "Blast-Radius & Merge-Tree Conflict Advisor",
      description:
        "Analyze commit blast radius across sensitive paths (auth, migrations, CI/CD, API contracts, config) and execute a strictly read-only git merge-tree --write-tree dry-run conflict check against the target branch.",
      inputSchema: {
        repoPath: z
          .string()
          .optional()
          .describe("Git repository path. Defaults to current working directory."),
        targetBranch: z
          .string()
          .optional()
          .describe("Target branch for merge-tree conflict check (auto-detects origin/main or main if omitted)."),
        sourceRef: z
          .string()
          .optional()
          .describe("Source Git ref for dry-run merge (default: HEAD)."),
        files: z
          .array(
            z.object({
              path: z.string(),
              status: z.string().optional(),
              additions: z.number().optional(),
              deletions: z.number().optional(),
              isBinary: z.boolean().optional(),
            }),
          )
          .optional()
          .describe("Optional synthetic file metrics for in-memory blast-radius scoring."),
      },
      _meta: {
        ui: {
          resourceUri: COCKPIT_RESOURCE_URI,
        },
      },
    },
    async (args) => {
      const blastRadius = await analyzeBlastRadius(
        {
          repoPath: args?.repoPath,
          targetBranch: args?.targetBranch,
          sourceRef: args?.sourceRef,
          files: args?.files,
        },
        runGit,
      );

      return {
        content: [{ type: "text", text: summarizeBlastForModel(blastRadius) }],
        structuredContent: {
          view: "blast-radius",
          repoPath: blastRadius.repoPath ?? process.cwd(),
          branch: blastRadius.branch,
          blastRadius: {
            ...blastRadius,
            files: blastRadius.files.slice(0, 200),
            heatmap: blastRadius.heatmap.slice(0, 40),
          },
          generatedAt: blastRadius.analyzedAt,
        },
      };
    },
  );

  // 5. plan_atomic_commits
  registerAppTool(
    server,
    "plan_atomic_commits",
    {
      title: "Atomic Commit Splitter",
      description:
        "Group staged and unstaged repository changes into logically ordered Conventional Commits while automatically excluding blocked secrets and build artifacts.",
      inputSchema: {
        repoPath: z
          .string()
          .optional()
          .describe("Git repository path. Defaults to current working directory."),
        files: z
          .array(
            z.object({
              path: z.string(),
              status: z.string().optional(),
              additions: z.number().optional(),
              deletions: z.number().optional(),
              content: z.string().optional(),
              sizeBytes: z.number().optional(),
            }),
          )
          .optional()
          .describe("Optional in-memory list of changed files to split."),
        excludeRisky: z
          .boolean()
          .optional()
          .describe("Automatically withhold blocked secret/artifact files (default: true)."),
      },
      _meta: {
        ui: {
          resourceUri: COCKPIT_RESOURCE_URI,
        },
      },
    },
    async (args) => {
      const atomicPlan = await planAtomicCommits(
        {
          repoPath: args?.repoPath,
          files: args?.files,
          excludeRisky: args?.excludeRisky,
        },
        runGit,
      );

      return {
        content: [{ type: "text", text: summarizeAtomicPlanForModel(atomicPlan) }],
        structuredContent: {
          view: "atomic-commits",
          repoPath: atomicPlan.repoPath ?? process.cwd(),
          branch: atomicPlan.branch ?? "in-memory",
          atomicPlan,
          generatedAt: atomicPlan.plannedAt,
        },
      };
    },
  );

  return server;
}

export async function startStdioServer(
  runGit: GitRunner = createExecGitRunner(),
): Promise<void> {
  const server = createGuardGitServer(runGit);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
