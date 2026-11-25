import path from "node:path";
import { analyzeBlastRadius } from "./blastRadius.js";
import { createExecGitRunner, type GitRunner, normalizeRelPath } from "./gitRunner.js";
import { guardScan } from "./guardScan.js";
import type {
  AtomicCommitGroup,
  AtomicCommitPlanInput,
  AtomicCommitPlanResult,
  CommitType,
  Severity,
} from "./types.js";

interface ClassifiedFile {
  path: string;
  status: string;
  additions: number;
  deletions: number;
  type: CommitType;
  scope: string;
  domainOrder: number;
}

const TYPE_ORDER: Record<CommitType, number> = {
  build: 1,
  ci: 2,
  config: 3,
  refactor: 4,
  feat: 5,
  fix: 6,
  style: 7,
  test: 8,
  docs: 9,
  chore: 10,
};

function inferScopeFromPath(relPath: string): string {
  const parts = normalizeRelPath(relPath).split("/");
  if (parts.length === 1) {
    const base = parts[0].toLowerCase();
    if (base.startsWith("package") || base.includes("lock")) return "deps";
    if (base.startsWith("tsconfig") || base.includes("config")) return "config";
    if (base.endsWith(".md") || base === "license") return "docs";
    return "root";
  }

  const first = parts[0].toLowerCase();
  if (first === ".github") return "ci";
  if ((first === "src" || first === "packages" || first === "apps" || first === "lib") && parts.length >= 3) {
    return parts[1].toLowerCase().replace(/[^a-z0-9-]/g, "");
  }
  return first.replace(/[^a-z0-9-]/g, "") || "core";
}

function classifyFileForCommit(file: {
  path: string;
  status?: string;
  additions?: number;
  deletions?: number;
}): ClassifiedFile {
  const relPath = normalizeRelPath(file.path);
  const lower = relPath.toLowerCase();
  const base = path.basename(lower);
  const ext = path.extname(lower);
  const status = String(file.status || "M").toUpperCase();
  const scope = inferScopeFromPath(relPath);

  let type: CommitType = status === "A" || status === "U" ? "feat" : "fix";

  // 1. Tests
  if (
    /(?:^|\/)(?:__tests__|tests?|specs?)\//i.test(lower) ||
    /\.(?:test|spec)\.[a-z0-9]+$/i.test(base)
  ) {
    type = "test";
  }
  // 2. Documentation
  else if (
    ext === ".md" ||
    ext === ".mdx" ||
    ext === ".txt" ||
    base === "license" ||
    /(?:^|\/)docs?\//i.test(lower)
  ) {
    type = "docs";
  }
  // 3. CI / Workflows
  else if (
    lower.startsWith(".github/") ||
    lower.startsWith(".gitlab-ci") ||
    base === "jenkinsfile" ||
    base === "dockerfile" ||
    base.startsWith("docker-compose")
  ) {
    type = "ci";
  }
  // 4. Build / Dependencies
  else if (
    base === "package.json" ||
    base === "package-lock.json" ||
    base === "pnpm-lock.yaml" ||
    base === "yarn.lock" ||
    base === "cargo.toml" ||
    base === "go.mod" ||
    base === "requirements.txt" ||
    base === "pyproject.toml" ||
    ext === ".csproj" ||
    ext === ".sln"
  ) {
    type = "build";
  }
  // 5. Configuration & i18n
  else if (
    base.startsWith("tsconfig") ||
    base.includes(".config.") ||
    base.startsWith(".eslint") ||
    base.startsWith(".prettier") ||
    base === ".gitignore" ||
    base === ".editorconfig" ||
    base === "wrangler.toml" ||
    /(?:^|\/)(?:config|settings|locales?|i18n)\//i.test(lower)
  ) {
    type = "config";
  }
  // 6. Pure CSS/styling
  else if (ext === ".css" || ext === ".scss" || ext === ".less" || ext === ".svg") {
    type = "style";
  }
  // 7. Deletions or renames default to refactor/chore
  else if (status === "D" || status === "R") {
    type = "refactor";
  }
  // 8. Source files: added -> feat, modified -> check name hints
  else if (status === "A" || status === "U") {
    type = "feat";
  } else {
    if (/fix|bug|patch|hotfix|error|guard|validat/i.test(lower)) {
      type = "fix";
    } else if (/refactor|clean|migrate|types|schema/i.test(lower)) {
      type = "refactor";
    } else {
      type = "feat";
    }
  }

  return {
    path: relPath,
    status,
    additions: file.additions ?? 0,
    deletions: file.deletions ?? 0,
    type,
    scope,
    domainOrder: TYPE_ORDER[type],
  };
}

function buildConventionalMessage(
  type: CommitType,
  scope: string,
  files: ClassifiedFile[],
): { message: string; rationale: string } {
  const count = files.length;
  const firstBase = path.basename(files[0].path);
  const scopeTag = scope && scope !== "root" ? `(${scope})` : "";
  const allAdded = files.every((f) => f.status === "A" || f.status === "U");
  const allDeleted = files.every((f) => f.status === "D");

  const verb = allAdded ? "add" : allDeleted ? "remove" : "update";

  const subjectByType: Record<CommitType, string> = {
    build: `${verb} project dependencies and build manifest`,
    ci: `${verb} CI/CD workflow and container configuration`,
    config: `${verb} ${scope === "config" ? "runtime" : scope} configuration`,
    feat:
      count === 1
        ? `${verb} ${firstBase.replace(/\.[^.]+$/, "")}`
        : `${verb} ${scope} implementation (${count} files)`,
    fix:
      count === 1
        ? `resolve issue in ${firstBase.replace(/\.[^.]+$/, "")}`
        : `apply targeted fixes in ${scope} (${count} files)`,
    refactor: `refactor ${scope} structure (${count} files)`,
    style: `refine ${scope} styling and visual assets`,
    test: `${allAdded ? "add" : "update"} ${scope} automated test coverage`,
    docs: `${allAdded ? "add" : "update"} documentation${count === 1 ? ` (${firstBase})` : ""}`,
    chore: `maintain ${scope} tooling files`,
  };

  const rationaleByType: Record<CommitType, string> = {
    build: "Isolates dependency/manifest updates so lockfile diffs do not obscure application logic.",
    ci: "Keeps pipeline and deployment automation reviewable independently of code changes.",
    config: "Separates environment, compiler, and localization config from feature behavior.",
    feat: `Groups cohesive ${scope} feature files into a single reviewable unit.`,
    fix: `Isolates ${scope} bug-fix edits for clean bisect and hotfix cherry-picking.`,
    refactor: "Separates structural cleanup from functional additions.",
    style: "Keeps UI styling and asset tweaks separate from business logic.",
    test: "Bundles test additions/updates cleanly after the implementation commit.",
    docs: "Keeps README and markdown updates isolated at the end of the commit sequence.",
    chore: "Isolates routine repository maintenance files.",
  };

  const commitPrefix = type === "config" ? "chore" : type;
  return {
    message: `${commitPrefix}${scopeTag}: ${subjectByType[type]}`,
    rationale: rationaleByType[type],
  };
}

export async function planAtomicCommits(
  input: AtomicCommitPlanInput = {},
  runGit: GitRunner = createExecGitRunner(),
): Promise<AtomicCommitPlanResult> {
  const excludeRisky = input.excludeRisky !== false;
  let branch: string | undefined;
  let rawFiles: Array<{ path: string; status: string; additions: number; deletions: number }>;
  const excludedRiskyFiles: Array<{ path: string; severity: Severity; reason: string }> = [];

  if (Array.isArray(input.files) && input.files.length > 0) {
    const scan = excludeRisky
      ? await guardScan({
          files: input.files.map((f) => ({
            path: f.path,
            status: f.status,
            content: f.content,
            sizeBytes: f.sizeBytes,
          })),
        })
      : null;

    const blockedMap = new Map<string, { severity: Severity; reason: string }>();
    if (scan) {
      for (const finding of scan.findings) {
        if (finding.severity === "critical" || finding.category === "artifact" || finding.category === "credential_file") {
          if (!blockedMap.has(finding.path)) {
            blockedMap.set(finding.path, { severity: finding.severity, reason: finding.title });
          }
        }
      }
    }

    rawFiles = [];
    for (const f of input.files) {
      const norm = normalizeRelPath(f.path);
      const blocked = blockedMap.get(norm);
      if (blocked) {
        excludedRiskyFiles.push({ path: norm, severity: blocked.severity, reason: blocked.reason });
      } else {
        rawFiles.push({
          path: norm,
          status: f.status || "M",
          additions: f.additions ?? 0,
          deletions: f.deletions ?? 0,
        });
      }
    }
  } else {
    const cwd = path.resolve(input.repoPath || process.cwd());
    const [blast, scan] = await Promise.all([
      analyzeBlastRadius({ repoPath: cwd }, runGit),
      excludeRisky ? guardScan({ repoPath: cwd }, runGit) : Promise.resolve(null),
    ]);
    branch = blast.branch;

    const blockedMap = new Map<string, { severity: Severity; reason: string }>();
    if (scan) {
      for (const finding of scan.findings) {
        if (finding.severity === "critical" || finding.category === "artifact" || finding.category === "credential_file") {
          if (!blockedMap.has(finding.path)) {
            blockedMap.set(finding.path, { severity: finding.severity, reason: finding.title });
          }
        }
      }
    }

    rawFiles = [];
    for (const f of blast.files) {
      const blocked = blockedMap.get(f.path);
      if (blocked) {
        excludedRiskyFiles.push({ path: f.path, severity: blocked.severity, reason: blocked.reason });
      } else {
        rawFiles.push({
          path: f.path,
          status: f.status,
          additions: f.additions,
          deletions: f.deletions,
        });
      }
    }
  }

  const classified = rawFiles.map(classifyFileForCommit);

  // Group by (type, scope)
  const bucketMap = new Map<string, ClassifiedFile[]>();
  for (const item of classified) {
    const key = `${item.type}::${item.scope}`;
    const list = bucketMap.get(key) ?? [];
    list.push(item);
    bucketMap.set(key, list);
  }

  const rawGroups = Array.from(bucketMap.values()).sort((a, b) => {
    const orderDiff = a[0].domainOrder - b[0].domainOrder;
    if (orderDiff !== 0) return orderDiff;
    return a[0].scope.localeCompare(b[0].scope);
  });

  const groups: AtomicCommitGroup[] = rawGroups.map((items, idx) => {
    const type = items[0].type;
    const scope = items[0].scope;
    const { message, rationale } = buildConventionalMessage(type, scope, items);
    const totalAdditions = items.reduce((sum, i) => sum + i.additions, 0);
    const totalDeletions = items.reduce((sum, i) => sum + i.deletions, 0);
    const quotedPaths = items.map((i) => `"${i.path}"`).join(" ");

    return {
      order: idx + 1,
      type,
      scope,
      suggestedMessage: message,
      rationale,
      files: items.map((i) => ({
        path: i.path,
        status: i.status,
        additions: i.additions,
        deletions: i.deletions,
      })),
      totalAdditions,
      totalDeletions,
      stageCommands: [
        `git add -- ${quotedPaths}`,
        `git commit -m "${message.replace(/"/g, '\\"')}"`,
      ],
    };
  });

  const totalFilesConsidered = rawFiles.length + excludedRiskyFiles.length;
  const summaryNote =
    groups.length === 0
      ? excludedRiskyFiles.length > 0
        ? `No safe commits planned; ${excludedRiskyFiles.length} risky file(s) were withheld for remediation.`
        : "Working tree is clean — no changes to split."
      : `Planned ${groups.length} atomic commit(s) across ${rawFiles.length} safe file(s)${
          excludedRiskyFiles.length > 0
            ? ` (${excludedRiskyFiles.length} risky file(s) withheld).`
            : "."
        }`;

  return {
    repoPath: input.repoPath ? path.resolve(input.repoPath) : undefined,
    branch,
    totalFilesConsidered,
    plannedFileCount: rawFiles.length,
    groups,
    excludedRiskyFiles,
    summaryNote,
    plannedAt: new Date().toISOString(),
  };
}
