import fs from "node:fs";
import path from "node:path";
import {
  createExecGitRunner,
  getCurrentBranch,
  type GitRunner,
  isGitRepository,
  normalizeRelPath,
  parseNumstatZ,
  parsePorcelainStatus,
} from "./gitRunner.js";
import type {
  BlastRadiusInput,
  BlastRadiusResult,
  BlastRiskBand,
  ChangedFileMetric,
  DirectoryHeatmapEntry,
  MergeConflictResult,
  SensitiveCategory,
} from "./types.js";

const SENSITIVE_RULES: Array<{
  category: SensitiveCategory;
  weight: number;
  patterns: RegExp[];
}> = [
  {
    category: "auth_security",
    weight: 18,
    patterns: [
      /(?:^|\/)(?:auth|security|rbac|acl|oauth|jwt|session|crypto|webauthn|passkey|middleware|guard|policy)(?:[./_-]|$)/i,
    ],
  },
  {
    category: "database_migration",
    weight: 18,
    patterns: [
      /(?:^|\/)(?:migrations?|prisma|alembic|flyway|liquibase|schema)(?:[./_-]|$)/i,
      /\.sql$/i,
    ],
  },
  {
    category: "ci_cd_infra",
    weight: 15,
    patterns: [
      /^\.github\/workflows\//i,
      /(?:^|\/)(?:dockerfile|docker-compose|terraform|helm|k8s|kubernetes|nginx|wrangler\.toml)/i,
      /\.(?:tf|tfvars|hcl)$/i,
    ],
  },
  {
    category: "dependencies_lock",
    weight: 12,
    patterns: [
      /(?:^|\/)(?:package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|cargo\.toml|cargo\.lock|go\.mod|go\.sum|requirements.*\.txt|pyproject\.toml|poetry\.lock)$/i,
      /\.csproj$/i,
    ],
  },
  {
    category: "config_runtime",
    weight: 10,
    patterns: [
      /(?:^|\/)(?:tsconfig.*\.json|vite\.config\.|next\.config\.|webpack\.config\.|appsettings.*\.json|\.env(?:\.|$)|config\/)/i,
    ],
  },
  {
    category: "core_api_contract",
    weight: 14,
    patterns: [
      /(?:^|\/)(?:openapi|swagger|schema\.graphql|routes?|controllers?|api\/|endpoints?)/i,
      /\.proto$/i,
    ],
  },
];

export function classifySensitiveCategories(relPath: string): {
  categories: SensitiveCategory[];
  weight: number;
} {
  const norm = normalizeRelPath(relPath);
  const categories: SensitiveCategory[] = [];
  let weight = 0;
  for (const rule of SENSITIVE_RULES) {
    if (rule.patterns.some((re) => re.test(norm))) {
      categories.push(rule.category);
      weight += rule.weight;
    }
  }
  return { categories, weight };
}

function getDirectoryBucket(relPath: string): string {
  const parts = normalizeRelPath(relPath).split("/");
  if (parts.length <= 1) return "(root)";
  if (parts.length === 2) return `${parts[0]}/`;
  return `${parts[0]}/${parts[1]}/`;
}

async function resolveDefaultTargetBranch(
  cwd: string,
  currentBranch: string,
  runGit: GitRunner,
): Promise<string | null> {
  const candidates = ["origin/main", "main", "origin/master", "master", "develop", "origin/develop"];
  for (const ref of candidates) {
    if (ref === currentBranch) continue;
    const check = await runGit(["rev-parse", "--verify", "--quiet", ref], cwd, {
      allowNonZeroExit: true,
    });
    if (check.exitCode === 0 && check.stdout.trim()) {
      return ref;
    }
  }
  return null;
}

export async function checkMergeConflicts(
  repoPath: string,
  targetBranch?: string,
  sourceRef = "HEAD",
  runGit: GitRunner = createExecGitRunner(),
  localDirtyPaths: string[] = [],
): Promise<MergeConflictResult> {
  const cwd = path.resolve(repoPath);
  const currentBranch = await getCurrentBranch(cwd, runGit);

  // Verify repository has at least one commit
  const headCheck = await runGit(["rev-parse", "--verify", "--quiet", sourceRef], cwd, {
    allowNonZeroExit: true,
  });
  if (headCheck.exitCode !== 0) {
    return {
      checked: false,
      targetBranch: targetBranch || "main",
      sourceRef,
      aheadCount: 0,
      behindCount: 0,
      hasConflicts: false,
      conflictedFiles: [],
      conflictDetails: [],
      workingTreeOverlapFiles: [],
      note: "Repository has no commits yet; dry-run merge check skipped.",
    };
  }

  let resolvedTarget = targetBranch?.trim() || "";
  if (resolvedTarget) {
    const verify = await runGit(["rev-parse", "--verify", "--quiet", resolvedTarget], cwd, {
      allowNonZeroExit: true,
    });
    if (verify.exitCode !== 0) {
      return {
        checked: false,
        targetBranch: resolvedTarget,
        sourceRef,
        aheadCount: 0,
        behindCount: 0,
        hasConflicts: false,
        conflictedFiles: [],
        conflictDetails: [],
        workingTreeOverlapFiles: [],
        note: `Target branch "${resolvedTarget}" not found in local refs.`,
      };
    }
  } else {
    const auto = await resolveDefaultTargetBranch(cwd, currentBranch, runGit);
    if (!auto) {
      return {
        checked: false,
        targetBranch: currentBranch,
        sourceRef,
        aheadCount: 0,
        behindCount: 0,
        hasConflicts: false,
        conflictedFiles: [],
        conflictDetails: [],
        workingTreeOverlapFiles: [],
        note: `On branch "${currentBranch}" with no distinct main/master/remote target branch to dry-run merge against.`,
      };
    }
    resolvedTarget = auto;
  }

  // Ahead/behind counts
  let aheadCount = 0;
  let behindCount = 0;
  const lr = await runGit(
    ["rev-list", "--left-right", "--count", `${resolvedTarget}...${sourceRef}`],
    cwd,
    { allowNonZeroExit: true },
  );
  if (lr.exitCode === 0) {
    const parts = lr.stdout.trim().split(/\s+/);
    if (parts.length === 2) {
      behindCount = parseInt(parts[0], 10) || 0;
      aheadCount = parseInt(parts[1], 10) || 0;
    }
  }

  const mbRes = await runGit(["merge-base", resolvedTarget, sourceRef], cwd, {
    allowNonZeroExit: true,
  });
  const mergeBase = mbRes.exitCode === 0 ? mbRes.stdout.trim() : undefined;

  // Check if local uncommitted edits overlap files touched on targetBranch since merge-base
  let workingTreeOverlapFiles: string[] = [];
  if (mergeBase && localDirtyPaths.length > 0) {
    const targetChanged = await runGit(
      ["diff", "--name-only", `${mergeBase}..${resolvedTarget}`],
      cwd,
      { allowNonZeroExit: true },
    );
    if (targetChanged.exitCode === 0) {
      const targetSet = new Set(
        targetChanged.stdout
          .split(/\r?\n/)
          .map((l) => normalizeRelPath(l.trim()))
          .filter(Boolean),
      );
      workingTreeOverlapFiles = localDirtyPaths.filter((p) => targetSet.has(normalizeRelPath(p)));
    }
  }

  // Strictly read-only in-memory merge dry-run via git merge-tree --write-tree
  const mt = await runGit(
    ["merge-tree", "--write-tree", "--name-only", "--messages", resolvedTarget, sourceRef],
    cwd,
    { allowNonZeroExit: true },
  );

  const outputLines = mt.stdout.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const treeOid = outputLines[0] && /^[0-9a-f]{40}$/i.test(outputLines[0].trim())
    ? outputLines[0].trim()
    : undefined;

  if (mt.exitCode === 0) {
    return {
      checked: true,
      targetBranch: resolvedTarget,
      sourceRef,
      mergeBase,
      aheadCount,
      behindCount,
      hasConflicts: false,
      treeOid,
      conflictedFiles: [],
      conflictDetails: [],
      workingTreeOverlapFiles,
      note:
        workingTreeOverlapFiles.length > 0
          ? `Committed history merges cleanly with ${resolvedTarget}, but ${workingTreeOverlapFiles.length} uncommitted local file(s) overlap upstream changes.`
          : `Clean in-memory merge with ${resolvedTarget} (${aheadCount} ahead, ${behindCount} behind). Zero working-tree mutations.`,
    };
  }

  // Parse conflicted files & conflict detail messages from merge-tree output
  const conflictedFiles: string[] = [];
  const conflictDetails: string[] = [];

  for (let i = treeOid ? 1 : 0; i < outputLines.length; i++) {
    const line = outputLines[i].trim();
    if (!line) continue;
    if (
      line.startsWith("CONFLICT") ||
      line.startsWith("Auto-merging") ||
      line.startsWith("ERROR") ||
      line.startsWith("Informational:")
    ) {
      conflictDetails.push(line);
    } else if (!line.includes("  ") && !line.startsWith("fatal:")) {
      conflictedFiles.push(normalizeRelPath(line));
    }
  }

  // Fallback extraction from CONFLICT (...) in <path> lines if needed
  if (conflictedFiles.length === 0) {
    for (const detail of conflictDetails) {
      const m = detail.match(/Merge conflict in (.+)$/i) || detail.match(/:\s+([^\s]+)\s+deleted/i);
      if (m?.[1]) conflictedFiles.push(normalizeRelPath(m[1].trim()));
    }
  }

  const uniqueConflicted = Array.from(new Set(conflictedFiles));

  return {
    checked: true,
    targetBranch: resolvedTarget,
    sourceRef,
    mergeBase,
    aheadCount,
    behindCount,
    hasConflicts: uniqueConflicted.length > 0 || conflictDetails.some((d) => d.startsWith("CONFLICT")),
    treeOid,
    conflictedFiles: uniqueConflicted,
    conflictDetails,
    workingTreeOverlapFiles,
    note:
      uniqueConflicted.length > 0
        ? `Dry-run merge against ${resolvedTarget} detected ${uniqueConflicted.length} conflicted file(s) before push.`
        : `git merge-tree reported non-zero status against ${resolvedTarget}: ${mt.stderr.trim() || "check branch history"}`,
  };
}

function buildBlastResult(
  branch: string,
  files: ChangedFileMetric[],
  mergeAdvice: MergeConflictResult,
  repoPath?: string,
): BlastRadiusResult {
  const sensitiveHits: Record<SensitiveCategory, string[]> = {
    auth_security: [],
    database_migration: [],
    ci_cd_infra: [],
    dependencies_lock: [],
    config_runtime: [],
    core_api_contract: [],
  };

  const dirMap = new Map<
    string,
    {
      fileCount: number;
      additions: number;
      deletions: number;
      riskScore: number;
      categories: Set<SensitiveCategory>;
      files: string[];
    }
  >();

  let stagedFiles = 0;
  let unstagedFiles = 0;
  let untrackedFiles = 0;
  let additions = 0;
  let deletions = 0;
  let binaryFiles = 0;
  let sensitiveWeightSum = 0;

  for (const f of files) {
    if (f.staged) stagedFiles++;
    if (f.unstaged) unstagedFiles++;
    if (f.untracked) untrackedFiles++;
    additions += f.additions;
    deletions += f.deletions;
    if (f.isBinary) binaryFiles++;

    for (const cat of f.sensitiveCategories) {
      sensitiveHits[cat].push(f.path);
    }
    sensitiveWeightSum += f.riskWeight;

    const bucket = getDirectoryBucket(f.path);
    let entry = dirMap.get(bucket);
    if (!entry) {
      entry = {
        fileCount: 0,
        additions: 0,
        deletions: 0,
        riskScore: 0,
        categories: new Set(),
        files: [],
      };
      dirMap.set(bucket, entry);
    }
    entry.fileCount++;
    entry.additions += f.additions;
    entry.deletions += f.deletions;
    entry.files.push(f.path);
    for (const cat of f.sensitiveCategories) entry.categories.add(cat);
    const churnWeight = Math.min(25, Math.floor((f.additions + f.deletions) / 40));
    entry.riskScore = Math.min(100, entry.riskScore + 6 + f.riskWeight + churnWeight);
  }

  const heatmap: DirectoryHeatmapEntry[] = Array.from(dirMap.entries())
    .map(([directory, d]) => ({
      directory,
      fileCount: d.fileCount,
      additions: d.additions,
      deletions: d.deletions,
      riskScore: Math.min(100, d.riskScore),
      categories: Array.from(d.categories),
      files: d.files.slice(0, 20),
    }))
    .sort((a, b) => b.riskScore - a.riskScore || b.fileCount - a.fileCount);

  // Composite score (0..100)
  const fileFactor = Math.min(25, files.length * 2.5);
  const churnFactor = Math.min(25, Math.floor((additions + deletions) / 50));
  const spreadFactor = Math.min(15, heatmap.length * 3);
  const sensitiveFactor = Math.min(35, sensitiveWeightSum);
  const conflictFactor = mergeAdvice.hasConflicts ? 25 : mergeAdvice.workingTreeOverlapFiles.length > 0 ? 10 : 0;

  const score = Math.min(
    100,
    Math.round(fileFactor + churnFactor + spreadFactor + sensitiveFactor + conflictFactor),
  );

  let band: BlastRiskBand = "LOW";
  if (score >= 75) band = "CRITICAL";
  else if (score >= 50) band = "HIGH";
  else if (score >= 25) band = "MODERATE";

  const recommendations: string[] = [];
  if (mergeAdvice.hasConflicts) {
    recommendations.push(
      `Rebase or merge ${mergeAdvice.targetBranch} before pushing — ${mergeAdvice.conflictedFiles.length} conflict(s) detected in dry-run.`,
    );
  }
  if (mergeAdvice.workingTreeOverlapFiles.length > 0) {
    recommendations.push(
      `Commit or stash before pulling ${mergeAdvice.targetBranch}: ${mergeAdvice.workingTreeOverlapFiles.join(", ")} also changed upstream.`,
    );
  }
  if (sensitiveHits.auth_security.length > 0) {
    recommendations.push("Request security/peer review for auth and permission changes.");
  }
  if (sensitiveHits.database_migration.length > 0) {
    recommendations.push("Verify rollback safety and idempotency for database migration files.");
  }
  if (files.length >= 12 || heatmap.length >= 4) {
    recommendations.push(
      `High cross-cutting spread (${files.length} files across ${heatmap.length} folders) — split with plan_atomic_commits.`,
    );
  }
  if (recommendations.length === 0) {
    recommendations.push("Change scope is contained and ready for standard pre-commit checks.");
  }

  return {
    repoPath,
    branch,
    score,
    band,
    totals: {
      filesChanged: files.length,
      stagedFiles,
      unstagedFiles,
      untrackedFiles,
      additions,
      deletions,
      binaryFiles,
      directoriesTouched: heatmap.length,
    },
    sensitiveHits,
    heatmap,
    files,
    mergeAdvice,
    recommendations,
    analyzedAt: new Date().toISOString(),
  };
}

export async function analyzeBlastRadius(
  input: BlastRadiusInput = {},
  runGit: GitRunner = createExecGitRunner(),
): Promise<BlastRadiusResult> {
  // Pure in-memory mode for supplied files
  if (Array.isArray(input.files) && input.files.length > 0) {
    const metrics: ChangedFileMetric[] = input.files.map((f) => {
      const norm = normalizeRelPath(f.path);
      const sens = classifySensitiveCategories(norm);
      return {
        path: norm,
        status: f.status || "M",
        staged: true,
        unstaged: false,
        untracked: f.status === "U",
        additions: f.additions ?? 0,
        deletions: f.deletions ?? 0,
        isBinary: Boolean(f.isBinary),
        sensitiveCategories: sens.categories,
        riskWeight: sens.weight,
      };
    });
    const noMerge: MergeConflictResult = {
      checked: false,
      targetBranch: input.targetBranch || "main",
      sourceRef: input.sourceRef || "HEAD",
      aheadCount: 0,
      behindCount: 0,
      hasConflicts: false,
      conflictedFiles: [],
      conflictDetails: [],
      workingTreeOverlapFiles: [],
      note: "In-memory file analysis mode (git merge-tree skipped).",
    };
    return buildBlastResult("in-memory", metrics, noMerge);
  }

  const cwd = path.resolve(input.repoPath || process.cwd());
  if (!fs.existsSync(cwd) || !(await isGitRepository(cwd, runGit))) {
    const emptyMerge: MergeConflictResult = {
      checked: false,
      targetBranch: input.targetBranch || "main",
      sourceRef: input.sourceRef || "HEAD",
      aheadCount: 0,
      behindCount: 0,
      hasConflicts: false,
      conflictedFiles: [],
      conflictDetails: [],
      workingTreeOverlapFiles: [],
      note: "Target path is not a Git repository.",
    };
    return buildBlastResult("none", [], emptyMerge, cwd);
  }

  const branch = await getCurrentBranch(cwd, runGit);

  const [statusRes, stagedNumRes, unstagedNumRes] = await Promise.all([
    runGit(["status", "--porcelain=v1", "-u"], cwd, { allowNonZeroExit: true }),
    runGit(["diff", "--cached", "--numstat", "-z"], cwd, { allowNonZeroExit: true }),
    runGit(["diff", "--numstat", "-z"], cwd, { allowNonZeroExit: true }),
  ]);

  const porcelain = parsePorcelainStatus(statusRes.stdout);
  const stagedNum = parseNumstatZ(stagedNumRes.stdout);
  const unstagedNum = parseNumstatZ(unstagedNumRes.stdout);

  const metrics: ChangedFileMetric[] = porcelain.map((entry) => {
    const s = stagedNum.get(entry.path);
    const u = unstagedNum.get(entry.path);
    const sens = classifySensitiveCategories(entry.path);

    let additions = (s?.added ?? 0) + (u?.added ?? 0);
    const deletions = (s?.deleted ?? 0) + (u?.deleted ?? 0);
    const isBinary = Boolean(s?.isBinary || u?.isBinary);

    // Estimate line count for small untracked files
    if (entry.untracked && additions === 0) {
      try {
        const full = path.join(cwd, entry.path);
        const st = fs.statSync(full);
        if (st.isFile() && st.size <= 256 * 1024) {
          const text = fs.readFileSync(full, "utf8");
          if (!text.includes("\0")) {
            additions = text.split(/\r?\n/).length;
          }
        }
      } catch {
        // ignore read error
      }
    }

    return {
      path: entry.path,
      oldPath: entry.oldPath,
      status: entry.effectiveStatus,
      staged: entry.staged,
      unstaged: entry.unstaged,
      untracked: entry.untracked,
      additions,
      deletions,
      isBinary,
      sensitiveCategories: sens.categories,
      riskWeight: sens.weight,
    };
  });

  const mergeAdvice = await checkMergeConflicts(
    cwd,
    input.targetBranch,
    input.sourceRef || "HEAD",
    runGit,
    metrics.map((m) => m.path),
  );

  return buildBlastResult(branch, metrics, mergeAdvice, cwd);
}
