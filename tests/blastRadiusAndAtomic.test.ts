import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { analyzeBlastRadius, checkMergeConflicts } from "../src/core/blastRadius.js";
import { planAtomicCommits } from "../src/core/atomicCommits.js";

const tempDirs: string[] = [];

function makeTempGitRepo(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardgit-test-"));
  tempDirs.push(dir);
  const git = (args: string[]) =>
    execFileSync("git", args, { cwd: dir, stdio: "pipe", encoding: "utf8" });

  git(["init", "-b", "main"]);
  git(["config", "user.email", "tester@example.com"]);
  git(["config", "user.name", "GuardGit Test"]);

  fs.mkdirSync(path.join(dir, "src", "auth"), { recursive: true });
  fs.writeFileSync(path.join(dir, "README.md"), "# Demo Repo\n", "utf8");
  fs.writeFileSync(path.join(dir, "src", "auth", "jwt.ts"), "export const ttl = 3600;\n", "utf8");
  git(["add", "."]);
  git(["commit", "-m", "chore: initial commit"]);

  return dir;
}

after(() => {
  for (const dir of tempDirs) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore cleanup failures on Windows handle lag
    }
  }
});

describe("blastRadius & checkMergeConflicts — Read-Only git merge-tree Dry Run", () => {
  it("detects merge conflicts in memory via git merge-tree without mutating working tree", async () => {
    const dir = makeTempGitRepo();
    const git = (args: string[]) =>
      execFileSync("git", args, { cwd: dir, stdio: "pipe", encoding: "utf8" });

    // Create feature branch and edit jwt.ts
    git(["checkout", "-b", "feat/session-ttl"]);
    fs.writeFileSync(path.join(dir, "src", "auth", "jwt.ts"), "export const ttl = 7200;\n", "utf8");
    git(["add", "src/auth/jwt.ts"]);
    git(["commit", "-m", "feat(auth): extend jwt ttl to 2h"]);

    // Diverge main on the exact same line
    git(["checkout", "main"]);
    fs.writeFileSync(path.join(dir, "src", "auth", "jwt.ts"), "export const ttl = 1800;\n", "utf8");
    git(["add", "src/auth/jwt.ts"]);
    git(["commit", "-m", "fix(auth): shorten jwt ttl to 30m"]);

    // Switch back to feature branch and add an uncommitted doc change
    git(["checkout", "feat/session-ttl"]);
    fs.writeFileSync(path.join(dir, "README.md"), "# Demo Repo\nUpdated docs.\n", "utf8");

    const statusBefore = git(["status", "--porcelain=v1"]);
    const blast = await analyzeBlastRadius({ repoPath: dir, targetBranch: "main" });
    const statusAfter = git(["status", "--porcelain=v1"]);

    // Strictly read-only guarantee
    assert.equal(statusAfter, statusBefore);
    assert.equal(blast.branch, "feat/session-ttl");
    assert.equal(blast.mergeAdvice.checked, true);
    assert.equal(blast.mergeAdvice.hasConflicts, true);
    assert.ok(blast.mergeAdvice.conflictedFiles.includes("src/auth/jwt.ts"));
    assert.equal(blast.mergeAdvice.aheadCount, 1);
    assert.equal(blast.mergeAdvice.behindCount, 1);
  });

  it("reports clean merge dry-run when diverged branches touch disjoint files", async () => {
    const dir = makeTempGitRepo();
    const git = (args: string[]) =>
      execFileSync("git", args, { cwd: dir, stdio: "pipe", encoding: "utf8" });

    git(["checkout", "-b", "feat/docs"]);
    fs.writeFileSync(path.join(dir, "NOTES.md"), "Release notes\n", "utf8");
    git(["add", "NOTES.md"]);
    git(["commit", "-m", "docs: add release notes"]);

    git(["checkout", "main"]);
    fs.writeFileSync(path.join(dir, "CHANGELOG.md"), "v1.0.0\n", "utf8");
    git(["add", "CHANGELOG.md"]);
    git(["commit", "-m", "docs: add changelog"]);

    git(["checkout", "feat/docs"]);
    const merge = await checkMergeConflicts(dir, "main", "HEAD");
    assert.equal(merge.checked, true);
    assert.equal(merge.hasConflicts, false);
    assert.equal(merge.conflictedFiles.length, 0);
    assert.ok(merge.treeOid && /^[0-9a-f]{40}$/i.test(merge.treeOid));
  });

  it("scores sensitive surfaces (auth, migrations, CI) and builds directory heatmap", async () => {
    const blast = await analyzeBlastRadius({
      files: [
        { path: "src/auth/rbac.ts", status: "M", additions: 80, deletions: 20 },
        { path: "db/migrations/20261125_add_tokens.sql", status: "A", additions: 60, deletions: 0 },
        { path: ".github/workflows/deploy.yml", status: "M", additions: 25, deletions: 5 },
        { path: "src/ui/Button.tsx", status: "M", additions: 12, deletions: 4 },
      ],
    });

    assert.ok(blast.score >= 50);
    assert.ok(blast.sensitiveHits.auth_security.includes("src/auth/rbac.ts"));
    assert.ok(blast.sensitiveHits.database_migration.includes("db/migrations/20261125_add_tokens.sql"));
    assert.ok(blast.sensitiveHits.ci_cd_infra.includes(".github/workflows/deploy.yml"));
    assert.equal(blast.heatmap.length, 4);
    assert.ok(blast.heatmap[0].riskScore >= blast.heatmap[blast.heatmap.length - 1].riskScore);
  });
});

describe("planAtomicCommits — Logical Conventional Commit Splitter", () => {
  it("groups mixed files into ordered Conventional Commits and withholds risky secrets/artifacts", async () => {
    const plan = await planAtomicCommits({
      files: [
        { path: ".env", status: "U", content: "SECRET=123" },
        { path: "dist/app.js", status: "A", content: "console.log(1);" },
        { path: "package.json", status: "M", additions: 4, deletions: 2 },
        { path: ".github/workflows/ci.yml", status: "A", additions: 35, deletions: 0 },
        { path: "tsconfig.json", status: "M", additions: 2, deletions: 1 },
        { path: "src/core/parser.ts", status: "A", additions: 120, deletions: 0 },
        { path: "tests/parser.test.ts", status: "A", additions: 90, deletions: 0 },
        { path: "README.md", status: "M", additions: 18, deletions: 3 },
      ],
    });

    assert.equal(plan.excludedRiskyFiles.length, 2);
    assert.ok(plan.excludedRiskyFiles.some((f) => f.path === ".env"));
    assert.ok(plan.excludedRiskyFiles.some((f) => f.path === "dist/app.js"));

    assert.equal(plan.plannedFileCount, 6);
    assert.ok(plan.groups.length >= 5);

    // Ordering: build -> ci -> config -> feat -> test -> docs
    const types = plan.groups.map((g) => g.type);
    assert.ok(types.indexOf("build") < types.indexOf("feat"));
    assert.ok(types.indexOf("feat") < types.indexOf("test"));
    assert.ok(types.indexOf("test") < types.indexOf("docs"));

    for (const g of plan.groups) {
      assert.ok(g.suggestedMessage.includes(": "));
      assert.ok(g.stageCommands[0].startsWith("git add -- "));
    }
  });
});
