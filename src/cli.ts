#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import {
  analyzeBlastRadius,
  formatBytes,
  guardScan,
  planAtomicCommits,
  structuralJsonDiff,
} from "./core/index.js";
import { SERVER_VERSION, startStdioServer } from "./server.js";

function printHelp(): void {
  const help = `GuardGit MCP v${SERVER_VERSION} — Pre-Commit DevSecOps Safety Net & Structural Diff Cockpit

Usage:
  guardgit-mcp [serve | --stdio]              Start the SEP-1865 MCP stdio server (default)
  guardgit-mcp scan [repoPath] [options]      Run pre-commit secret, blob, and artifact guard
  guardgit-mcp diff <old.json> <new.json>     Run semantic structural JSON diff on two files
  guardgit-mcp diff --repo <dir> --file <p>   Diff a tracked JSON file against HEAD (or --base)
  guardgit-mcp blast [repoPath] [options]     Analyze blast radius + read-only git merge-tree dry-run
  guardgit-mcp plan [repoPath] [--json]       Split dirty files into atomic Conventional Commits

Options:
  --strict           Exit non-zero (code 2) when scan verdict is BLOCK
  --fail-on-warn     Exit non-zero (code 1) when scan verdict is WARN or BLOCK
  --max-mb <num>     Large blob threshold in MB (default: 1)
  --target <branch>  Target branch for git merge-tree dry-run
  --base <ref>       Base Git ref for JSON diff (default: HEAD)
  --json             Output structured JSON
  -v, --version      Show version
  -h, --help         Show this help text
`;
  process.stdout.write(help);
}

function getFlagValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  const prefix = `${flag}=`;
  const eq = args.find((a) => a.startsWith(prefix));
  return eq ? eq.slice(prefix.length) : undefined;
}

function positionalArgs(args: string[]): string[] {
  const valueFlags = new Set(["--max-mb", "--target", "--base", "--repo", "--file"]);
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (valueFlags.has(a)) {
      i++;
      continue;
    }
    if (a.startsWith("-")) continue;
    out.push(a);
  }
  return out;
}

async function runCli(argv: string[]): Promise<void> {
  const cmd = argv[0];

  if (!cmd || cmd === "serve" || cmd === "--stdio") {
    await startStdioServer();
    return;
  }

  if (cmd === "-h" || cmd === "--help" || cmd === "help") {
    printHelp();
    return;
  }

  if (cmd === "-v" || cmd === "--version") {
    process.stdout.write(`${SERVER_VERSION}\n`);
    return;
  }

  const rest = argv.slice(1);
  const asJson = rest.includes("--json");
  const pos = positionalArgs(rest);

  if (cmd === "scan") {
    const repoPath = pos[0] || process.cwd();
    const maxMbRaw = getFlagValue(rest, "--max-mb");
    const threshold = maxMbRaw ? Math.round(parseFloat(maxMbRaw) * 1024 * 1024) : undefined;
    const result = await guardScan({
      repoPath,
      largeFileThresholdBytes: Number.isFinite(threshold) ? threshold : undefined,
    });

    if (asJson) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(
        `GuardGit Scan | Verdict: ${result.verdict} | Risk Score: ${result.riskScore}/100 | Files: ${result.summary.filesScanned}\n`,
      );
      if (result.findings.length === 0) {
        process.stdout.write("No secrets, oversized blobs, or risky artifacts detected.\n");
      } else {
        for (const f of result.findings) {
          const loc = f.line ? `${f.path}:${f.line}` : f.path;
          const snip = f.maskedSnippet ? ` (${f.maskedSnippet})` : "";
          process.stdout.write(`  [${f.severity.toUpperCase()}] ${f.title} — ${loc}${snip}\n`);
          if (f.remediationCommands[0]) {
            process.stdout.write(`      Fix: ${f.remediationCommands[0]}\n`);
          }
        }
      }
    }

    if (rest.includes("--strict") && result.verdict === "BLOCK") {
      process.exitCode = 2;
    } else if (rest.includes("--fail-on-warn") && result.verdict !== "PASS") {
      process.exitCode = result.verdict === "BLOCK" ? 2 : 1;
    }
    return;
  }

  if (cmd === "diff") {
    const repoFlag = getFlagValue(rest, "--repo");
    const fileFlag = getFlagValue(rest, "--file");
    const baseFlag = getFlagValue(rest, "--base") || "HEAD";

    let result;
    if (fileFlag) {
      result = await structuralJsonDiff({
        repoPath: repoFlag || process.cwd(),
        filePath: fileFlag,
        baseRef: baseFlag,
      });
    } else if (pos.length >= 2) {
      const oldPath = path.resolve(pos[0]);
      const newPath = path.resolve(pos[1]);
      const oldJson = fs.readFileSync(oldPath, "utf8");
      const newJson = fs.readFileSync(newPath, "utf8");
      result = await structuralJsonDiff({
        oldJson,
        newJson,
        filePath: path.basename(newPath),
      });
    } else {
      process.stderr.write("Usage: guardgit-mcp diff <old.json> <new.json> OR --repo <dir> --file <relPath>\n");
      process.exitCode = 1;
      return;
    }

    if (asJson) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(
        `${result.textSummary}\nSummary: +${result.stats.added} -${result.stats.removed} ~${result.stats.modified} | Breaking: ${result.stats.breakingCount} (${formatBytes(result.oldBytes)} -> ${formatBytes(result.newBytes)})\n`,
      );
    }
    return;
  }

  if (cmd === "blast") {
    const repoPath = pos[0] || process.cwd();
    const targetBranch = getFlagValue(rest, "--target");
    const result = await analyzeBlastRadius({ repoPath, targetBranch });

    if (asJson) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(
        `GuardGit Blast Radius | Band: ${result.band} (${result.score}/100) | Branch: ${result.branch}\n` +
          `Files: ${result.totals.filesChanged} (+${result.totals.additions}/-${result.totals.deletions}) across ${result.totals.directoriesTouched} directories\n` +
          `Merge Dry-Run (${result.mergeAdvice.targetBranch}): ${result.mergeAdvice.note}\n`,
      );
      for (const h of result.heatmap) {
        process.stdout.write(
          `  ${h.directory.padEnd(28)} risk=${String(h.riskScore).padStart(3)} files=${h.fileCount} (+${h.additions}/-${h.deletions})\n`,
        );
      }
    }
    return;
  }

  if (cmd === "plan") {
    const repoPath = pos[0] || process.cwd();
    const result = await planAtomicCommits({ repoPath });
    if (asJson) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(`${result.summaryNote}\n`);
      for (const g of result.groups) {
        process.stdout.write(`\n${g.order}. ${g.suggestedMessage}\n`);
        process.stdout.write(`   ${g.rationale}\n`);
        for (const f of g.files) {
          process.stdout.write(`   - [${f.status}] ${f.path} (+${f.additions}/-${f.deletions})\n`);
        }
      }
    }
    return;
  }

  process.stderr.write(`Unknown command: ${cmd}\nRun "guardgit-mcp --help" for usage.\n`);
  process.exitCode = 1;
}

runCli(process.argv.slice(2)).catch((err) => {
  process.stderr.write(`GuardGit error: ${(err as Error).message}\n`);
  process.exit(1);
});
