import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface GitExecOptions {
  maxBuffer?: number;
  timeoutMs?: number;
  allowNonZeroExit?: boolean;
}

export interface GitExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export type GitRunner = (
  args: string[],
  cwd: string,
  options?: GitExecOptions,
) => Promise<GitExecResult>;

export const DEFAULT_GIT_MAX_BUFFER = 20 * 1024 * 1024;
export const DEFAULT_GIT_TIMEOUT_MS = 15_000;

export function createExecGitRunner(): GitRunner {
  return async (
    args: string[],
    cwd: string,
    options: GitExecOptions = {},
  ): Promise<GitExecResult> => {
    try {
      const { stdout, stderr } = await execFileAsync("git", args, {
        cwd,
        maxBuffer: options.maxBuffer ?? DEFAULT_GIT_MAX_BUFFER,
        timeout: options.timeoutMs ?? DEFAULT_GIT_TIMEOUT_MS,
        windowsHide: true,
        encoding: "utf8",
      });
      return {
        stdout: stdout ?? "",
        stderr: stderr ?? "",
        exitCode: 0,
      };
    } catch (err: unknown) {
      const e = err as {
        stdout?: string | Buffer;
        stderr?: string | Buffer;
        code?: number | string;
        message?: string;
      };
      const stdout = typeof e.stdout === "string" ? e.stdout : e.stdout?.toString("utf8") ?? "";
      const stderr = typeof e.stderr === "string" ? e.stderr : e.stderr?.toString("utf8") ?? e.message ?? "";
      const exitCode = typeof e.code === "number" ? e.code : 1;
      if (options.allowNonZeroExit) {
        return { stdout, stderr, exitCode };
      }
      throw new Error(`git ${args.join(" ")} failed (code ${exitCode}): ${stderr.trim() || "unknown error"}`);
    }
  };
}

export function normalizeRelPath(input: string): string {
  return String(input || "")
    .replace(/\\/g, "/")
    .replace(/^\.\//, "")
    .replace(/^\/+/, "");
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export interface NumstatEntry {
  path: string;
  oldPath: string | null;
  added: number;
  deleted: number;
  isBinary: boolean;
}

export function parseNumstatZ(output: string): Map<string, NumstatEntry> {
  const map = new Map<string, NumstatEntry>();
  if (!output) return map;
  const tokens = output.split("\0");
  let i = 0;
  while (i < tokens.length) {
    const tok = tokens[i++];
    if (!tok) continue;
    const tab1 = tok.indexOf("\t");
    if (tab1 === -1) continue;
    const tab2 = tok.indexOf("\t", tab1 + 1);
    if (tab2 === -1) continue;

    const addedRaw = tok.slice(0, tab1);
    const deletedRaw = tok.slice(tab1 + 1, tab2);
    const rest = tok.slice(tab2 + 1);

    let filePath = rest;
    let oldPath: string | null = null;
    if (rest === "") {
      oldPath = tokens[i++] || "";
      filePath = tokens[i++] || oldPath;
    }
    const normPath = normalizeRelPath(filePath);
    if (!normPath) continue;
    const isBinary = addedRaw === "-" || deletedRaw === "-";
    map.set(normPath, {
      path: normPath,
      oldPath: oldPath ? normalizeRelPath(oldPath) : null,
      added: isBinary ? 0 : parseInt(addedRaw, 10) || 0,
      deleted: isBinary ? 0 : parseInt(deletedRaw, 10) || 0,
      isBinary,
    });
  }
  return map;
}

export interface NameStatusEntry {
  status: string;
  oldPath: string | null;
  path: string;
}

export function parseNameStatusZ(output: string): NameStatusEntry[] {
  const entries: NameStatusEntry[] = [];
  if (!output) return entries;
  const tokens = output.split("\0");
  let i = 0;
  while (i < tokens.length) {
    const statusRaw = tokens[i++];
    if (!statusRaw) continue;
    const code = statusRaw[0];
    if (code === "R" || code === "C") {
      const oldPath = normalizeRelPath(tokens[i++] || "");
      const newPath = normalizeRelPath(tokens[i++] || "");
      if (newPath) {
        entries.push({ status: code, oldPath, path: newPath });
      }
    } else {
      const filePath = normalizeRelPath(tokens[i++] || "");
      if (filePath) {
        entries.push({ status: code, oldPath: null, path: filePath });
      }
    }
  }
  return entries;
}

export interface PorcelainEntry {
  indexStatus: string;
  worktreeStatus: string;
  path: string;
  oldPath: string | null;
  staged: boolean;
  unstaged: boolean;
  untracked: boolean;
  effectiveStatus: string;
}

function unquoteGitPath(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed
      .slice(1, -1)
      .replace(/\\"/g, '"')
      .replace(/\\\\/g, "\\");
  }
  return trimmed;
}

export function parsePorcelainStatus(output: string): PorcelainEntry[] {
  const entries: PorcelainEntry[] = [];
  if (!output) return entries;

  const lines = output.split(/\r?\n/);
  for (const line of lines) {
    if (line.length < 4) continue;
    const x = line[0];
    const y = line[1];
    if (line[2] !== " ") continue;

    const rest = line.slice(3);
    let filePath = rest;
    let oldPath: string | null = null;

    if ((x === "R" || x === "C" || y === "R" || y === "C") && rest.includes(" -> ")) {
      const idx = rest.indexOf(" -> ");
      oldPath = normalizeRelPath(unquoteGitPath(rest.slice(0, idx)));
      filePath = normalizeRelPath(unquoteGitPath(rest.slice(idx + 4)));
    } else {
      filePath = normalizeRelPath(unquoteGitPath(rest));
    }

    if (!filePath) continue;

    const untracked = x === "?" && y === "?";
    const staged = !untracked && x !== " " && x !== "!";
    const unstaged = !untracked && y !== " " && y !== "!";
    const effectiveStatus = untracked ? "U" : staged ? x : y;

    entries.push({
      indexStatus: x,
      worktreeStatus: y,
      path: filePath,
      oldPath,
      staged,
      unstaged,
      untracked,
      effectiveStatus,
    });
  }
  return entries;
}

export async function isGitRepository(cwd: string, runGit: GitRunner): Promise<boolean> {
  const res = await runGit(["rev-parse", "--is-inside-work-tree"], cwd, {
    allowNonZeroExit: true,
  });
  return res.exitCode === 0 && res.stdout.trim() === "true";
}

export async function getCurrentBranch(cwd: string, runGit: GitRunner): Promise<string> {
  const res = await runGit(["rev-parse", "--abbrev-ref", "HEAD"], cwd, {
    allowNonZeroExit: true,
  });
  if (res.exitCode === 0 && res.stdout.trim()) {
    return res.stdout.trim();
  }
  const sym = await runGit(["symbolic-ref", "--short", "HEAD"], cwd, {
    allowNonZeroExit: true,
  });
  return sym.exitCode === 0 && sym.stdout.trim() ? sym.stdout.trim() : "HEAD";
}
