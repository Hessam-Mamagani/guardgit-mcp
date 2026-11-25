import fs from "node:fs";
import path from "node:path";
import {
  createExecGitRunner,
  formatBytes,
  getCurrentBranch,
  type GitRunner,
  isGitRepository,
  normalizeRelPath,
  parsePorcelainStatus,
} from "./gitRunner.js";
import type {
  GuardFileInput,
  GuardFinding,
  GuardScanInput,
  GuardScanResult,
  GuardVerdict,
  IgnoreOption,
  Severity,
} from "./types.js";

const DEFAULT_LARGE_FILE_BYTES = 1024 * 1024; // 1 MiB
const MAX_CONTENT_SCAN_BYTES = 512 * 1024; // 512 KiB per file

const SAFE_ENV_TEMPLATES = new Set([
  ".env.example",
  ".env.sample",
  ".env.template",
  ".env.defaults",
  ".env.schema",
  ".env.dist",
]);

const SECRET_FILE_BASENAMES = new Set([
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  "credentials.json",
  "serviceaccountkey.json",
  "service-account.json",
  "secrets.json",
  "secrets.yaml",
  "secrets.yml",
  "appsettings.secrets.json",
  ".pypirc",
  ".netrc",
  ".htpasswd",
]);

const SECRET_EXTENSIONS = new Set([
  ".pem",
  ".key",
  ".p12",
  ".pfx",
  ".jks",
  ".keystore",
  ".ppk",
]);

const OS_JUNK_BASENAMES = new Set([
  ".ds_store",
  "thumbs.db",
  "desktop.ini",
]);

const TEMP_EXTENSIONS = new Set([
  ".log",
  ".tmp",
  ".bak",
  ".orig",
  ".swp",
  ".swo",
]);

const PACKAGE_ARTIFACT_EXTENSIONS = new Set([
  ".vsix",
  ".nupkg",
  ".apk",
  ".ipa",
  ".whl",
  ".jar",
]);

const DATABASE_EXTENSIONS = new Set([
  ".db",
  ".sqlite",
  ".sqlite3",
  ".dump",
]);

const GENERATED_DIR_RULES: Array<{
  dir: string;
  severity: Severity;
  reason: string;
  badge: string;
}> = [
  { dir: "node_modules", severity: "high", badge: "Deps", reason: "Installed Node.js dependencies directory" },
  { dir: ".venv", severity: "high", badge: "Venv", reason: "Python virtual environment directory" },
  { dir: "venv", severity: "high", badge: "Venv", reason: "Python virtual environment directory" },
  { dir: "__pycache__", severity: "medium", badge: "Cache", reason: "Python bytecode cache directory" },
  { dir: ".next", severity: "high", badge: "Build", reason: "Next.js build output directory" },
  { dir: ".nuxt", severity: "high", badge: "Build", reason: "Nuxt build output directory" },
  { dir: ".turbo", severity: "medium", badge: "Cache", reason: "Turborepo build cache directory" },
  { dir: ".cache", severity: "medium", badge: "Cache", reason: "Local build cache directory" },
  { dir: "dist", severity: "high", badge: "Build", reason: "Compiled distribution build output" },
  { dir: "build", severity: "high", badge: "Build", reason: "Compiled build output directory" },
  { dir: "coverage", severity: "medium", badge: "Report", reason: "Generated test coverage output" },
  { dir: "tmp", severity: "medium", badge: "Scratch", reason: "Temporary scratch folder" },
  { dir: "temp", severity: "medium", badge: "Scratch", reason: "Temporary scratch folder" },
  { dir: "scratch", severity: "medium", badge: "Scratch", reason: "Local scratch folder" },
];

interface SecretPatternRule {
  ruleId: string;
  title: string;
  severity: Severity;
  regex: RegExp;
  captureGroup?: number;
  reason: string;
}

const SECRET_PATTERNS: SecretPatternRule[] = [
  {
    ruleId: "secret.private_key_block",
    title: "Private Key Material",
    severity: "critical",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    reason: "Embedded PEM or OpenSSH private key block detected in source or diff.",
  },
  {
    ruleId: "secret.aws_access_key",
    title: "AWS Access Key ID",
    severity: "critical",
    regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    reason: "AWS IAM access key identifier detected.",
  },
  {
    ruleId: "secret.aws_secret_key",
    title: "AWS Secret Access Key",
    severity: "critical",
    regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    captureGroup: 1,
    reason: "AWS secret access key assignment detected.",
  },
  {
    ruleId: "secret.openai_api_key",
    title: "OpenAI API Key",
    severity: "critical",
    regex: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g,
    reason: "OpenAI API secret key detected.",
  },
  {
    ruleId: "secret.anthropic_api_key",
    title: "Anthropic API Key",
    severity: "critical",
    regex: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{24,}\b/g,
    reason: "Anthropic Claude API key detected.",
  },
  {
    ruleId: "secret.github_token",
    title: "GitHub Personal or OAuth Token",
    severity: "critical",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b/g,
    reason: "GitHub access token detected.",
  },
  {
    ruleId: "secret.stripe_live_key",
    title: "Stripe Live Secret or Webhook Key",
    severity: "critical",
    regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b|\bwhsec_[A-Za-z0-9]{24,}\b/g,
    reason: "Stripe live credential or webhook signing secret detected.",
  },
  {
    ruleId: "secret.cloudflare_token",
    title: "Cloudflare API Token",
    severity: "critical",
    regex: /(?:cloudflare|cf)[_-]?(?:api[_-]?)?(?:token|key|secret)\s*[:=]\s*["']?([A-Za-z0-9_-]{32,})["']?/gi,
    captureGroup: 1,
    reason: "Cloudflare API token assignment detected.",
  },
  {
    ruleId: "secret.google_api_key",
    title: "Google Cloud / Gemini API Key",
    severity: "high",
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    reason: "Google Cloud, Firebase, or Gemini API key detected.",
  },
  {
    ruleId: "secret.slack_token",
    title: "Slack API Token",
    severity: "critical",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    reason: "Slack bot or user token detected.",
  },
  {
    ruleId: "secret.sendgrid_key",
    title: "SendGrid API Key",
    severity: "critical",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    reason: "SendGrid API key detected.",
  },
  {
    ruleId: "secret.npm_token",
    title: "npm Registry Auth Token",
    severity: "critical",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    reason: "npm publish or access token detected.",
  },
  {
    ruleId: "secret.npmrc_auth",
    title: "Registry Auth Token in Config",
    severity: "critical",
    regex: /(?:_authToken|_auth|\/\/[^/\s]+\/:_auth)\s*=\s*([^\s"'#]{10,})/gi,
    captureGroup: 1,
    reason: "Plaintext registry authentication token detected.",
  },
  {
    ruleId: "secret.jwt_token",
    title: "Hardcoded JSON Web Token (JWT)",
    severity: "high",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    reason: "Signed JWT bearer token appears hardcoded in tracked content.",
  },
  {
    ruleId: "secret.database_url",
    title: "Database Connection String with Credentials",
    severity: "critical",
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^:\s/@"']+:([^@\s/"']{6,})@[^\s"'<>]+/gi,
    captureGroup: 1,
    reason: "Connection string includes embedded password credentials.",
  },
];

const PLACEHOLDER_RE =
  /(?:example|changeme|your[_-]|placeholder|dummy|sample|test[_-]?key|fake|redacted|replace[_-]?me|xxxxx|\*{4,}|\$\{[^}]+\}|process\.env)/i;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_ONLY_RE = /^[0-9a-f]{32,64}$/i;

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 4,
};

export function shannonEntropy(value: string): number {
  if (!value) return 0;
  const freq = new Map<string, number>();
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = value.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function maskSecret(raw: string): string {
  const clean = raw.trim();
  if (clean.length <= 8) return "***REDACTED***";
  if (clean.length <= 14) {
    return `${clean.slice(0, 2)}***${clean.slice(-2)}`;
  }
  return `${clean.slice(0, 4)}***...***${clean.slice(-4)}`;
}

function countCharClasses(value: string): number {
  let classes = 0;
  if (/[a-z]/.test(value)) classes++;
  if (/[A-Z]/.test(value)) classes++;
  if (/[0-9]/.test(value)) classes++;
  if (/[^a-zA-Z0-9]/.test(value)) classes++;
  return classes;
}

export function normalizeGitignorePattern(rawPattern: string): string {
  return String(rawPattern || "")
    .trim()
    .replace(/\\/g, "/")
    .replace(/^\.\//, "");
}

export function buildIgnoreOptionsForPath(
  relPath: string,
  isDirectory = false,
): IgnoreOption[] {
  const norm = normalizeRelPath(relPath).replace(/\/+$/, "");
  if (!norm) return [];

  const options: IgnoreOption[] = [];
  const seen = new Set<string>();
  const addOpt = (
    pattern: string,
    label: string,
    description: string,
    kind: IgnoreOption["kind"],
  ) => {
    const clean = normalizeGitignorePattern(pattern);
    if (!clean || seen.has(clean)) return;
    seen.add(clean);
    options.push({ pattern: clean, label, description, kind });
  };

  if (isDirectory) {
    addOpt(
      `${norm}/`,
      `Ignore folder: ${norm}/`,
      "Ignore this directory and everything inside it",
      "folder",
    );
    const parts = norm.split("/");
    if (parts.length > 1) {
      const topDir = `${parts[0]}/`;
      addOpt(
        topDir,
        `Ignore top folder: ${topDir}`,
        "Ignore the entire top-level directory",
        "folder",
      );
    }
    return options;
  }

  const parts = norm.split("/");
  const baseName = parts[parts.length - 1];
  const ext = path.extname(baseName);

  addOpt(
    norm,
    `Ignore exact file: ${norm}`,
    "Ignore only this specific file path",
    "file",
  );

  if (parts.length > 1) {
    const parentDir = `${parts.slice(0, -1).join("/")}/`;
    addOpt(
      parentDir,
      `Ignore folder: ${parentDir}`,
      `Ignore all files inside ${parentDir}`,
      "folder",
    );
    addOpt(
      baseName,
      `Ignore filename anywhere: ${baseName}`,
      `Ignore any file named "${baseName}" in any directory`,
      "basename",
    );
  }

  if (ext && ext !== baseName) {
    addOpt(
      `*${ext}`,
      `Ignore file type: *${ext}`,
      `Ignore all *${ext} files across the repository`,
      "extension",
    );
  }

  return options;
}

function findMatchingDirSegment(relPath: string, targetDirLower: string): string | null {
  const parts = normalizeRelPath(relPath).split("/");
  for (let i = 0; i < parts.length - 1; i++) {
    if (parts[i].toLowerCase() === targetDirLower) {
      return `${parts.slice(0, i + 1).join("/")}/`;
    }
  }
  return null;
}

function buildRemediationCommands(
  relPath: string,
  gitignoreRule: string,
  isFolderRule: boolean,
  isContentSecret: boolean,
): string[] {
  if (isContentSecret) {
    return [
      `git restore --staged -- "${relPath}"`,
      `# Remove hardcoded secret from "${relPath}", load via environment variable, and rotate the exposed credential.`,
    ];
  }
  const untrackTarget = isFolderRule ? gitignoreRule.replace(/\/+$/, "") : relPath;
  return [
    `git rm --cached ${isFolderRule ? "-r " : ""}--ignore-unmatch -- "${untrackTarget}"`,
    `echo "${gitignoreRule}" >> .gitignore`,
  ];
}

function getFileSizeSafe(cwd: string | undefined, relPath: string): number | null {
  if (!cwd) return null;
  try {
    const st = fs.statSync(path.join(cwd, relPath));
    return st.isFile() ? st.size : null;
  } catch {
    return null;
  }
}

function readDiskContentSafe(cwd: string | undefined, relPath: string): { text?: string; isBinary?: boolean; sizeBytes?: number } {
  if (!cwd) return {};
  try {
    const full = path.join(cwd, relPath);
    const st = fs.statSync(full);
    if (!st.isFile()) return {};
    if (st.size > MAX_CONTENT_SCAN_BYTES) {
      // Sample first 4096 bytes for NUL binary detection only
      const fd = fs.openSync(full, "r");
      try {
        const buf = Buffer.alloc(Math.min(4096, st.size));
        const read = fs.readSync(fd, buf, 0, buf.length, 0);
        const isBinary = buf.subarray(0, read).includes(0);
        return { sizeBytes: st.size, isBinary };
      } finally {
        fs.closeSync(fd);
      }
    }
    const buf = fs.readFileSync(full);
    const isBinary = buf.subarray(0, Math.min(4096, buf.length)).includes(0);
    return {
      sizeBytes: st.size,
      isBinary,
      text: isBinary ? undefined : buf.toString("utf8"),
    };
  } catch {
    return {};
  }
}

function classifyPathHygiene(
  file: GuardFileInput,
  largeFileThresholdBytes: number,
  cwd?: string,
): GuardFinding[] {
  const findings: GuardFinding[] = [];
  const relPath = normalizeRelPath(file.path);
  if (!relPath) return findings;

  const status = String(file.status || "M").toUpperCase();
  if (status === "D") return findings;

  const isNewOrUntracked = status === "A" || status === "U" || status === "?";
  const parts = relPath.split("/");
  const baseName = parts[parts.length - 1];
  const baseLower = baseName.toLowerCase();
  const extLower = path.extname(baseLower);

  const pushFinding = (
    ruleId: string,
    severity: Severity,
    category: GuardFinding["category"],
    badge: string,
    title: string,
    reason: string,
    gitignoreRule: string,
    isFolderRule: boolean,
    sizeBytes?: number,
  ) => {
    findings.push({
      id: `${ruleId}:${relPath}`,
      ruleId,
      severity,
      category,
      badge,
      path: relPath,
      title,
      reason,
      sizeBytes,
      gitignoreRule,
      isFolderRule,
      remediationCommands: buildRemediationCommands(relPath, gitignoreRule, isFolderRule, false),
      ignoreOptions: buildIgnoreOptionsForPath(
        isFolderRule ? gitignoreRule.replace(/\/+$/, "") : relPath,
        isFolderRule,
      ),
    });
  };

  // 1. Private folders
  const privateDir = findMatchingDirSegment(relPath, ".private");
  if (privateDir) {
    pushFinding(
      "hygiene.private_folder",
      "critical",
      "credential_file",
      "Private",
      "Private Local Folder Tracked",
      "Private local folders (.private/) should never be committed to Git history.",
      privateDir,
      true,
    );
    return findings;
  }

  // 2. Environment files (.env, .env.local, .env.production, etc.)
  if (
    (baseLower === ".env" || baseLower.startsWith(".env.")) &&
    !SAFE_ENV_TEMPLATES.has(baseLower)
  ) {
    pushFinding(
      "hygiene.env_file",
      "critical",
      "credential_file",
      "Env Secret",
      "Environment File Contains Runtime Secrets",
      "Live .env files often hold API keys, database passwords, and signing secrets.",
      baseLower === ".env" ? ".env" : relPath,
      false,
    );
  }

  // 3. Private keys, certs, credential JSONs
  if (
    SECRET_FILE_BASENAMES.has(baseLower) ||
    SECRET_EXTENSIONS.has(extLower) ||
    /^firebase-adminsdk.*\.json$/i.test(baseName) ||
    /service[-_]?account.*\.json$/i.test(baseName)
  ) {
    pushFinding(
      "hygiene.credential_file",
      "critical",
      "credential_file",
      "Credential",
      "Private Key or Credential File",
      "Keystore, SSH key, TLS private key, or cloud service account file detected.",
      extLower && SECRET_EXTENSIONS.has(extLower) ? `*${extLower}` : relPath,
      false,
    );
  }

  // 4. Package artifacts (.vsix, .nupkg, .apk, .ipa, .whl, .jar)
  if (PACKAGE_ARTIFACT_EXTENSIONS.has(extLower)) {
    pushFinding(
      "hygiene.package_artifact",
      "high",
      "artifact",
      "Package",
      `Compiled Package Artifact (${extLower})`,
      `Binary distribution packages (${extLower}) bloat Git history and belong in CI release artifacts.`,
      `*${extLower}`,
      false,
    );
  }

  // 5. Generated / dependency directories
  for (const rule of GENERATED_DIR_RULES) {
    const matchedDir = findMatchingDirSegment(relPath, rule.dir);
    if (matchedDir) {
      pushFinding(
        `hygiene.dir_${rule.dir.replace(/[^a-z0-9]/g, "")}`,
        rule.severity,
        "artifact",
        rule.badge,
        `Generated Directory (${rule.dir}/)`,
        rule.reason,
        matchedDir,
        true,
      );
      break;
    }
  }

  // 6. Database files
  if (
    DATABASE_EXTENSIONS.has(extLower) ||
    baseLower.endsWith(".db-wal") ||
    baseLower.endsWith(".db-shm") ||
    baseLower.endsWith(".sql.gz")
  ) {
    pushFinding(
      "hygiene.local_database",
      "high",
      "database",
      "Database",
      "Local Database or Dump File",
      "SQLite/local database files or raw SQL dumps can leak PII and bloat Git storage.",
      extLower ? `*${extLower}` : relPath,
      false,
    );
  }

  // 7. OS junk & temp/log files
  if (OS_JUNK_BASENAMES.has(baseLower)) {
    pushFinding(
      "hygiene.os_junk",
      "medium",
      "junk",
      "OS Junk",
      "Operating System Metadata File",
      "OS metadata files pollute repository diffs across platforms.",
      baseName,
      false,
    );
  } else if (
    isNewOrUntracked &&
    (TEMP_EXTENSIONS.has(extLower) ||
      baseLower.endsWith("~") ||
      baseLower.startsWith("npm-debug.log") ||
      baseLower.startsWith("yarn-error.log"))
  ) {
    pushFinding(
      "hygiene.temp_log",
      "medium",
      "junk",
      extLower === ".log" ? "Log" : "Temp",
      "Temporary or Log File",
      "Transient log or editor backup file should not be committed.",
      extLower ? `*${extLower}` : relPath,
      false,
    );
  }

  // 8. Large / binary blobs
  const sizeBytes =
    typeof file.sizeBytes === "number"
      ? file.sizeBytes
      : typeof file.content === "string"
        ? Buffer.byteLength(file.content, "utf8")
        : getFileSizeSafe(cwd, relPath) ?? undefined;

  if (
    largeFileThresholdBytes > 0 &&
    typeof sizeBytes === "number" &&
    sizeBytes >= largeFileThresholdBytes
  ) {
    const severity: Severity = sizeBytes >= 5 * 1024 * 1024 ? "high" : "medium";
    pushFinding(
      "hygiene.large_blob",
      severity,
      "large_blob",
      formatBytes(sizeBytes),
      `Large Blob (${formatBytes(sizeBytes)})`,
      `File exceeds configured ${formatBytes(largeFileThresholdBytes)} pre-commit blob threshold and may bloat Git history.`,
      relPath,
      false,
      sizeBytes,
    );
  } else if (file.isBinary && isNewOrUntracked && !PACKAGE_ARTIFACT_EXTENSIONS.has(extLower)) {
    const allowedAssetExts = new Set([".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".woff", ".woff2", ".pdf"]);
    if (!allowedAssetExts.has(extLower)) {
      pushFinding(
        "hygiene.binary_blob",
        "medium",
        "binary",
        "Binary",
        "Unexpected Binary File",
        "Newly added binary blob detected; verify it is an intentional repository asset or move to Git LFS.",
        relPath,
        false,
        sizeBytes,
      );
    }
  }

  return findings;
}

function scanTextLinesForSecrets(
  relPath: string,
  lines: Array<{ lineNumber: number; text: string }>,
): GuardFinding[] {
  const findings: GuardFinding[] = [];
  const seenKeys = new Set<string>();

  for (const { lineNumber, text } of lines) {
    if (!text || text.length > 20_000) continue;

    // 1. Named token / key patterns
    for (const rule of SECRET_PATTERNS) {
      rule.regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = rule.regex.exec(text)) !== null) {
        const rawSecret =
          rule.captureGroup && match[rule.captureGroup]
            ? match[rule.captureGroup]
            : match[0];

        if (PLACEHOLDER_RE.test(rawSecret) && rule.ruleId !== "secret.private_key_block") {
          continue;
        }

        const dedupKey = `${rule.ruleId}:${relPath}:${lineNumber}`;
        if (seenKeys.has(dedupKey)) continue;
        seenKeys.add(dedupKey);

        findings.push({
          id: dedupKey,
          ruleId: rule.ruleId,
          severity: rule.severity,
          category: "secret",
          badge: "Secret",
          path: relPath,
          line: lineNumber,
          title: rule.title,
          reason: rule.reason,
          maskedSnippet: maskSecret(rawSecret),
          gitignoreRule: relPath,
          isFolderRule: false,
          remediationCommands: buildRemediationCommands(relPath, relPath, false, true),
          ignoreOptions: buildIgnoreOptionsForPath(relPath, false),
        });
      }
    }

    // 2. High-entropy assigned secret detector
    const entropyAssignRe =
      /(?:secret|token|api[_-]?key|apikey|password|passwd|private[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?key|signing[_-]?key)\s*[:=]\s*["'`]([^"'`\s]{20,160})["'`]/gi;
    let m: RegExpExecArray | null;
    while ((m = entropyAssignRe.exec(text)) !== null) {
      const candidate = m[1];
      if (!candidate) continue;
      if (PLACEHOLDER_RE.test(candidate)) continue;
      if (UUID_RE.test(candidate) || HEX_ONLY_RE.test(candidate)) continue;
      if (/^https?:\/\//i.test(candidate)) continue;

      const entropy = shannonEntropy(candidate);
      const charClasses = countCharClasses(candidate);
      if (entropy >= 4.2 && charClasses >= 3) {
        // Avoid duplicating an already caught named secret on the same line
        const hasSpecificOnLine = findings.some(
          (f) => f.path === relPath && f.line === lineNumber && f.category === "secret",
        );
        if (hasSpecificOnLine) continue;

        const dedupKey = `secret.high_entropy:${relPath}:${lineNumber}`;
        if (seenKeys.has(dedupKey)) continue;
        seenKeys.add(dedupKey);

        findings.push({
          id: dedupKey,
          ruleId: "secret.high_entropy",
          severity: "high",
          category: "secret",
          badge: "Entropy",
          path: relPath,
          line: lineNumber,
          title: "High-Entropy Secret Assignment",
          reason: `Suspicious credential assignment with Shannon entropy ${entropy.toFixed(2)} bits/char.`,
          maskedSnippet: maskSecret(candidate),
          gitignoreRule: relPath,
          isFolderRule: false,
          remediationCommands: buildRemediationCommands(relPath, relPath, false, true),
          ignoreOptions: buildIgnoreOptionsForPath(relPath, false),
        });
      }
    }
  }

  return findings;
}

export function parseAddedLinesFromUnifiedDiff(
  diffText: string,
): Map<string, Array<{ lineNumber: number; text: string }>> {
  const byFile = new Map<string, Array<{ lineNumber: number; text: string }>>();
  if (!diffText) return byFile;

  let currentFile = "";
  let currentLine = 0;

  for (const rawLine of diffText.split(/\r?\n/)) {
    if (rawLine.startsWith("+++ b/")) {
      currentFile = normalizeRelPath(rawLine.slice(6).replace(/^"|"$/g, ""));
      if (currentFile && !byFile.has(currentFile)) {
        byFile.set(currentFile, []);
      }
      continue;
    }
    if (rawLine.startsWith("+++ /dev/null")) {
      currentFile = "";
      continue;
    }
    const hunkMatch = rawLine.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) {
      currentLine = parseInt(hunkMatch[1], 10);
      continue;
    }
    if (!currentFile) continue;

    if (rawLine.startsWith("+") && !rawLine.startsWith("+++")) {
      byFile.get(currentFile)!.push({
        lineNumber: Math.max(1, currentLine),
        text: rawLine.slice(1),
      });
      currentLine++;
    } else if (rawLine.startsWith(" ")) {
      currentLine++;
    }
  }
  return byFile;
}

function finalizeScanResult(
  source: GuardScanResult["source"],
  findings: GuardFinding[],
  filesScanned: number,
  repoPath?: string,
  branch?: string,
): GuardScanResult {
  // Deduplicate by id
  const uniqueMap = new Map<string, GuardFinding>();
  for (const f of findings) {
    if (!uniqueMap.has(f.id)) {
      uniqueMap.set(f.id, f);
    }
  }
  const uniqueFindings = Array.from(uniqueMap.values()).sort((a, b) => {
    const sevDiff = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (sevDiff !== 0) return sevDiff;
    return a.path.localeCompare(b.path) || (a.line ?? 0) - (b.line ?? 0);
  });

  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let rawScore = 0;

  for (const f of uniqueFindings) {
    if (f.severity === "critical") critical++;
    else if (f.severity === "high") high++;
    else if (f.severity === "medium") medium++;
    else low++;
    rawScore += SEVERITY_WEIGHT[f.severity];
  }

  const riskScore = Math.min(100, rawScore);
  let verdict: GuardVerdict = "PASS";
  if (critical > 0 || riskScore >= 60) {
    verdict = "BLOCK";
  } else if (high > 0 || medium > 0 || riskScore >= 15) {
    verdict = "WARN";
  }

  const gitignoreRules = Array.from(
    new Set(
      uniqueFindings
        .filter((f) => f.category !== "secret")
        .map((f) => f.gitignoreRule)
        .filter(Boolean),
    ),
  );

  const suggestedGitignoreBlock =
    gitignoreRules.length > 0
      ? ["# Added by GuardGit MCP", ...gitignoreRules].join("\n")
      : "";

  return {
    source,
    repoPath,
    branch,
    verdict,
    riskScore,
    summary: {
      totalFindings: uniqueFindings.length,
      critical,
      high,
      medium,
      low,
      filesScanned,
    },
    findings: uniqueFindings,
    suggestedGitignoreBlock,
    scannedAt: new Date().toISOString(),
  };
}

export async function guardScan(
  input: GuardScanInput = {},
  runGit: GitRunner = createExecGitRunner(),
): Promise<GuardScanResult> {
  const largeFileThresholdBytes =
    typeof input.largeFileThresholdBytes === "number" && input.largeFileThresholdBytes >= 0
      ? input.largeFileThresholdBytes
      : DEFAULT_LARGE_FILE_BYTES;

  const allowedSet = new Set(
    (input.allowedPaths ?? []).map((p) => normalizeRelPath(p).toLowerCase()),
  );

  const findings: GuardFinding[] = [];

  // Mode 1: Direct files array (pure in-memory scan)
  if (Array.isArray(input.files) && input.files.length > 0) {
    for (const file of input.files) {
      const norm = normalizeRelPath(file.path);
      if (!norm || allowedSet.has(norm.toLowerCase())) continue;

      findings.push(...classifyPathHygiene(file, largeFileThresholdBytes));

      if (typeof file.content === "string" && file.content.length > 0) {
        const lines = file.content.split(/\r?\n/).map((text, idx) => ({
          lineNumber: idx + 1,
          text,
        }));
        findings.push(...scanTextLinesForSecrets(norm, lines));
      }
    }
    return finalizeScanResult("files", findings, input.files.length);
  }

  // Mode 2: Direct unified diff string
  if (typeof input.diff === "string" && input.diff.trim().length > 0) {
    const addedByFile = parseAddedLinesFromUnifiedDiff(input.diff);
    for (const [relPath, lines] of addedByFile.entries()) {
      if (allowedSet.has(relPath.toLowerCase())) continue;
      findings.push(...classifyPathHygiene({ path: relPath, status: "A" }, largeFileThresholdBytes));
      findings.push(...scanTextLinesForSecrets(relPath, lines));
    }
    return finalizeScanResult("diff", findings, addedByFile.size);
  }

  // Mode 3: Read-only live Git repository scan
  const cwd = path.resolve(input.repoPath || process.cwd());
  if (!fs.existsSync(cwd)) {
    return finalizeScanResult("empty", [], 0, cwd);
  }

  const gitRepo = await isGitRepository(cwd, runGit);
  if (!gitRepo) {
    return finalizeScanResult("empty", [], 0, cwd);
  }

  const branch = await getCurrentBranch(cwd, runGit);
  const statusRes = await runGit(["status", "--porcelain=v1", "-u"], cwd, {
    allowNonZeroExit: true,
  });
  const porcelain = parsePorcelainStatus(statusRes.stdout);
  const includeUntracked = input.includeUntracked !== false;

  const targetEntries = porcelain.filter((e) => includeUntracked || !e.untracked);
  const scannedFiles = new Set<string>();

  for (const entry of targetEntries) {
    if (allowedSet.has(entry.path.toLowerCase())) continue;
    scannedFiles.add(entry.path);

    const diskInfo =
      entry.effectiveStatus !== "D" ? readDiskContentSafe(cwd, entry.path) : {};

    findings.push(
      ...classifyPathHygiene(
        {
          path: entry.path,
          status: entry.effectiveStatus,
          sizeBytes: diskInfo.sizeBytes,
          isBinary: diskInfo.isBinary,
        },
        largeFileThresholdBytes,
        cwd,
      ),
    );

    if (entry.untracked && diskInfo.text) {
      const lines = diskInfo.text.split(/\r?\n/).map((text, idx) => ({
        lineNumber: idx + 1,
        text,
      }));
      findings.push(...scanTextLinesForSecrets(entry.path, lines));
    }
  }

  // Scan staged and unstaged diffs (read-only)
  const [stagedDiff, unstagedDiff] = await Promise.all([
    runGit(["diff", "--cached", "--unified=0"], cwd, { allowNonZeroExit: true }),
    runGit(["diff", "--unified=0"], cwd, { allowNonZeroExit: true }),
  ]);

  for (const rawDiff of [stagedDiff.stdout, unstagedDiff.stdout]) {
    const addedByFile = parseAddedLinesFromUnifiedDiff(rawDiff);
    for (const [relPath, lines] of addedByFile.entries()) {
      if (allowedSet.has(relPath.toLowerCase())) continue;
      scannedFiles.add(relPath);
      findings.push(...scanTextLinesForSecrets(relPath, lines));
    }
  }

  return finalizeScanResult("repo", findings, scannedFiles.size, cwd, branch);
}
