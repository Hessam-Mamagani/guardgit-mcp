export type Severity = "critical" | "high" | "medium" | "low";

export type GuardVerdict = "PASS" | "WARN" | "BLOCK";

export type GuardCategory =
  | "secret"
  | "credential_file"
  | "large_blob"
  | "binary"
  | "artifact"
  | "database"
  | "junk";

export interface IgnoreOption {
  pattern: string;
  label: string;
  description: string;
  kind: "file" | "folder" | "basename" | "extension";
}

export interface GuardFinding {
  id: string;
  ruleId: string;
  severity: Severity;
  category: GuardCategory;
  badge: string;
  path: string;
  line?: number;
  title: string;
  reason: string;
  maskedSnippet?: string;
  sizeBytes?: number;
  gitignoreRule: string;
  isFolderRule: boolean;
  remediationCommands: string[];
  ignoreOptions: IgnoreOption[];
}

export interface GuardFileInput {
  path: string;
  status?: string;
  content?: string;
  sizeBytes?: number;
  isBinary?: boolean;
}

export interface GuardScanInput {
  repoPath?: string;
  diff?: string;
  files?: GuardFileInput[];
  largeFileThresholdBytes?: number;
  allowedPaths?: string[];
  includeUntracked?: boolean;
}

export interface GuardScanSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  filesScanned: number;
}

export interface GuardScanResult {
  source: "repo" | "diff" | "files" | "empty";
  repoPath?: string;
  branch?: string;
  verdict: GuardVerdict;
  riskScore: number;
  summary: GuardScanSummary;
  findings: GuardFinding[];
  suggestedGitignoreBlock: string;
  scannedAt: string;
}

export type JsonDiffKind = "added" | "removed" | "modified" | "type_changed";

export interface JsonArrayDiffSummary {
  strategy: "primitive" | "key" | "edge" | "hash";
  keyName?: string;
  oldLength: number;
  newLength: number;
  addedCount: number;
  removedCount: number;
  modifiedCount: number;
  addedSamples: string[];
  removedSamples: string[];
  modifiedSamples: string[];
  bulkShiftedFields: string[];
}

export interface JsonDiffNode {
  path: string;
  kind: JsonDiffKind;
  oldType?: string;
  newType?: string;
  oldPreview?: string;
  newPreview?: string;
  arraySummary?: JsonArrayDiffSummary;
  breaking: boolean;
  breakingReason?: string;
}

export interface StructuralJsonDiffInput {
  oldJson?: string;
  newJson?: string;
  filePath?: string;
  repoPath?: string;
  baseRef?: string;
  maxNodes?: number;
}

export interface StructuralJsonDiffResult {
  filePath: string;
  oldBytes: number;
  newBytes: number;
  isMinified: boolean;
  semanticallyEqual: boolean;
  stats: {
    added: number;
    removed: number;
    modified: number;
    typeChanged: number;
    breakingCount: number;
    totalNodes: number;
  };
  metadataHints: string[];
  nodes: JsonDiffNode[];
  breakingChanges: JsonDiffNode[];
  textSummary: string;
  error?: string;
}

export type SensitiveCategory =
  | "auth_security"
  | "database_migration"
  | "ci_cd_infra"
  | "dependencies_lock"
  | "config_runtime"
  | "core_api_contract";

export type BlastRiskBand = "LOW" | "MODERATE" | "HIGH" | "CRITICAL";

export interface ChangedFileMetric {
  path: string;
  oldPath?: string | null;
  status: string;
  staged: boolean;
  unstaged: boolean;
  untracked: boolean;
  additions: number;
  deletions: number;
  isBinary: boolean;
  sensitiveCategories: SensitiveCategory[];
  riskWeight: number;
}

export interface DirectoryHeatmapEntry {
  directory: string;
  fileCount: number;
  additions: number;
  deletions: number;
  riskScore: number;
  categories: SensitiveCategory[];
  files: string[];
}

export interface MergeConflictResult {
  checked: boolean;
  targetBranch: string;
  sourceRef: string;
  mergeBase?: string;
  aheadCount: number;
  behindCount: number;
  hasConflicts: boolean;
  treeOid?: string;
  conflictedFiles: string[];
  conflictDetails: string[];
  workingTreeOverlapFiles: string[];
  note: string;
}

export interface BlastRadiusInput {
  repoPath?: string;
  targetBranch?: string;
  sourceRef?: string;
  files?: Array<{
    path: string;
    status?: string;
    additions?: number;
    deletions?: number;
    isBinary?: boolean;
  }>;
}

export interface BlastRadiusResult {
  repoPath?: string;
  branch: string;
  score: number;
  band: BlastRiskBand;
  totals: {
    filesChanged: number;
    stagedFiles: number;
    unstagedFiles: number;
    untrackedFiles: number;
    additions: number;
    deletions: number;
    binaryFiles: number;
    directoriesTouched: number;
  };
  sensitiveHits: Record<SensitiveCategory, string[]>;
  heatmap: DirectoryHeatmapEntry[];
  files: ChangedFileMetric[];
  mergeAdvice: MergeConflictResult;
  recommendations: string[];
  analyzedAt: string;
}

export type CommitType =
  | "feat"
  | "fix"
  | "refactor"
  | "test"
  | "docs"
  | "ci"
  | "build"
  | "config"
  | "style"
  | "chore";

export interface AtomicCommitGroup {
  order: number;
  type: CommitType;
  scope: string;
  suggestedMessage: string;
  rationale: string;
  files: Array<{
    path: string;
    status: string;
    additions: number;
    deletions: number;
  }>;
  totalAdditions: number;
  totalDeletions: number;
  stageCommands: string[];
}

export interface AtomicCommitPlanInput {
  repoPath?: string;
  files?: Array<{
    path: string;
    status?: string;
    additions?: number;
    deletions?: number;
    content?: string;
    sizeBytes?: number;
  }>;
  excludeRisky?: boolean;
}

export interface AtomicCommitPlanResult {
  repoPath?: string;
  branch?: string;
  totalFilesConsidered: number;
  plannedFileCount: number;
  groups: AtomicCommitGroup[];
  excludedRiskyFiles: Array<{
    path: string;
    severity: Severity;
    reason: string;
  }>;
  summaryNote: string;
  plannedAt: string;
}

export interface CockpitSnapshot {
  view: "overview" | "guard" | "json-diff" | "blast-radius" | "atomic-commits";
  repoPath: string;
  isGitRepo: boolean;
  branch: string;
  guard: GuardScanResult;
  blastRadius: BlastRadiusResult;
  atomicPlan: AtomicCommitPlanResult;
  jsonDiff?: StructuralJsonDiffResult;
  modifiedJsonFiles: string[];
  generatedAt: string;
}
