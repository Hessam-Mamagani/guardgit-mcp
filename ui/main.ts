import {
  App,
  applyDocumentTheme,
  applyHostFonts,
  applyHostStyleVariables,
} from "@modelcontextprotocol/ext-apps";
import type {
  AtomicCommitPlanResult,
  BlastRadiusResult,
  GuardFinding,
  GuardScanResult,
  JsonDiffNode,
  SensitiveCategory,
  StructuralJsonDiffResult,
} from "../src/core/types.js";

interface CockpitState {
  activeTab: "guard" | "json-diff" | "blast-radius" | "atomic-commits";
  severityFilter: "all" | "critical" | "high" | "medium";
  repoPath: string;
  branch: string;
  guard?: GuardScanResult;
  blastRadius?: BlastRadiusResult;
  atomicPlan?: AtomicCommitPlanResult;
  jsonDiff?: StructuralJsonDiffResult;
  modifiedJsonFiles: string[];
  connected: boolean;
}

const state: CockpitState = {
  activeTab: "guard",
  severityFilter: "all",
  repoPath: "",
  branch: "--",
  modifiedJsonFiles: [],
  connected: false,
};

const SENSITIVE_LABELS: Record<SensitiveCategory, string> = {
  auth_security: "Auth & Security",
  database_migration: "DB & Migrations",
  ci_cd_infra: "CI/CD & Infra",
  dependencies_lock: "Dependencies",
  config_runtime: "Runtime Config",
  core_api_contract: "API Contracts",
};

const app = new App({ name: "GuardGit Cockpit", version: "1.0.0" }, {});

function el<T extends HTMLElement = HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

function escapeHtml(raw: string): string {
  return String(raw)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function showToast(message: string): void {
  const toast = el("toast");
  toast.textContent = message;
  toast.classList.remove("hidden");
  window.setTimeout(() => {
    toast.classList.add("hidden");
  }, 2200);
}

async function copyText(text: string, label: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    showToast(`Copied ${label}`);
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    document.body.removeChild(area);
    showToast(`Copied ${label}`);
  }
}

function setLoading(loading: boolean, text = "Analyzing repository..."): void {
  const banner = el("loading-banner");
  el("loading-text").textContent = text;
  banner.classList.toggle("hidden", !loading);
}

function switchTab(tab: CockpitState["activeTab"]): void {
  state.activeTab = tab;
  document.querySelectorAll<HTMLButtonElement>(".tab").forEach((btn) => {
    const active = btn.dataset.tab === tab;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });
  document.querySelectorAll<HTMLElement>(".panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `panel-${tab}`);
  });
}

function renderHeader(): void {
  el("branch-pill").textContent = `branch: ${state.branch || "--"}`;
  el("repo-subtitle").textContent = state.repoPath
    ? state.repoPath
    : "Pre-commit DevSecOps safety net & structural diff cockpit";
  const repoInput = el<HTMLInputElement>("repo-path-input");
  if (state.repoPath && document.activeElement !== repoInput) {
    repoInput.value = state.repoPath;
  }

  const verdict = state.guard?.verdict ?? "PASS";
  const vPill = el("verdict-pill");
  vPill.textContent = verdict;
  vPill.className = `chip ${
    verdict === "BLOCK" ? "chip-block" : verdict === "WARN" ? "chip-warn" : "chip-pass"
  }`;

  el("tab-badge-guard").textContent = String(state.guard?.summary.totalFindings ?? 0);
  el("tab-badge-json").textContent = String(state.jsonDiff?.stats.totalNodes ?? 0);
  el("tab-badge-blast").textContent = state.blastRadius ? String(state.blastRadius.score) : "--";
  el("tab-badge-commits").textContent = String(state.atomicPlan?.groups.length ?? 0);
}

function renderGuardPanel(): void {
  const guard = state.guard;
  const score = guard?.riskScore ?? 0;
  const verdict = guard?.verdict ?? "PASS";

  // SVG semi-circle arc length ~ 170
  const arc = el("gauge-arc");
  const maxArc = 170;
  const offset = maxArc - (Math.min(100, Math.max(0, score)) / 100) * maxArc;
  arc.setAttribute("stroke-dashoffset", offset.toFixed(1));
  arc.setAttribute(
    "stroke",
    verdict === "BLOCK"
      ? "var(--gg-accent-danger)"
      : verdict === "WARN"
        ? "var(--gg-accent-warn)"
        : "var(--gg-accent-ok)",
  );

  el("gauge-score").textContent = String(score);
  const verdictLabel = el("gauge-verdict-label");
  verdictLabel.textContent = verdict;
  verdictLabel.style.color =
    verdict === "BLOCK"
      ? "var(--gg-accent-danger)"
      : verdict === "WARN"
        ? "var(--gg-accent-warn)"
        : "var(--gg-accent-ok)";

  el("gauge-subtext").textContent =
    verdict === "BLOCK"
      ? "Commit blocked until critical secrets or files are remediated"
      : verdict === "WARN"
        ? "Review warnings before staging or pushing"
        : "Zero blocking issues detected";

  el("kpi-findings").textContent = String(guard?.summary.totalFindings ?? 0);
  el("kpi-findings-sub").textContent = guard
    ? `${guard.summary.critical} critical · ${guard.summary.high} high · ${guard.summary.medium} medium`
    : "No scan data";

  if (state.blastRadius) {
    el("kpi-blast").textContent = `${state.blastRadius.score} (${state.blastRadius.band})`;
    el("kpi-blast-sub").textContent =
      `${state.blastRadius.totals.filesChanged} files · +${state.blastRadius.totals.additions}/-${state.blastRadius.totals.deletions}`;

    const m = state.blastRadius.mergeAdvice;
    el("kpi-merge").textContent = m.hasConflicts
      ? `${m.conflictedFiles.length} Conflict(s)`
      : m.checked
        ? "Clean"
        : "Skipped";
    el("kpi-merge-sub").textContent = m.checked
      ? `vs ${m.targetBranch} (${m.aheadCount} ahead / ${m.behindCount} behind)`
      : m.note;
  }

  if (state.atomicPlan) {
    el("kpi-commits").textContent = String(state.atomicPlan.groups.length);
    el("kpi-commits-sub").textContent =
      `${state.atomicPlan.plannedFileCount} safe files · ${state.atomicPlan.excludedRiskyFiles.length} withheld`;
  }

  const allFindings = guard?.findings ?? [];
  const filtered =
    state.severityFilter === "all"
      ? allFindings
      : allFindings.filter((f) => f.severity === state.severityFilter);

  const empty = el("findings-empty");
  const wrap = el("findings-table-wrap");
  const tbody = el("findings-tbody");

  if (filtered.length === 0) {
    empty.classList.remove("hidden");
    wrap.classList.add("hidden");
    tbody.innerHTML = "";
  } else {
    empty.classList.add("hidden");
    wrap.classList.remove("hidden");
    tbody.innerHTML = filtered
      .map((f: GuardFinding, idx: number) => {
        const loc = f.line ? `${f.path}:${f.line}` : f.path;
        const cmd = f.remediationCommands[0] ?? `echo "${f.gitignoreRule}" >> .gitignore`;
        return `
          <tr>
            <td><span class="sev-badge sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td>
            <td>
              <div style="font-weight:600">${escapeHtml(f.title)}</div>
              <div class="muted" style="font-size:11.5px">${escapeHtml(f.reason)}</div>
              ${f.maskedSnippet ? `<span class="snippet-chip">${escapeHtml(f.maskedSnippet)}</span>` : ""}
            </td>
            <td class="mono">${escapeHtml(loc)}</td>
            <td>
              <div class="mono" style="margin-bottom:5px;word-break:break-all">${escapeHtml(cmd)}</div>
              <button class="btn btn-sm copy-fix-btn" data-idx="${idx}" type="button">Copy Fix</button>
            </td>
          </tr>
        `;
      })
      .join("");

    tbody.querySelectorAll<HTMLButtonElement>(".copy-fix-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const item = filtered[Number(btn.dataset.idx)];
        if (item) {
          void copyText(item.remediationCommands.join("\n"), "remediation command");
        }
      });
    });
  }

  const gitignoreBox = el("gitignore-box");
  if (guard?.suggestedGitignoreBlock) {
    gitignoreBox.classList.remove("hidden");
    el("gitignore-pre").textContent = guard.suggestedGitignoreBlock;
  } else {
    gitignoreBox.classList.add("hidden");
  }
}

function renderJsonDiffPanel(): void {
  const diff = state.jsonDiff;
  const select = el<HTMLSelectElement>("json-file-select");

  if (state.modifiedJsonFiles.length > 0) {
    select.classList.remove("hidden");
    select.innerHTML = state.modifiedJsonFiles
      .map((f) => `<option value="${escapeHtml(f)}" ${diff?.filePath === f ? "selected" : ""}>${escapeHtml(f)}</option>`)
      .join("");
  } else {
    select.classList.add("hidden");
  }

  if (!diff) {
    el("json-diff-title").textContent = "Structural JSON Diff";
    el("json-diff-meta").textContent = "Select a modified JSON file or compare custom JSON payloads";
    el("json-tree-container").innerHTML = `<div class="empty-state"><div class="empty-title">No JSON Diff Loaded</div></div>`;
    return;
  }

  el("json-diff-title").textContent = `Structural JSON Diff — ${diff.filePath}`;
  el("json-diff-meta").textContent =
    `${diff.oldBytes} B -> ${diff.newBytes} B${diff.isMinified ? " · Minified JSON compacted" : ""}${diff.metadataHints.length ? ` · ${diff.metadataHints.join(", ")}` : ""}`;

  el("json-stat-strip").innerHTML = `
    <span class="stat-chip stat-add">+${diff.stats.added} Added</span>
    <span class="stat-chip stat-rem">-${diff.stats.removed} Removed</span>
    <span class="stat-chip stat-mod">~${diff.stats.modified + diff.stats.typeChanged} Modified</span>
    <span class="stat-chip stat-brk">${diff.stats.breakingCount} Breaking</span>
  `;

  const banner = el("json-breaking-banner");
  if (diff.breakingChanges.length > 0) {
    banner.classList.remove("hidden");
    banner.innerHTML = `<strong>${diff.breakingChanges.length} potential breaking change(s):</strong> ${diff.breakingChanges
      .slice(0, 4)
      .map((b) => `<span class="mono">${escapeHtml(b.path)}</span> (${escapeHtml(b.breakingReason || "breaking")})`)
      .join(" · ")}`;
  } else {
    banner.classList.add("hidden");
  }

  const query = el<HTMLInputElement>("json-search-input").value.trim().toLowerCase();
  const breakingOnly = el<HTMLInputElement>("json-breaking-only").checked;

  const nodes = diff.nodes.filter((n: JsonDiffNode) => {
    if (breakingOnly && !n.breaking) return false;
    if (!query) return true;
    return (
      n.path.toLowerCase().includes(query) ||
      (n.oldPreview ?? "").toLowerCase().includes(query) ||
      (n.newPreview ?? "").toLowerCase().includes(query) ||
      (n.breakingReason ?? "").toLowerCase().includes(query)
    );
  });

  const container = el("json-tree-container");
  if (nodes.length === 0) {
    container.innerHTML = `<div class="empty-state"><div class="empty-title">${
      diff.semanticallyEqual ? "Semantically Identical" : "No Matching Diff Nodes"
    }</div><p class="muted">${
      diff.semanticallyEqual
        ? "Only whitespace or key ordering changed."
        : "Try clearing the filter or unchecking Breaking only."
    }</p></div>`;
    return;
  }

  // Group nodes by top-level key
  const groups = new Map<string, JsonDiffNode[]>();
  for (const n of nodes) {
    const top = n.path.split(".")[0] || "(root)";
    const list = groups.get(top) ?? [];
    list.push(n);
    groups.set(top, list);
  }

  container.innerHTML = Array.from(groups.entries())
    .map(([groupName, groupNodes]) => {
      const breakingInGroup = groupNodes.filter((g) => g.breaking).length;
      const rowsHtml = groupNodes
        .map((n) => {
          const valLine =
            n.kind === "added"
              ? `<span style="color:var(--gg-accent-ok)">+ ${escapeHtml(n.newPreview ?? "")}</span>`
              : n.kind === "removed"
                ? `<span style="color:var(--gg-accent-danger)">- ${escapeHtml(n.oldPreview ?? "")}</span>`
                : `<span class="muted">${escapeHtml(n.oldPreview ?? "")}</span> <span>-></span> <strong>${escapeHtml(n.newPreview ?? "")}</strong>`;
          return `
            <div class="tree-row">
              <div class="tree-row-top">
                <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                  <span class="diff-kind kind-${escapeHtml(n.kind)}">${escapeHtml(n.kind)}</span>
                  <span class="mono" style="font-weight:600">${escapeHtml(n.path)}</span>
                </div>
                ${n.breaking ? `<span class="sev-badge sev-critical">BREAKING</span>` : ""}
              </div>
              <div class="mono" style="font-size:11.5px;word-break:break-word">${valLine}</div>
              ${n.breakingReason ? `<div style="font-size:11px;color:var(--gg-accent-danger)">${escapeHtml(n.breakingReason)}</div>` : ""}
            </div>
          `;
        })
        .join("");

      return `
        <details class="tree-group" open>
          <summary>
            <span>${escapeHtml(groupName)}</span>
            <span class="muted" style="font-size:11px">${groupNodes.length} change(s)${breakingInGroup ? ` · ${breakingInGroup} breaking` : ""}</span>
          </summary>
          <div class="tree-rows">${rowsHtml}</div>
        </details>
      `;
    })
    .join("");
}

function renderBlastPanel(): void {
  const blast = state.blastRadius;
  if (!blast) {
    el("merge-status-card").innerHTML = `<div class="muted">Run a scan to evaluate blast radius and git merge-tree status.</div>`;
    return;
  }

  const m = blast.mergeAdvice;
  const statusClass = m.hasConflicts ? "chip-block" : m.workingTreeOverlapFiles.length > 0 ? "chip-warn" : "chip-pass";
  const statusText = m.hasConflicts ? "CONFLICT DETECTED" : m.checked ? "CLEAN DRY-RUN" : "NOT CHECKED";

  el("merge-status-card").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
      <span class="chip ${statusClass}">${statusText}</span>
      <span class="mono muted">${escapeHtml(m.sourceRef)} -> ${escapeHtml(m.targetBranch)} (+${m.aheadCount}/-${m.behindCount})</span>
    </div>
    <div>${escapeHtml(m.note)}</div>
    ${m.treeOid ? `<div class="mono muted" style="font-size:11px">In-memory tree OID: ${escapeHtml(m.treeOid.slice(0, 12))}</div>` : ""}
    ${
      m.conflictedFiles.length > 0
        ? `<div class="commit-files">${m.conflictedFiles.map((f) => `<span class="file-chip" style="color:var(--gg-accent-danger)">${escapeHtml(f)}</span>`).join("")}</div>`
        : ""
    }
    ${
      m.workingTreeOverlapFiles.length > 0
        ? `<div style="font-size:11.5px;color:var(--gg-accent-warn)">Uncommitted overlap: ${m.workingTreeOverlapFiles.map(escapeHtml).join(", ")}</div>`
        : ""
    }
  `;

  el("blast-recommendations").innerHTML = blast.recommendations
    .map((rec) => `<div class="rec-item">${escapeHtml(rec)}</div>`)
    .join("");

  const categories = Object.keys(SENSITIVE_LABELS) as SensitiveCategory[];
  el("sensitive-grid").innerHTML = categories
    .map((cat) => {
      const hits = blast.sensitiveHits[cat] ?? [];
      return `
        <div class="sensitive-tile ${hits.length > 0 ? "sensitive-tile-active" : ""}">
          <div style="font-size:11px;font-weight:600;color:var(--gg-text-muted)">${escapeHtml(SENSITIVE_LABELS[cat])}</div>
          <div class="num" style="font-size:18px;font-weight:700;margin-top:2px">${hits.length}</div>
          <div class="mono muted" style="font-size:10.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${hits.length > 0 ? escapeHtml(hits.slice(0, 2).join(", ")) : "None"}</div>
        </div>
      `;
    })
    .join("");

  el("heatmap-subtitle").textContent =
    `${blast.totals.filesChanged} changed file(s) across ${blast.totals.directoriesTouched} folder(s) · Composite score ${blast.score}/100 (${blast.band})`;

  const heatContainer = el("heatmap-list");
  if (blast.heatmap.length === 0) {
    heatContainer.innerHTML = `<div class="empty-state"><div class="empty-title">Working Tree Clean</div><p class="muted">No modified directories to map.</p></div>`;
    return;
  }

  heatContainer.innerHTML = blast.heatmap
    .map((entry) => {
      const color =
        entry.riskScore >= 70
          ? "var(--gg-accent-danger)"
          : entry.riskScore >= 40
            ? "var(--gg-accent-warn)"
            : "var(--gg-accent)";
      const tags = entry.categories
        .map((c) => `<span class="chip chip-warn" style="font-size:10px">${escapeHtml(SENSITIVE_LABELS[c])}</span>`)
        .join(" ");
      return `
        <div class="heatmap-row">
          <div class="heatmap-row-top">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
              <span class="mono" style="font-weight:650">${escapeHtml(entry.directory)}</span>
              ${tags}
            </div>
            <div class="mono muted" style="font-size:11.5px">
              ${entry.fileCount} file(s) · +${entry.additions}/-${entry.deletions} · <strong>${entry.riskScore}/100</strong>
            </div>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width:${Math.max(4, entry.riskScore)}%;background:${color}"></div>
          </div>
        </div>
      `;
    })
    .join("");
}

function renderAtomicCommitsPanel(): void {
  const plan = state.atomicPlan;
  const list = el("commit-groups-list");
  const withheld = el("withheld-banner");

  if (!plan) {
    list.innerHTML = `<div class="empty-state"><div class="empty-title">No Commit Plan Yet</div></div>`;
    return;
  }

  el("atomic-subtitle").textContent = plan.summaryNote;

  if (plan.excludedRiskyFiles.length > 0) {
    withheld.classList.remove("hidden");
    withheld.innerHTML = `<strong>Withheld ${plan.excludedRiskyFiles.length} risky file(s) from commit groups:</strong> ${plan.excludedRiskyFiles
      .map((f) => `<span class="mono">${escapeHtml(f.path)}</span> (${escapeHtml(f.reason)})`)
      .join(" · ")}`;
  } else {
    withheld.classList.add("hidden");
  }

  if (plan.groups.length === 0) {
    list.innerHTML = `<div class="empty-state"><div class="empty-title">No Safe Changes to Split</div><p class="muted">Modify or stage files to generate an atomic Conventional Commit plan.</p></div>`;
    return;
  }

  list.innerHTML = plan.groups
    .map(
      (g, idx) => `
      <div class="commit-card">
        <div class="commit-head">
          <div>
            <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap">
              <span class="chip chip-muted">#${g.order}</span>
              <span class="mono" style="font-weight:700">${escapeHtml(g.suggestedMessage)}</span>
            </div>
            <div class="muted" style="font-size:11.5px;margin-top:3px">${escapeHtml(g.rationale)}</div>
          </div>
          <button class="btn btn-sm copy-commit-btn" data-idx="${idx}" type="button">Copy Git Commands</button>
        </div>
        <div class="commit-files">
          ${g.files
            .map(
              (f) =>
                `<span class="file-chip">[${escapeHtml(f.status)}] ${escapeHtml(f.path)} (+${f.additions}/-${f.deletions})</span>`,
            )
            .join("")}
        </div>
      </div>
    `,
    )
    .join("");

  list.querySelectorAll<HTMLButtonElement>(".copy-commit-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const group = plan.groups[Number(btn.dataset.idx)];
      if (group) {
        void copyText(group.stageCommands.join("\n"), `commit #${group.order} commands`);
      }
    });
  });
}

function renderAll(): void {
  renderHeader();
  renderGuardPanel();
  renderJsonDiffPanel();
  renderBlastPanel();
  renderAtomicCommitsPanel();
}

function applyStructuredPayload(payload: Record<string, unknown> | undefined): void {
  if (!payload || typeof payload !== "object") return;

  if (typeof payload.repoPath === "string") state.repoPath = payload.repoPath;
  if (typeof payload.branch === "string") state.branch = payload.branch;
  if (Array.isArray(payload.modifiedJsonFiles)) {
    state.modifiedJsonFiles = payload.modifiedJsonFiles.filter((x): x is string => typeof x === "string");
  }
  if (payload.guard) state.guard = payload.guard as GuardScanResult;
  if (payload.blastRadius) state.blastRadius = payload.blastRadius as BlastRadiusResult;
  if (payload.atomicPlan) state.atomicPlan = payload.atomicPlan as AtomicCommitPlanResult;
  if (payload.jsonDiff) state.jsonDiff = payload.jsonDiff as StructuralJsonDiffResult;

  const view = payload.view;
  if (view === "guard" || view === "overview") switchTab("guard");
  else if (view === "json-diff") switchTab("json-diff");
  else if (view === "blast-radius") switchTab("blast-radius");
  else if (view === "atomic-commits") switchTab("atomic-commits");

  renderAll();
}

async function invokeTool(name: string, args: Record<string, unknown>, loadingMsg: string): Promise<void> {
  if (!state.connected) {
    showToast("Connect via an MCP App host to execute server tools");
    return;
  }
  setLoading(true, loadingMsg);
  try {
    const res = await app.callServerTool({ name, arguments: args });
    applyStructuredPayload(res.structuredContent as Record<string, unknown> | undefined);
  } catch (err) {
    showToast(`Tool failed: ${(err as Error).message}`);
  } finally {
    setLoading(false);
  }
}

function wireDomEvents(): void {
  document.querySelectorAll<HTMLButtonElement>(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.tab as CockpitState["activeTab"];
      if (target) switchTab(target);
    });
  });

  el("severity-filters")
    .querySelectorAll<HTMLButtonElement>(".pill")
    .forEach((pill) => {
      pill.addEventListener("click", () => {
        state.severityFilter = (pill.dataset.severity as CockpitState["severityFilter"]) || "all";
        el("severity-filters")
          .querySelectorAll(".pill")
          .forEach((p) => p.classList.toggle("active", p === pill));
        renderGuardPanel();
      });
    });

  el("rescan-btn").addEventListener("click", () => {
    const repoPath = el<HTMLInputElement>("repo-path-input").value.trim() || undefined;
    void invokeTool("open_guardgit_cockpit", repoPath ? { repoPath } : {}, "Running full DevSecOps scan...");
  });

  el("copy-gitignore-btn").addEventListener("click", () => {
    if (state.guard?.suggestedGitignoreBlock) {
      void copyText(state.guard.suggestedGitignoreBlock, ".gitignore rules");
    }
  });

  el("toggle-json-compare-btn").addEventListener("click", () => {
    el("custom-json-drawer").classList.toggle("hidden");
  });

  el("run-json-diff-btn").addEventListener("click", () => {
    const oldJson = el<HTMLTextAreaElement>("old-json-input").value.trim();
    const newJson = el<HTMLTextAreaElement>("new-json-input").value.trim();
    const filePath = el<HTMLInputElement>("custom-json-filename").value.trim() || "custom.json";
    if (!oldJson || !newJson) {
      showToast("Provide both baseline and updated JSON");
      return;
    }
    void invokeTool(
      "diff_structural_json",
      { oldJson, newJson, filePath },
      `Diffing ${filePath}...`,
    );
  });

  el<HTMLSelectElement>("json-file-select").addEventListener("change", (ev) => {
    const filePath = (ev.target as HTMLSelectElement).value;
    if (!filePath) return;
    void invokeTool(
      "diff_structural_json",
      { repoPath: state.repoPath || undefined, filePath, baseRef: "HEAD" },
      `Diffing ${filePath} vs HEAD...`,
    );
  });

  el("json-search-input").addEventListener("input", () => renderJsonDiffPanel());
  el("json-breaking-only").addEventListener("change", () => renderJsonDiffPanel());

  el("run-blast-btn").addEventListener("click", () => {
    const targetBranch = el<HTMLInputElement>("target-branch-input").value.trim() || undefined;
    void invokeTool(
      "analyze_blast_radius",
      { repoPath: state.repoPath || undefined, targetBranch },
      "Running read-only git merge-tree dry run...",
    );
  });

  el("refresh-plan-btn").addEventListener("click", () => {
    void invokeTool(
      "plan_atomic_commits",
      { repoPath: state.repoPath || undefined },
      "Recomputing atomic Conventional Commits...",
    );
  });

  el("attach-ctx-btn").addEventListener("click", async () => {
    if (!state.connected) return;
    const summary = [
      `GuardGit Cockpit Snapshot (${state.repoPath}, branch ${state.branch})`,
      state.guard
        ? `Guard Verdict: ${state.guard.verdict} (${state.guard.riskScore}/100, ${state.guard.summary.totalFindings} findings)`
        : "",
      state.blastRadius
        ? `Blast Radius: ${state.blastRadius.band} (${state.blastRadius.score}/100), Merge: ${state.blastRadius.mergeAdvice.note}`
        : "",
    ]
      .filter(Boolean)
      .join("\n");
    await app.updateModelContext({
      content: [{ type: "text", text: summary }],
    });
    showToast("Attached GuardGit findings to next message");
  });

  el("ask-fix-btn").addEventListener("click", async () => {
    if (!state.connected) return;
    const topFindings = (state.guard?.findings ?? [])
      .slice(0, 5)
      .map((f) => `- [${f.severity}] ${f.title} at ${f.path}`)
      .join("\n");
    const prompt = topFindings
      ? `Please help remediate these GuardGit pre-commit findings safely:\n${topFindings}`
      : "Review the current GuardGit blast-radius and atomic commit split plan and help me commit cleanly.";
    await app.sendMessage({
      role: "user",
      content: [{ type: "text", text: prompt }],
    });
    showToast("Sent remediation request to chat");
  });
}

function applyHostContext(): void {
  const ctx = app.getHostContext();
  if (ctx?.theme) applyDocumentTheme(ctx.theme);
  if (ctx?.styles?.variables) applyHostStyleVariables(ctx.styles.variables);
  if (ctx?.styles?.css?.fonts) applyHostFonts(ctx.styles.css.fonts);

  const caps = app.getHostCapabilities();
  el("attach-ctx-btn").classList.toggle("hidden", !caps?.updateModelContext);
  el("ask-fix-btn").classList.toggle("hidden", !caps?.message);
}

async function bootstrap(): Promise<void> {
  wireDomEvents();

  // Register MCP App handlers BEFORE connect() per SEP-1865 lifecycle
  app.ontoolinput = () => {
    setLoading(true, "Running GuardGit analysis...");
  };

  app.ontoolresult = (result) => {
    setLoading(false);
    applyStructuredPayload(result.structuredContent as Record<string, unknown> | undefined);
  };

  app.ontoolcancelled = () => {
    setLoading(false);
  };

  app.onhostcontextchanged = (ctx) => {
    if (ctx.theme) applyDocumentTheme(ctx.theme);
    if (ctx.styles?.variables) applyHostStyleVariables(ctx.styles.variables);
    if (ctx.styles?.css?.fonts) applyHostFonts(ctx.styles.css.fonts);
  };

  try {
    await app.connect();
    state.connected = true;
    applyHostContext();
  } catch {
    // Standalone browser preview fallback
    state.connected = false;
    renderAll();
  }
}

void bootstrap();
