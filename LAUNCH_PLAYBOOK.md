# GuardGit MCP v1.0 — Public Launch Playbook

Zero-conflict, 100% personal AGPL-3.0 open-source launch assets ready for immediate distribution across Hacker News, Reddit (`r/mcp`, `r/ClaudeAI`, `r/programming`), and LinkedIn.

---

## 1. Show HN Post

**Title:**
Show HN: GuardGit MCP – Pre-commit DevSecOps cockpit and structural JSON diff MCP App for AI coding agents

**Body:**
Hi HN,

While working heavily with autonomous AI coding agents (Claude Code, Cursor, Antigravity), I kept hitting the same four repo-hygiene failures:
1. Agents accidentally staging `.env` files, API tokens, SQLite WAL files, or 20 MB build outputs.
2. Unreadable 10,000-character single-line diffs whenever `package.json`, `tsconfig.json`, i18n dictionaries, or lockfiles change.
3. Pushing branches without realizing upstream `main` diverged on the same files.
4. Dumping 35 unrelated file changes into a single "update code" commit.

I extracted and rebuilt my diff and hygiene engines into **GuardGit MCP** — a clean TypeScript, AGPL-3.0 open-source **SEP-1865 MCP App** + CLI (`npx guardgit-mcp`) that runs 100% locally and read-only:

- **Pre-Commit Secret & Artifact Guard (`scan_precommit_guard`)**: Detects AWS/OpenAI/Anthropic/GitHub/Stripe/Cloudflare/JWT/PEM keys, Shannon high-entropy assignments, large/binary blobs, and generated folders (`dist/`, `node_modules/`, `*.vsix`, `*.db`). Masks secrets before returning results to the LLM and outputs exact `git rm --cached` + `.gitignore` fixes.
- **Structural JSON Diff (`diff_structural_json`)**: Zero-dependency semantic key-level and keyed-array diffing with breaking-change heuristics (removed i18n keys, `tsconfig` strictness weakening, major dependency bumps, type flips).
- **Blast-Radius & `git merge-tree` Dry-Run (`analyze_blast_radius`)**: Scores change spread across sensitive surfaces (auth, migrations, CI/CD, API contracts) and runs in-memory `git merge-tree --write-tree` conflict detection without touching your index or working tree.
- **Atomic Commit Splitter (`plan_atomic_commits`)**: Withholds blocked secrets/artifacts and groups safe changes into logically ordered Conventional Commits.
- **Interactive SEP-1865 Cockpit**: Single-file bundled HTML (`ui://guardgit/cockpit.html`, zero external CDN calls) that adapts to host light/dark theme variables.

Repo: https://github.com/Hessam-Mamagani/guardgit-mcp
Install: `npx guardgit-mcp`

Would love feedback on additional secret rules, breaking-change config heuristics (Helm/K8s/Terraform), or pre-commit hook ergonomics.

---

## 2. Reddit Posts

### r/mcp
**Title:**
I built GuardGit MCP — an AGPL-3.0 open-source SEP-1865 MCP App that gives AI coding agents a pre-commit DevSecOps cockpit (secret guard, structural JSON diff, read-only `git merge-tree` advisor & atomic commit splitter)

**Body:**
Built this because autonomous coding agents are fast at writing code and equally fast at staging `.env` files, bloating diffs with minified JSON, or making 30-file mega-commits.

**What GuardGit MCP ships:**
- 5 MCP tools (`open_guardgit_cockpit`, `scan_precommit_guard`, `diff_structural_json`, `analyze_blast_radius`, `plan_atomic_commits`), all working with `{}` defaults.
- Full **SEP-1865 MCP App UI** (`ui://guardgit/cockpit.html`) built with `@modelcontextprotocol/ext-apps` and bundled into a single self-contained HTML file (no CDN dependencies, host theme-adaptive via `applyHostStyleVariables`).
- Ready-to-copy Antigravity plugin (`aux_pane` + `global` entrypoints), plus standard stdio config for Claude Desktop, Claude Code, and Cursor.
- Standalone CLI (`npx guardgit-mcp scan . --strict`) for CI and local pre-commit hooks.
- 100% read-only Git execution (uses `git merge-tree --write-tree` in memory so it never mutates your working tree) and automatic secret masking so credentials never leak into model context.

GitHub (AGPL-3.0): https://github.com/Hessam-Mamagani/guardgit-mcp

### r/ClaudeAI
**Title:**
Open-sourced a local MCP safety net for Claude Code / Desktop: catches leaked secrets, replaces unreadable JSON diffs with semantic trees, checks merge conflicts via `git merge-tree`, and splits mega-commits

**Body:**
If you let Claude Code work across large repos, you have probably caught it trying to stage a build folder, losing context on a giant JSON file, or bundling 25 edits into one commit.

I open-sourced **GuardGit MCP** (AGPL-3.0) to run right inside your MCP config (`npx -y guardgit-mcp`):
- Scans staged/unstaged diffs & untracked files for cloud/LLM tokens (OpenAI, Anthropic, AWS, GitHub, Stripe, Cloudflare, JWTs, PEM keys, high-entropy strings) and masks matches before handing results back to Claude.
- Turns minified/large JSON diffs into key-path trees with breaking-change flags.
- Runs strictly read-only `git merge-tree --write-tree` conflict checks against `main` before you push.
- Splits messy working trees into clean, ordered Conventional Commits.

Works as both a standard stdio MCP server + interactive SEP-1865 cockpit UI and a CLI tool.
Repo: https://github.com/Hessam-Mamagani/guardgit-mcp

### r/programming
**Title:**
Using `git merge-tree --write-tree`, Shannon entropy, and semantic JSON tree diffing as a zero-mutation safety gate for AI coding agents (AGPL-3.0 TypeScript)

**Body:**
Short technical write-up + AGPL-3.0 repo (**GuardGit MCP**) covering four deterministic guardrails that belong outside the LLM prompt:
1. **In-memory merge dry-runs**: `git merge-tree --write-tree --name-only <target> HEAD` detects exact conflicted files without touching the index or working tree, combined with `merge-base` overlap checks for uncommitted local edits.
2. **Keyed structural JSON diffing**: Sampling array objects to infer primary keys (`id`, `key`, `name`, `slug`) or graph edges (`source`/`target`), separating bulk-shifted fields from substantive mutations, and flagging schema/config breaking changes (`package.json` major bumps, `tsconfig` strictness drops, removed i18n keys).
3. **Deterministic secret & artifact guard**: Pattern rules + Shannon entropy (`>= 4.2` bits/char across 3+ character classes) with automatic masking so raw tokens are never returned to the agent context.
4. **Atomic Conventional Commit planning**: Deterministic domain grouping that automatically withholds blocked secrets/artifacts.

Repo (AGPL-3.0, TypeScript, zero external runtime services): https://github.com/Hessam-Mamagani/guardgit-mcp

---

## 3. LinkedIn Launch Post (EN + optional short TR follow-up comment)

**Post:**
Autonomous AI coding agents changed how fast we write code — but they also multiplied four subtle production risks:
- Accidental `.env`, API token, or SQLite/build-artifact leaks into Git history
- Unreadable single-line diffs in `package.json`, `tsconfig.json`, i18n, and infrastructure JSON
- Merge conflicts discovered only after pushing
- 30+ file mega-commits that make code review and `git bisect` painful

Today I am open-sourcing **GuardGit MCP v1.0** (AGPL-3.0 Open-Source + Commercial Dual-License) — a local, strictly read-only **SEP-1865 MCP App** and CLI (`npx guardgit-mcp`) built in TypeScript.

What it brings directly into Antigravity, Claude, Cursor, and CI pipelines:
1. Pre-Commit Secret, High-Entropy & Artifact Guard (with automatic token redaction and copyable `git rm --cached` / `.gitignore` remediation)
2. Structural JSON Diff Engine (semantic path tree, keyed array matching, and breaking-change detection)
3. Blast-Radius Heatmap & In-Memory `git merge-tree --write-tree` Dry-Run Conflict Advisor (zero working-tree mutations)
4. Atomic Conventional Commit Splitter

Everything runs locally with zero external API calls, ships with a full unit test suite, and includes a single-file theme-adaptive SEP-1865 cockpit UI.

GitHub: https://github.com/Hessam-Mamagani/guardgit-mcp

If your engineering team is adopting agentic coding workflows and wants deterministic DevSecOps guardrails before code hits Git, I would value your feedback.

#OpenSource #MCP #DevSecOps #TypeScript #SoftwareArchitecture #AIEngineering #Git

---

## 4. Pre-Publish Release Checklist (5 Minutes)

1. `cd guardgit-mcp`
2. `npm test` — confirm 100% unit tests + MCP stdio smoke test pass.
3. Verify zero private/employer strings (`git status`, inspect `package.json` author email `hessam.mamagani@gmail.com`).
4. Create public GitHub repo `Hessam-Mamagani/guardgit-mcp`, add topics (`mcp`, `mcp-app`, `sep-1865`, `devsecops`, `git`, `typescript`, `pre-commit`), and push `main` + tag `v1.0.0`.
5. Optional: `npm publish --access public` so `npx guardgit-mcp` works worldwide with zero cloning.
6. Publish Show HN (Tuesday–Thursday 15:00–17:00 TRT / 08:00–10:00 EST) + LinkedIn + `r/mcp` on the same day.
