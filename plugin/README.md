# GuardGit MCP — Antigravity Plugin Bundle

This directory is a self-contained Antigravity plugin bundle (`guardgit-mcp`) built via `npm run build` from the repository root.

## Install into Antigravity

Copy this `plugin/` directory to `~/.gemini/config/plugins/guardgit-mcp/`:

### Windows (PowerShell)

```powershell
Copy-Item -Recurse -Force ".\plugin" "$HOME\.gemini\config\plugins\guardgit-mcp"
```

### macOS / Linux

```bash
cp -R ./plugin ~/.gemini/config/plugins/guardgit-mcp
```

Antigravity automatically discovers `plugin.json` and `mcp_config.json`, registers the `guardgit-mcp_guardgit` MCP server, and exposes **GuardGit Cockpit** in both the side pane (`+` menu) and the global sidebar.
