import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

const uiSrc = path.join(rootDir, "dist", "ui", "cockpit.html");
const pluginUiDir = path.join(rootDir, "plugin", "ui");
const pluginBinDir = path.join(rootDir, "plugin", "bin");

fs.mkdirSync(pluginUiDir, { recursive: true });
fs.mkdirSync(pluginBinDir, { recursive: true });

if (!fs.existsSync(uiSrc)) {
  throw new Error(`Missing built UI bundle at ${uiSrc}. Run "npm run build:ui" first.`);
}

fs.copyFileSync(uiSrc, path.join(pluginUiDir, "cockpit.html"));

await build({
  entryPoints: [path.join(rootDir, "src", "cli.ts")],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "cjs",
  outfile: path.join(pluginBinDir, "guardgit-mcp.cjs"),
  sourcemap: false,
  minify: false,
  logLevel: "info",
});

console.log("Bundled standalone Antigravity plugin into plugin/bin/guardgit-mcp.cjs and plugin/ui/cockpit.html");
