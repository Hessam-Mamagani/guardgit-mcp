import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: path.resolve(__dirname, "ui"),
  plugins: [viteSingleFile()],
  build: {
    outDir: path.resolve(__dirname, "dist/ui"),
    emptyOutDir: true,
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    target: "es2022",
    rollupOptions: {
      input: path.resolve(__dirname, "ui/cockpit.html"),
    },
  },
});
