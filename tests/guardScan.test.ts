import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { guardScan, maskSecret, shannonEntropy } from "../src/core/guardScan.js";

describe("guardScan — Pre-Commit Secret & Artifact Guard", () => {
  it("passes cleanly on safe source files and .env.example templates", async () => {
    const res = await guardScan({
      files: [
        { path: ".env.example", status: "A", content: "OPENAI_API_KEY=your_api_key_here\nPORT=3000\n" },
        { path: "src/app.ts", status: "M", content: "export const greeting = 'hello world';\n" },
      ],
    });
    assert.equal(res.verdict, "PASS");
    assert.equal(res.riskScore, 0);
    assert.equal(res.findings.length, 0);
  });

  it("blocks .env files, private keys, and multiple provider API tokens while redacting raw secrets", async () => {
    const fakeAws = "AKIA" + "9X8Y7Z6W5V4U3T2S";
    const fakeOpenAi = "sk-proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    const fakeAnthropic = "sk-ant-api03-" + "ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210";
    const fakeGithub = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzABCD";
    const fakeStripe = "sk_live_" + "51NxYzAbCdEfGhIjKlMnOpQrStUvWx";
    const fakeCloudflare = "cf_api_token = 'aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zA2bC4dE6f'";
    const fakeJwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const fakePem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";

    const res = await guardScan({
      files: [
        { path: ".env.production", status: "A", content: `AWS_KEY=${fakeAws}\nOPENAI=${fakeOpenAi}\n` },
        {
          path: "src/config.ts",
          status: "M",
          content: [
            `const a = "${fakeAnthropic}";`,
            `const g = "${fakeGithub}";`,
            `const s = "${fakeStripe}";`,
            fakeCloudflare,
            `const token = "${fakeJwt}";`,
            fakePem,
          ].join("\n"),
        },
      ],
    });

    assert.equal(res.verdict, "BLOCK");
    assert.equal(res.riskScore, 100);
    assert.ok(res.summary.critical >= 6);

    const ruleIds = new Set(res.findings.map((f) => f.ruleId));
    assert.ok(ruleIds.has("hygiene.env_file"));
    assert.ok(ruleIds.has("secret.aws_access_key"));
    assert.ok(ruleIds.has("secret.openai_api_key"));
    assert.ok(ruleIds.has("secret.anthropic_api_key"));
    assert.ok(ruleIds.has("secret.github_token"));
    assert.ok(ruleIds.has("secret.stripe_live_key"));
    assert.ok(ruleIds.has("secret.cloudflare_token"));
    assert.ok(ruleIds.has("secret.jwt_token"));
    assert.ok(ruleIds.has("secret.private_key_block"));

    // Confirm raw secret values are never echoed unmasked
    const serialized = JSON.stringify(res);
    assert.equal(serialized.includes(fakeOpenAi), false);
    assert.equal(serialized.includes(fakeAnthropic), false);
    assert.equal(serialized.includes(fakeGithub), false);
    assert.equal(serialized.includes(fakeStripe), false);
    assert.equal(serialized.includes(fakeJwt), false);
  });

  it("detects high-entropy assigned secrets while ignoring UUIDs and placeholders", async () => {
    const highEnt = "X9#kP2mQ7$vL4nR8wT1yB6cF3zJ5hD0g";
    assert.ok(shannonEntropy(highEnt) >= 4.2);

    const res = await guardScan({
      files: [
        {
          path: "src/secrets.ts",
          status: "M",
          content: [
            `const webhook_secret = "${highEnt}";`,
            `const client_secret = "your_placeholder_secret_value_here";`,
            `const api_key = "550e8400-e29b-41d4-a716-446655440000";`,
          ].join("\n"),
        },
      ],
    });

    assert.equal(res.findings.length, 1);
    assert.equal(res.findings[0].ruleId, "secret.high_entropy");
    assert.equal(res.findings[0].line, 1);
    assert.equal(res.findings[0].maskedSnippet, maskSecret(highEnt));
  });

  it("flags large blobs (>1MB), build artifacts, VSIX packages, and local SQLite DBs with remediation commands", async () => {
    const res = await guardScan({
      largeFileThresholdBytes: 1024 * 1024,
      files: [
        { path: "node_modules/pkg/index.js", status: "U" },
        { path: "dist/bundle.js", status: "A" },
        { path: "release/tool-1.0.0.vsix", status: "U" },
        { path: "data/local-cache.db", status: "U" },
        { path: "assets/raw-dump.bin", status: "A", sizeBytes: 2.5 * 1024 * 1024, isBinary: true },
      ],
    });

    assert.equal(res.verdict, "BLOCK");
    assert.ok(res.findings.some((f) => f.ruleId === "hygiene.dir_nodemodules"));
    assert.ok(res.findings.some((f) => f.ruleId === "hygiene.dir_dist"));
    assert.ok(res.findings.some((f) => f.ruleId === "hygiene.package_artifact"));
    assert.ok(res.findings.some((f) => f.ruleId === "hygiene.local_database"));
    assert.ok(res.findings.some((f) => f.ruleId === "hygiene.large_blob"));
    assert.ok(res.suggestedGitignoreBlock.includes("node_modules/"));
    assert.ok(res.suggestedGitignoreBlock.includes("*.vsix"));
    assert.ok(res.findings.every((f) => f.remediationCommands.length > 0));
  });

  it("scans unified diff patches directly and tracks accurate line numbers", async () => {
    const fakeToken = "ghp_" + "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRr";
    const diff = [
      "diff --git a/src/auth.ts b/src/auth.ts",
      "--- a/src/auth.ts",
      "+++ b/src/auth.ts",
      "@@ -10,2 +10,4 @@",
      " const env = process.env.NODE_ENV;",
      `+const fallbackToken = "${fakeToken}";`,
      "+export default fallbackToken;",
    ].join("\n");

    const res = await guardScan({ diff });
    assert.equal(res.source, "diff");
    assert.equal(res.verdict, "BLOCK");
    assert.equal(res.findings.length, 1);
    assert.equal(res.findings[0].path, "src/auth.ts");
    assert.equal(res.findings[0].line, 11);
  });
});
