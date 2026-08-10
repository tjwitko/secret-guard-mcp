import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { resolveScanPath } from "../lib/paths.mjs";
import {
  checkGitleaksInstalled,
  normalizeFindings,
  scanContent,
  scanPath,
  summarize,
} from "../lib/gitleaks.mjs";

// Test material. These are published documentation/example values or locally-generated strings,
// deliberately not anything live.
const STRIPE = "REDACTED_STRIPE_TEST_FIXTURE";
const AWS_KEY = "REDACTED_AWS_TEST_FIXTURE";
const DSN = "REDACTED_DSN_TEST_FIXTURE";

const haveGitleaks = checkGitleaksInstalled();
const needsBinary = { skip: haveGitleaks ? false : "gitleaks not installed" };

function withDir(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "secret-guard-"));
  for (const [rel, contents] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, contents);
  }
  return dir;
}

// ---------------------------------------------------------------------------
// Redaction — the property that must hold no matter what gitleaks returns
// ---------------------------------------------------------------------------

// --redact is passed on every invocation, but this is the layer that has to be true even if that
// flag changes behaviour or a future call site omits it. A finding is fed back into a model's
// context and persisted in the run transcript; a scanner that prints the secret becomes the leak.
test("normalizeFindings strips the secret even when gitleaks returns it in plaintext", () => {
  const out = normalizeFindings([
    {
      RuleID: "stripe-access-token",
      Description: "Found a Stripe token",
      Secret: STRIPE,
      Match: `STRIPE = "${STRIPE}"`,
      File: "/x/app.py",
      StartLine: 1,
      EndLine: 1,
      Entropy: 4.75,
      Fingerprint: "/x/app.py:stripe-access-token:1",
    },
  ]);

  assert.equal(out[0].secret, "<redacted>");
  assert.ok(!JSON.stringify(out).includes(STRIPE));
  // Match is dropped entirely: with --redact gitleaks still returns the characters bracketing
  // the secret, which reconstructs part of it.
  assert.equal(out[0].match, undefined);
  assert.equal(out[0].fingerprint, "/x/app.py:stripe-access-token:1");
});

test("marks heuristic rules but not vendor-format rules", () => {
  const out = normalizeFindings([
    { RuleID: "generic-api-key", Secret: "x" },
    { RuleID: "aws-access-token", Secret: "x" },
  ]);
  assert.deepEqual(
    out.map((f) => f.heuristic),
    [true, false]
  );
  assert.deepEqual(summarize(out), {
    total: 2,
    confirmed: 1,
    heuristic: 1,
    byRule: { "generic-api-key": 1, "aws-access-token": 1 },
  });
});

test("normalizeFindings tolerates an empty or missing report", () => {
  assert.deepEqual(normalizeFindings([]), []);
  assert.deepEqual(normalizeFindings(undefined), []);
});

// ---------------------------------------------------------------------------
// Path containment
// ---------------------------------------------------------------------------

// A secret scanner pointed somewhere unintended does not just read those files, it reports what
// it found in them — traversal here is credential disclosure, not merely unauthorized read.
test("refuses to scan outside the scan root", () => {
  assert.throws(() => resolveScanPath("../../../.aws", "/srv/project"), /refuses to scan outside/);
  assert.throws(() => resolveScanPath("/etc/passwd", "/srv/project"), /refuses to scan outside/);
  assert.equal(resolveScanPath("src/app.py", "/srv/project"), "/srv/project/src/app.py");
  assert.equal(resolveScanPath(".", "/srv/project"), "/srv/project");
});

// A sibling directory sharing a prefix with the root is outside it. String-prefix checks without
// the separator let /srv/project-secrets through.
test("a sibling directory with a shared prefix is outside the root", () => {
  assert.throws(() => resolveScanPath("/srv/project-secrets/x", "/srv/project"), /refuses to scan/);
});

// ---------------------------------------------------------------------------
// Real gitleaks runs
// ---------------------------------------------------------------------------

test("finds credentials across languages and config formats", needsBinary, () => {
  const dir = withDir({
    "app.py": `STRIPE = "${STRIPE}"\n`,
    "config/settings.yaml": `aws_access_key_id: ${AWS_KEY}\n`,
    "deploy/values.json": `{"token": "REDACTED_SLACK_TEST_FIXTURE"}\n`,
  });
  try {
    const { ok, findings } = scanPath(dir);
    assert.ok(ok);
    const rules = findings.map((f) => f.rule).sort();
    assert.ok(rules.includes("stripe-access-token"), rules.join(","));
    assert.ok(rules.includes("aws-access-token"), rules.join(","));
    assert.ok(rules.includes("slack-bot-token"), rules.join(","));
    assert.ok(!JSON.stringify(findings).includes(AWS_KEY));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Verified gap in gitleaks 8.30.1's default rules — this is why extra-rules.toml exists.
test("catches a password embedded in a connection string", needsBinary, () => {
  const dir = withDir({ "config.yaml": `database_url: ${DSN}\n` });
  try {
    const { findings } = scanPath(dir);
    assert.deepEqual(
      findings.map((f) => f.rule),
      ["connection-string-password"]
    );
    assert.ok(!JSON.stringify(findings).includes("sup3rs3cr3tpw"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The custom rule must not fire on documentation and templates. A scanner that flags a README
// showing a URI format gets switched off, and then it protects nothing.
test("does not flag connection-string placeholders", needsBinary, () => {
  const dir = withDir({
    "README.md": [
      "postgres://user:password@localhost:5432/db",
      "mysql://admin:changeme@host/db",
      "redis://default:${REDIS_PASSWORD}@cache:6379",
      "mongodb://user:<your-password>@cluster/db",
    ].join("\n"),
  });
  try {
    const { findings } = scanPath(dir);
    assert.deepEqual(findings, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a clean tree reports no findings", needsBinary, () => {
  const dir = withDir({ "app.py": "import os\nKEY = os.environ['API_KEY']\n" });
  try {
    const { ok, findings } = scanPath(dir);
    assert.ok(ok);
    assert.deepEqual(findings, []);
    assert.equal(summarize(findings).total, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The whole point of scan_content: catch it before the bytes land anywhere.
test("scan_content finds a secret in a string that was never written to disk", needsBinary, () => {
  const { ok, findings } = scanContent(`STRIPE = "${STRIPE}"\n`, { pathLabel: "app.py" });
  assert.ok(ok);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, "app.py");
  assert.equal(findings[0].secret, "<redacted>");
  assert.ok(!JSON.stringify(findings).includes(STRIPE));
});

test("scan_content passes clean content", needsBinary, () => {
  const { findings } = scanContent("KEY = os.environ['API_KEY']\n");
  assert.deepEqual(findings, []);
});

// A project's own allowlist has to be honoured, or every confirmed false positive keeps failing
// the gate and the gate gets removed. gitleaks resolves .gitleaksignore relative to "." by
// default, which is this server's cwd, not the scanned project.
test("honours the scanned project's .gitleaksignore", needsBinary, () => {
  const dir = withDir({ "app.py": `STRIPE = "${STRIPE}"\n` });
  try {
    const before = scanPath(dir).findings;
    assert.equal(before.length, 1);

    writeFileSync(path.join(dir, ".gitleaksignore"), before[0].fingerprint + "\n");
    assert.deepEqual(scanPath(dir).findings, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
