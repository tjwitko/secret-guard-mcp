import { spawnSync } from "child_process";
import { fileURLToPath } from "url";
import path from "path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_CONFIG = path.join(HERE, "..", "gitleaks", "extra-rules.toml");

// No shell:true — args-array invocation only, same reasoning as dep-audit-mcp's osv-scanner
// spawn (Node flags shell:true+args as unsafe in general, DEP0190). A missing binary surfaces as
// spawnSync's own .error rather than a shell exit code.
export function checkGitleaksInstalled() {
  return !spawnSync("gitleaks", ["version"], { encoding: "utf8" }).error;
}

export const NOT_INSTALLED_MESSAGE =
  "gitleaks is not installed or not on PATH. Install it with `brew install gitleaks` and retry.";

// gitleaks' generic rules are keyword-proximity + entropy heuristics rather than a vendor's
// documented credential format. They are the main source of false positives (a base64 blob, a
// test fixture, a lockfile hash), so findings from them are marked instead of being presented
// with the same confidence as `aws-access-token` or `private-key`.
//
// This is a confidence flag, not a severity scale. Inventing severities gitleaks does not
// publish would mean putting a number on a judgement the tool never made.
const HEURISTIC_RULES = new Set(["generic-api-key", "jwt", "curl-auth-header", "authenticated-url"]);

// Defence in depth over `--redact`. Every finding is rewritten here so that a gitleaks upgrade
// changing the flag's behaviour, or a future call site forgetting it, still cannot put plaintext
// credential material into a tool response.
//
// The stakes are specific to an agent loop: unlike CI, where a finding lands in a build log, a
// finding here is fed straight back into a model's context, persisted in the run transcript, and
// echoed into any log capturing either. A scanner that prints the secret it found becomes the
// leak it exists to prevent.
export function normalizeFindings(rawFindings, { pathLabel } = {}) {
  return (rawFindings || []).map((f) => ({
    rule: f.RuleID,
    description: f.Description,
    file: pathLabel ?? f.File ?? "",
    startLine: f.StartLine,
    endLine: f.EndLine,
    entropy: f.Entropy,
    heuristic: HEURISTIC_RULES.has(f.RuleID),
    // Never the value. Never `Match` either — with --redact gitleaks still returns the
    // characters bracketing the secret, which is enough to reconstruct part of it.
    secret: "<redacted>",
    // Stable id for allowlisting a confirmed false positive in a .gitleaksignore file.
    fingerprint: f.Fingerprint,
  }));
}

function parseReport(stdout) {
  const text = (stdout || "").trim();
  if (!text) return [];
  return JSON.parse(text);
}

function baseArgs(configPath) {
  return [
    "-f",
    "json",
    "-r",
    "-", // report to stdout
    "--no-banner",
    "--redact",
    "--log-level",
    "error",
    "-c",
    configPath || DEFAULT_CONFIG,
    "--timeout",
    "120",
  ];
}

// gitleaks exits 1 when it finds leaks — success-with-results, not failure. Only a run that
// produced no parseable JSON is an actual error. Same shape as osv-scanner's exit-1 behaviour in
// dep-audit-mcp.
function runGitleaks(args, input) {
  const result = spawnSync("gitleaks", args, {
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024,
    ...(input === undefined ? {} : { input }),
  });

  if (result.error) {
    return { ok: false, error: `gitleaks failed to run: ${result.error.message}` };
  }

  try {
    return { ok: true, findings: parseReport(result.stdout) };
  } catch {
    return {
      ok: false,
      error:
        `gitleaks produced no parseable output (exit ${result.status}). ` +
        `stderr: ${result.stderr?.slice(0, 2000) || "(empty)"}`,
    };
  }
}

export function scanPath(targetPath, { configPath } = {}) {
  // `-i <target>` points gitleaks at the scanned project's own .gitleaksignore rather than the
  // default ".", which resolves against THIS server's working directory — so without it a
  // project's allowlisted false positives would be silently ignored and keep failing.
  const args = ["dir", targetPath, ...baseArgs(configPath), "-i", targetPath];
  const result = runGitleaks(args);
  if (!result.ok) return result;
  return { ok: true, findings: normalizeFindings(result.findings) };
}

// Scans a string that has not been written anywhere. This is the reason `gitleaks stdin` is used
// instead of writing a temp file and scanning that: a pre-write check whose implementation writes
// the candidate secret to disk has already done the thing it was called to prevent.
//
// Trade-off worth knowing: with no filename, gitleaks cannot apply path-based allowlists or a
// .gitleaksignore, so scan_content can report a finding that scan_path on the same bytes would
// suppress.
export function scanContent(content, { pathLabel, configPath } = {}) {
  const result = runGitleaks(["stdin", ...baseArgs(configPath)], content);
  if (!result.ok) return result;
  return { ok: true, findings: normalizeFindings(result.findings, { pathLabel: pathLabel || "(content)" }) };
}

export function summarize(findings) {
  const byRule = {};
  for (const f of findings) byRule[f.rule] = (byRule[f.rule] || 0) + 1;
  return {
    total: findings.length,
    confirmed: findings.filter((f) => !f.heuristic).length,
    heuristic: findings.filter((f) => f.heuristic).length,
    byRule,
  };
}

// A secret found in a file that is already committed is not fixed by deleting the line: it stays
// in git history, and anyone who fetched the repo already has it. Models reliably "fix" these by
// removing the text and reporting success, so the remediation text has to say this outright.
export const REMEDIATION =
  "Move the value out of the file (environment variable, secret manager, or a workload identity " +
  "that needs no static credential) and reference it indirectly. If the file was already " +
  "committed, deleting the line does NOT fix it — the value remains in git history and must be " +
  "treated as compromised and rotated at the provider. To dismiss a confirmed false positive, " +
  "add its fingerprint to a .gitleaksignore file rather than weakening the scan.";
