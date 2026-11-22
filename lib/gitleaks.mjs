import { spawnSync } from "child_process";
import { existsSync, readFileSync, realpathSync, statSync } from "fs";
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

// A scan that ran always writes a report: a clean one is "[]" (measured on a clean directory, an
// empty directory and clean stdin). Nothing at all on stdout is gitleaks ending before it scanned.
// That was read as no findings: measured on v1.0.3, a config that does not exist, or one whose
// [extend] names a file that is not there, exited 1 with a fatal error on stderr and came back
// from here as { ok: true, findings: [] } -- a scan that never ran, reported clean.
function parseReport(stdout) {
  const text = (stdout || "").trim();
  if (!text) throw new Error("gitleaks wrote no report");
  return JSON.parse(text);
}

// The config in use, as a whole path: gitleaks is started in that file's directory (runGitleaks),
// so a name relative to the caller's directory has to be settled before then.
const configFile = (configPath) => path.resolve(configPath || DEFAULT_CONFIG);

function baseArgs(configPath) {
  return [
    "-f",
    "json",
    "-r",
    "-", // report to stdout
    "--no-banner",
    "--redact",
    // Not "error": what gitleaks could not read it says at "warn", and skipped() reads that.
    "--log-level",
    "warn",
    "--no-color",
    "-c",
    configFile(configPath),
    "--timeout",
    "120",
  ];
}

const ANSI = /\x1b\[[0-9;]*m/g;

// Warnings that are not about a path gitleaks failed to read.
//
// "Invalid .gitleaksignore entry" prints the offending line, so it is also never passed on: see
// ignorePathFor for what that line once was.
const NOT_ABOUT_READING = [
  /^leaks found: \d+$/,
  /^Invalid \.gitleaksignore entry$/,
  /^Error closing \.gitleaksignore file$/,
  /^config requires a newer Gitleaks version/,
  /^Disabled rule doesn't exist in extended config\.$/,
];

const logValue = (text) => {
  if (!text.startsWith('"')) return text;
  try {
    return JSON.parse(text);
  } catch {
    return text.slice(1, -1);
  }
};

// What gitleaks said it did not read, from its log: [{ path, reason }], path null when the line
// names none.
//
// gitleaks walks past what it cannot read, reports "[]" and exits 0. Measured on 8.30.1, each of
// these came back from scanPath as { ok: true, findings: [] } with a credential in the part not
// read:
//
//   a directory of mode 000      WRN skipping directory error="permission denied" path=...
//   a file of mode 000           WRN skipping file: permission denied path=...
//   a directory of mode 444      ERR skipping file: could not get info error="lstat ...: permission denied" path=...
//   the time limit reached       ERR failed scan directory error="context deadline exceeded", then
//                                WRN partial scan completed in ..., with "[]" and exit 1
//
// and its source has more of the kind: "skipping" for any other error while walking, "issue
// reading file" for a read that failed part-way, and an error with no message for a file whose
// type or content could not be read. The first two were printed only at --log-level warn, and the
// wrapper asked for "error" and did not read stderr when a report arrived.
//
// So every WRN and ERR line counts unless it is one of the few known to be about something else.
// A line this does not recognise is counted, with the line's own words as the reason: a gitleaks
// that words a skip differently should be noticed, not believed.
//
// Not covered, because gitleaks says nothing at this level or at any: a file it could not open for
// a reason other than permission is skipped without a log line (sources/files.go), and archives,
// files whose first bytes say "application/..." and the paths of the allowlist are left unread by
// design. gitleaks/unread-paths.json lists the ones a name can say.
export function skipped(stderr) {
  const out = [];
  let partial = false;
  let stopped = false;
  for (const raw of (stderr || "").replace(ANSI, "").split("\n")) {
    const line = /^\S+\s+(WRN|ERR)\s*(.*)$/.exec(raw.trim());
    if (!line) continue;
    const rest = line[2];
    const firstField = rest.search(/(?:^|\s)[A-Za-z_][\w-]*=/);
    const message = (firstField === -1 ? rest : rest.slice(0, firstField)).trim();
    if (NOT_ABOUT_READING.some((re) => re.test(message))) continue;
    const field = (name) => {
      const m = new RegExp(`(?:^|\\s)${name}=("(?:[^"\\\\]|\\\\.)*"|\\S*)`).exec(rest);
      return m ? logValue(m[1]) : null;
    };
    const error = field("error");
    // One scan that stopped early is four lines; it is said once.
    if (/partial scan|^scanned ~/.test(message)) {
      partial = true;
      continue;
    }
    if (/^failed scan/.test(message)) {
      stopped = true;
      out.push({ path: null, reason: `the scan stopped before it finished${error ? `: ${error}` : ""}` });
      continue;
    }
    const reason = [message.replace(/^skipping(?: (?:file|directory))?:?\s*/, ""), error].filter(Boolean);
    out.push({ path: field("path"), reason: [...new Set(reason)].join(": ") || "not read" });
  }
  if (partial && !stopped) out.push({ path: null, reason: "the scan stopped before it finished" });
  return out;
}

// In words: the paths, ten at most, then anything said of the scan as a whole.
const describeSkipped = (list) => {
  const paths = list.filter((s) => s.path);
  const shown = paths.slice(0, 10).map((s) => `${s.path} (${s.reason})`);
  const more = paths.length > shown.length ? `, and ${paths.length - shown.length} more` : "";
  return [
    ...(paths.length ? [`gitleaks did not read ${shown.join(", ")}${more}`] : []),
    ...list.filter((s) => !s.path).map((s) => s.reason),
  ].join("; ");
};

// What a scan that left something unread comes back as.
//
// With findings: the findings, as before, and the list beside them. What was found is a fact and a
// caller that blocks on findings must still block.
// With none: an error. "No findings" would be a statement about the whole tree, and part of it was
// not read. Every caller that reads only `ok` and `findings` is then right without changing.
function settle(result, normalize) {
  if (!result.ok) return result;
  const findings = normalize(result.findings);
  if (!result.skipped.length) return { ok: true, findings };
  if (findings.length) return { ok: true, findings, skipped: result.skipped };
  return {
    ok: false,
    error: `not a clean scan: ${describeSkipped(result.skipped)}`,
    findings: [],
    skipped: result.skipped,
  };
}

// gitleaks exits 1 when it finds leaks — success-with-results, not failure. A run that produced no
// parseable JSON is an error, and so is one that says it left something unread (settle). Same
// shape as osv-scanner's exit-1 behaviour in dep-audit-mcp.
//
// Started in the config's own directory, because gitleaks reads a config's `[extend] path` relative
// to the directory it is started in, and extra-rules.toml extends the file beside it. Every path
// handed to gitleaks is therefore a whole one.
function runGitleaks(args, input, configPath) {
  // Said here, by name: started in a directory that is not there, spawn fails with ENOENT, which
  // reads as gitleaks itself being absent.
  if (!existsSync(configFile(configPath))) {
    return { ok: false, error: `the gitleaks config ${configFile(configPath)} is not there, so nothing was scanned` };
  }
  const result = spawnSync("gitleaks", args, {
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024,
    cwd: path.dirname(configFile(configPath)),
    ...(input === undefined ? {} : { input }),
  });

  // EPIPE is gitleaks ending before it had taken all it was given on stdin, and not a failure to
  // run it: it ran, and its exit code, its report and its log are all here. Measured on 8.30.1 with
  // a config it could not load and 1.2 MB of content, 40 times of 40: "gitleaks failed to run:
  // spawnSync gitleaks EPIPE", in place of gitleaks' own line saying which file was missing. With
  // six bytes of content the write usually lands first and the reason came through, so which error
  // a caller saw depended on the size of the content and on timing.
  const endedEarly = result.error?.code === "EPIPE" && result.status !== null;
  if (result.error && !endedEarly) {
    return { ok: false, error: `gitleaks failed to run: ${result.error.message}` };
  }

  let findings;
  try {
    findings = parseReport(result.stdout);
  } catch {
    // Only what gitleaks called an error, or the first line of a panic, which is how it ends on a
    // rule whose regex does not compile. Its warnings can quote a line of a file it was reading.
    const said = (result.stderr || "")
      .replace(ANSI, "")
      .split("\n")
      .filter((l) => /^\S+\s+(ERR|FTL)\b/.test(l.trim()) || /^(panic|fatal error): /.test(l))
      .join("\n");
    return {
      ok: false,
      error: `gitleaks produced no parseable output (exit ${result.status}). stderr: ${said.slice(0, 2000) || "(empty)"}`,
    };
  }
  const unread = skipped(result.stderr);
  // A report from a gitleaks that did not take all of the content is a report on part of it.
  if (endedEarly) unread.push({ path: null, reason: "gitleaks ended before it had read all of the content" });
  // gitleaks exits non-zero for findings or for a scan that did not finish, and for nothing else.
  // Held here as well as read from the log, so that it does not rest on the log's wording.
  if (result.status !== 0 && !findings.length && !unread.length) {
    unread.push({ path: null, reason: `gitleaks exited ${result.status} with no finding, which it does when a scan did not finish` });
  }
  return { ok: true, findings, skipped: unread };
}

// The directory whose .gitleaksignore applies to a target: the target, or the directory a file is
// in. gitleaks takes -i as a directory to look in or as the ignore file itself, so handed a file to
// scan as -i it read that file as an ignore file. Measured on 8.30.1, through scanPath: a file
// holding a token on line 2 and "<its own path>:stripe-access-token:2" on line 1 came back clean,
// and at --log-level warn every other line of it was printed to stderr as an "Invalid
// .gitleaksignore entry", the token's line among them.
function ignorePathFor(target) {
  try {
    return statSync(target).isDirectory() ? target : path.dirname(target);
  } catch {
    return path.dirname(target);
  }
}

export function scanPath(targetPath, { configPath } = {}) {
  // `-i <target>` points gitleaks at the scanned project's own .gitleaksignore rather than the
  // default ".", which resolves against THIS server's working directory — so without it a
  // project's allowlisted false positives would be silently ignored and keep failing.
  //
  // A whole path, settled here against the caller's directory: gitleaks is not started in it.
  const named = path.resolve(targetPath);
  // And the real one. Given a path whose last part is a link, to a directory or to a file,
  // gitleaks reads nothing, reports "[]" and exits 0 (measured, 8.30.1), and so does it for a path
  // that does not exist: neither is a clean scan. The server settles real paths before it calls
  // this (resolveScanPath), but a caller using this file as a library got { ok: true, findings: [] }
  // for a linked directory that held a credential. The link is followed here because it is the
  // path the caller named; links met while walking the tree are still not followed. Findings and
  // fingerprints then carry the real path, the same spelling the server's have.
  let target;
  try {
    target = realpathSync(named);
  } catch (err) {
    const why = err?.code === "ENOENT" ? "is not there" : `could not be read (${err?.code || err?.message})`;
    return { ok: false, error: `${named} ${why}, so nothing was scanned` };
  }
  const args = ["dir", target, ...baseArgs(configPath), "-i", ignorePathFor(target)];
  return settle(runGitleaks(args, undefined, configPath), (found) => normalizeFindings(found));
}

// Scans a string that has not been written anywhere. This is the reason `gitleaks stdin` is used
// instead of writing a temp file and scanning that: a pre-write check whose implementation writes
// the candidate secret to disk has already done the thing it was called to prevent.
//
// Trade-off worth knowing: with no filename, gitleaks cannot apply path-based allowlists or a
// project's .gitleaksignore, so scan_content can report a finding that scan_path on the same bytes
// would suppress.
//
// One .gitleaksignore can still reach it: gitleaks reads the one in the directory it is started in,
// and a finding in content has the fingerprint ":<rule>:<line>", with no file in it. That directory
// was the caller's through v1.0.3, so a project's own ignore file holding such a line silenced this
// check for every file with that rule on that line (measured on 71f608c). It is the config's
// directory now (runGitleaks), which no scanned project writes to unless SECRET_GUARD_CONFIG
// names a config inside one.
export function scanContent(content, { pathLabel, configPath } = {}) {
  return settle(runGitleaks(["stdin", ...baseArgs(configPath)], content, configPath), (found) =>
    normalizeFindings(found, { pathLabel: pathLabel || "(content)" })
  );
}

// Files that can switch this scanner off. They are listed here, in the scanner's own library,
// because every consumer needs the same list and a control whose bypass list lives in three
// places drifts.
export const SUPPRESSION_FILES = [".gitleaksignore", ".gitleaks.toml"];

// Reads the fingerprints a project has allowlisted. Exists so suppression is never invisible.
//
// A suppressed finding produces no output at all -- the scan simply passes -- which is exactly
// what made allowlisting attractive as a way to silence a real finding rather than fix it. A
// measured agent run did this: blocked from committing a credential in a Kubernetes Secret, it
// wrote the fingerprint into .gitleaksignore and the commit went through. Reporting the count on
// every scan turns a silent bypass into a visible one.
//
// Note gitleaks discovers .gitleaksignore from the scan target itself, regardless of -i, so
// there is no way to ask it "what did you suppress?" -- the file has to be read directly.
export function readSuppressions(dir) {
  const file = `${dir}/.gitleaksignore`;
  if (!existsSync(file)) return [];
  try {
    return readFileSync(file, "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));
  } catch {
    return [];
  }
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
