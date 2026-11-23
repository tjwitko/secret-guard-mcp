import { spawnSync } from "child_process";
import { existsSync, readFileSync, realpathSync, statSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";

import { ANSI, LIMITS, inMB, logField, unreadLine } from "./gitleaks-log.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_CONFIG = path.join(HERE, "..", "gitleaks", "extra-rules.toml");
const RUNNER = path.join(HERE, "gitleaks-run.mjs");
const UNREAD_LIST = JSON.parse(readFileSync(path.join(HERE, "..", "gitleaks", "unread-paths.json"), "utf8")).entries.map((e) => ({
  ...e,
  re: new RegExp(e.pattern, e.flags),
}));

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
    // "warn" is where gitleaks says what it could not read (skipped) and "debug" where it says what
    // it left unread by design (leftUnread). Not "trace", which is the only level that names an
    // archive: measured on the 34 calibration checkouts it is 13.6 MB of log against 3.9, and 15,595
    // of its lines hold a candidate value. At "debug" a value appears only for a finding a
    // .gitleaksignore dropped, and that line is dropped as it is read (lib/gitleaks-log.mjs).
    "--log-level",
    "debug",
    "--no-color",
    "-c",
    configFile(configPath),
    "--timeout",
    "120",
  ];
}

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

// What gitleaks left unread by design and said so at "debug": [{ path, kind, mime? }]. A scan that
// did this is complete: it is what the tool is for. It is told apart from skipped() because the
// caller decides what to do about it. Archives are not here, gitleaks names them only at "trace"
// (see baseArgs); they go by name alone, so the archive entry of unread-paths.json is exact.
export function leftUnread(stderr) {
  return (stderr || "").split("\n").map(unreadLine).filter(Boolean);
}

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
// Not covered, because gitleaks says nothing at any level: a file it could not open for
// a reason other than permission is skipped without a log line (sources/files.go). What it leaves
// unread by design is not here: see leftUnread.
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
    const field = (name) => logField(rest, name);
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
//
// `unread`, when there is any, is what gitleaks left unread by design in a tree it otherwise read
// (leftUnread). It does not make a scan incomplete. `whole` is the exception: what the caller handed
// over was itself left unread, so nothing was read and "no findings" would be about nothing.
//
// A caller gets `unreadCount`, and `unread` only for the paths it named (`unreadOf`): a list of the
// whole tree grows with the tree.
function settle(result, normalize, whole = () => null, asked = false) {
  if (!result.ok) return result;
  const findings = normalize(result.findings);
  const also = {
    ...(result.unreadCount ? { unreadCount: result.unreadCount } : {}),
    ...(asked && result.unread ? { unread: result.unread } : {}),
  };
  const notRead = whole(result);
  const skippedAll = notRead ? [...result.skipped, notRead] : result.skipped;
  if (!skippedAll.length) return { ok: true, findings, ...also };
  if (findings.length) return { ok: true, findings, skipped: skippedAll, ...also };
  return {
    ok: false,
    error: `not a clean scan: ${describeSkipped(skippedAll)}`,
    findings: [],
    skipped: skippedAll,
    ...also,
  };
}

// Said of a target gitleaks did not read at all.
const firstBytes = (u) => `gitleaks does not read a file whose first bytes are those of a binary format (${u.mime || "application"}), and text can begin with them: two letters, MZ, are enough`;

// When the path handed to scanPath was itself not read: a file on the allowlist, named as an archive
// or with a binary format's first bytes, or a directory gitleaks would not go into. gitleaks tests
// the whole path, so a checkout at .../vendor/app is such a directory: measured on 8.30.1, a token in
// it came back { ok: true, findings: [] }.
function targetNotRead(target, said, configPath) {
  let isFile = false;
  try {
    isFile = statSync(target).isFile();
  } catch {
    return null;
  }
  if (said) {
    return {
      path: target,
      reason: said.kind === "first-bytes" ? firstBytes(said) : "it is where the scan's path allowlist does not look, so nothing in it was read",
    };
  }
  const archive = UNREAD_LIST.find((e) => e.kind === "archive");
  if (isFile) return archive.re.test(target.split(path.sep).join("/")) ? { path: target, reason: "gitleaks does not read a file whose name says it is an archive" } : null;
  // A directory that does not match while everything under it does (.../vendor). Only for the
  // config this list describes.
  if (configFile(configPath) !== DEFAULT_CONFIG) return null;
  const under = `${target.split(path.sep).join("/")}/x`;
  return UNREAD_LIST.some((e) => e.directories && e.re.test(under))
    ? { path: target, reason: "everything under it is where the scan's path allowlist does not look, so nothing in it was read" }
    : null;
}

// gitleaks exits 1 when it finds leaks — success-with-results, not failure. A run that produced no
// parseable JSON is an error, and so is one that says it left something unread (settle). Same
// shape as osv-scanner's exit-1 behaviour in dep-audit-mcp.
//
// Started in the config's own directory, because gitleaks reads a config's `[extend] path` relative
// to the directory it is started in, and extra-rules.toml extends the file beside it. Every path
// handed to gitleaks is therefore a whole one.
function runGitleaks(args, input, configPath, tree = null) {
  // Said here, by name: started in a directory that is not there, spawn fails with ENOENT, which
  // reads as gitleaks itself being absent.
  if (!existsSync(configFile(configPath))) {
    return { ok: false, error: `the gitleaks config ${configFile(configPath)} is not there, so nothing was scanned` };
  }
  const result = tree ? runOverTree(args, configPath, tree) : runOnContent(args, input, configPath);
  if (result.failed) return { ok: false, error: result.failed };
  const endedEarly = result.endedEarly;

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
  for (const reason of result.ceilings || []) unread.push({ path: null, reason });
  return { ok: true, findings, skipped: unread, unread: result.unread, unreadCount: result.unreadCount, targetEntry: result.targetEntry };
}

// A tree: in a process of its own that reads the log as it is written (lib/gitleaks-run.mjs), because
// spawnSync holds a child's whole output and at "debug" that grows with the tree.
function runOverTree(args, configPath, { target, unreadOf }) {
  const run = spawnSync(process.execPath, [RUNNER], {
    input: JSON.stringify({ args, target, unreadOf }),
    encoding: "utf8",
    // Room for every limit in LIMITS, escaped as JSON. The process enforces them, so this is not reached.
    maxBuffer: 2 * (LIMITS.report + LIMITS.log) + LIMITS.unread + 1024 * 1024,
    cwd: path.dirname(configFile(configPath)),
  });
  if (run.error) return { failed: `gitleaks failed to run: ${run.error.message}` };
  let out;
  try {
    out = JSON.parse(run.stdout);
  } catch {
    return { failed: `gitleaks failed to run: the process reading its log ended with ${run.status ?? run.signal} and no result` };
  }
  if (out.spawnError) return { failed: `gitleaks failed to run: ${out.spawnError}` };
  if (out.error) return { failed: out.error };
  return out;
}

// Content: one thing, so its log is a few lines, and gitleaks is given it on stdin.
function runOnContent(args, input, configPath) {
  const result = spawnSync("gitleaks", args, {
    encoding: "utf8",
    maxBuffer: LIMITS.report,
    cwd: path.dirname(configFile(configPath)),
    input,
  });

  // EPIPE is gitleaks ending before it had taken all it was given on stdin, and not a failure to
  // run it: it ran, and its exit code, its report and its log are all here. Measured on 8.30.1 with
  // a config it could not load and 1.2 MB of content, 40 times of 40: "gitleaks failed to run:
  // spawnSync gitleaks EPIPE", in place of gitleaks' own line saying which file was missing. With
  // six bytes of content the write usually lands first and the reason came through, so which error
  // a caller saw depended on the size of the content and on timing.
  const endedEarly = result.error?.code === "EPIPE" && result.status !== null;
  if (result.error?.code === "ENOBUFS") {
    return { failed: `gitleaks' output on this content passed the ${inMB(LIMITS.report)} a scan holds, so it was not all read. Scan the content in smaller parts.` };
  }
  if (result.error && !endedEarly) return { failed: `gitleaks failed to run: ${result.error.message}` };
  const unread = leftUnread(result.stderr);
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, endedEarly, unread, unreadCount: unread.length };
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

export function scanPath(targetPath, { configPath, unreadOf } = {}) {
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
  return settle(
    runGitleaks(args, undefined, configPath, { target, unreadOf }),
    (found) => normalizeFindings(found),
    (result) => targetNotRead(target, result.targetEntry, configPath),
    Boolean(unreadOf)
  );
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
  // gitleaks skipping the only thing it was given is not a clean scan. It stays out of `unread`:
  // there is no tree for that to be part of.
  const { unreadCount, ...result } = runGitleaks(["stdin", ...baseArgs(configPath)], content, configPath);
  return settle(
    result,
    (found) => normalizeFindings(found, { pathLabel: pathLabel || "(content)" }),
    () => {
      const binary = (result.unread || []).find((u) => u.kind === "first-bytes");
      return binary ? { path: null, reason: `the content was not read: ${firstBytes(binary)}` } : null;
    }
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
