import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { checkGitleaksInstalled, scanContent, scanPath, skipped } from "../lib/gitleaks.mjs";

// A scan that left part of the tree unread is not a clean scan.
//
// gitleaks walks past what it cannot read, prints "[]" and exits 0. Measured on 8.30.1 at 86800b5,
// each tree below with a token in the part not read came back { ok: true, findings: [] }. gitleaks
// says what it skipped only in its log, at a level the wrapper did not ask for, and the wrapper did
// not read the log when a report arrived.

// Assembled at run time, as in gitleaks.test.mjs: Stripe's own published example.
const STRIPE = ["sk", "live", "4eC39HqLyjWDarjtT1zdp7dc"].join("_");
const SECRET = `STRIPE = "${STRIPE}"\n`;

const needsBinary = { skip: checkGitleaksInstalled() ? false : "gitleaks not installed" };

// Every tree made here, with what was locked in it, so the modes can be put back before removal.
function tree(files) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secret-guard-skipped-")));
  for (const [rel, contents] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), contents);
  }
  const locked = [];
  return {
    dir,
    lock(rel, mode = 0o000) {
      chmodSync(path.join(dir, rel), mode);
      locked.push(rel);
      return path.join(dir, rel);
    },
    remove() {
      for (const rel of locked.reverse()) chmodSync(path.join(dir, rel), 0o755);
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

// The premise of the tests below: this process cannot read a file of mode 000. An administrator
// can, and then there is nothing to test.
function modesHold() {
  const t = tree({ "probe.txt": "x\n" });
  try {
    readFileSync(t.lock("probe.txt"));
    return false;
  } catch {
    return true;
  } finally {
    t.remove();
  }
}
const needsModes = { skip: needsBinary.skip || (modesHold() ? false : "this user reads files of mode 000, so nothing here is unreadable") };

test("a directory that cannot be opened is an error that names it, not a clean scan", needsModes, () => {
  const t = tree({ "ok.py": "x = 1\n", "locked/app.py": SECRET });
  try {
    const locked = t.lock("locked");
    const r = scanPath(t.dir);
    assert.equal(r.ok, false, "the token is in the directory that was not read");
    assert.deepEqual(r.skipped, [{ path: locked, reason: "permission denied" }]);
    assert.equal(r.error, `not a clean scan: gitleaks did not read ${locked} (permission denied)`);
    assert.deepEqual(r.findings, []);
  } finally {
    t.remove();
  }
});

test("a file that cannot be opened is an error that names it", needsModes, () => {
  const t = tree({ "ok.py": "x = 1\n", "app.py": SECRET });
  try {
    const locked = t.lock("app.py");
    const r = scanPath(t.dir);
    assert.equal(r.ok, false);
    assert.deepEqual(r.skipped, [{ path: locked, reason: "permission denied" }]);
    // And when it is the one file asked for.
    const alone = scanPath(locked);
    assert.equal(alone.ok, false);
    assert.deepEqual(alone.skipped, [{ path: locked, reason: "permission denied" }]);
  } finally {
    t.remove();
  }
});

// Listed but not entered: gitleaks reports this one at "error", which the wrapper did ask for and
// then did not read.
test("a directory that can be listed and not entered is an error that names what was in it", needsModes, () => {
  const t = tree({ "ok.py": "x = 1\n", "listed/app.py": SECRET });
  try {
    t.lock("listed", 0o444);
    const r = scanPath(t.dir);
    assert.equal(r.ok, false);
    assert.deepEqual(r.skipped.map((s) => s.path), [path.join(t.dir, "listed", "app.py")]);
    assert.match(r.skipped[0].reason, /^could not get info: lstat .*permission denied$/);
  } finally {
    t.remove();
  }
});

// What was found is still a fact, and a caller that blocks on findings must still block: an error
// here would turn "blocked" into "could not run".
test("with a finding elsewhere, the finding is reported and the unread path listed beside it", needsModes, () => {
  const t = tree({ "seen.py": SECRET, "app.py": SECRET });
  try {
    const locked = t.lock("app.py");
    const r = scanPath(t.dir);
    assert.equal(r.ok, true, r.error);
    assert.deepEqual(r.findings.map((f) => [f.rule, f.file]), [["stripe-access-token", path.join(t.dir, "seen.py")]]);
    assert.deepEqual(r.skipped, [{ path: locked, reason: "permission denied" }]);
  } finally {
    t.remove();
  }
});

// gitleaks does not try to read these, so there is nothing it failed to read: an unreadable file
// under a path its rules never look at, and an empty file. A result with nothing skipped has the
// shape it always had.
test("what gitleaks never tries to read is not reported as skipped", needsModes, () => {
  const t = tree({ "ok.py": "x = 1\n", "node_modules/x/app.py": SECRET, "empty.py": "" });
  try {
    t.lock("node_modules/x/app.py");
    t.lock("empty.py");
    // Complete, and it says what it left unread by design: the tree it did not go into.
    assert.deepEqual(scanPath(t.dir), { ok: true, findings: [], unreadCount: 1 });
    assert.deepEqual(scanPath(t.dir, { unreadOf: ["node_modules/x/app.py", "ok.py"] }), { ok: true, findings: [], unreadCount: 1, unread: [{ path: path.join(t.dir, "node_modules"), kind: "directory" }] });
  } finally {
    t.remove();
  }
});

// The same through the server, which is how a gate calls it. The first block of an error is the
// sentence, and callers that read only that block are unchanged. The second is the list, for a
// caller that already knows of a directory it cannot read and has its own rule for it.
test("the server: an error with the unread paths as a second block, or the report with a skipped list", needsModes, async () => {
  const t = tree({ "ok.py": "x = 1\n", "data/app.py": SECRET });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL("../index.mjs", import.meta.url))],
    env: { PATH: process.env.PATH, HOME: process.env.HOME || "", SCAN_ROOT: t.dir },
    stderr: "ignore",
  });
  const client = new Client({ name: "skipped-test", version: "1" });
  try {
    const locked = t.lock("data");
    await client.connect(transport);
    const error = await client.callTool({ name: "scan_path", arguments: { target: "." } });
    assert.equal(error.isError, true);
    assert.equal(error.content[0].text, `not a clean scan: gitleaks did not read ${locked} (permission denied)`);
    assert.deepEqual(JSON.parse(error.content[1].text), {
      target: t.dir,
      incomplete: true,
      skipped: [{ path: locked, reason: "permission denied" }],
    });

    writeFileSync(path.join(t.dir, "seen.py"), SECRET);
    const found = await client.callTool({ name: "scan_path", arguments: { target: "." } });
    assert.ok(!found.isError);
    assert.equal(found.content.length, 1);
    const report = JSON.parse(found.content[0].text);
    assert.equal(report.clean, false);
    assert.equal(report.summary.total, 1);
    assert.deepEqual(report.skipped, [{ path: locked, reason: "permission denied" }]);

    // An error for another reason has one block, as before.
    const absent = await client.callTool({ name: "scan_path", arguments: { target: "nowhere" } });
    assert.equal(absent.isError, true);
    assert.equal(absent.content.length, 1);
  } finally {
    await client.close();
    t.remove();
  }
});

// gitleaks takes -i as a directory to look in or as the ignore file itself, and the wrapper passed
// the target. For one file that made the file its own ignore file: measured on 86800b5, this file
// came back clean, and at --log-level warn its other lines were printed to stderr as invalid
// entries, the token's line among them.
test("a file scanned alone is not read as its own ignore file", needsBinary, () => {
  const t = tree({ "plain.py": `x = 1\n${SECRET}` });
  try {
    const self = path.join(t.dir, "self.py");
    writeFileSync(self, `${self}:stripe-access-token:2\n${SECRET}`);
    const r = scanPath(self);
    assert.equal(r.ok, true, r.error);
    assert.deepEqual(r.findings.map((f) => [f.rule, f.startLine]), [["stripe-access-token", 2]]);

    // The ignore file of the directory it is in still applies, which is what -i is for.
    const plain = path.join(t.dir, "plain.py");
    const found = scanPath(plain);
    assert.equal(found.findings.length, 1);
    writeFileSync(path.join(t.dir, ".gitleaksignore"), found.findings[0].fingerprint + "\n");
    assert.deepEqual(scanPath(plain), { ok: true, findings: [] });
  } finally {
    t.remove();
  }
});

// The lines are gitleaks 8.30.1's own, copied from runs of the trees above and of a scan stopped by
// --timeout, with the paths shortened.
test("skipped() reads gitleaks' log: what it did not read, and nothing else", () => {
  assert.deepEqual(skipped(""), []);
  assert.deepEqual(skipped(undefined), []);
  // A scan that read everything says at most this.
  assert.deepEqual(skipped("9:36AM WRN leaks found: 1\n"), []);

  assert.deepEqual(
    skipped(
      [
        '9:36AM WRN skipping directory error="permission denied" path=/p/locked',
        "9:36AM WRN skipping file: permission denied path=/p/app.py",
        '9:36AM ERR skipping file: could not get info error="lstat /p/nox/app.py: permission denied" path=/p/nox/app.py',
        '9:36AM WRN skipping file: permission denied path="/p/my notes.txt"',
        "9:36AM WRN leaks found: 2",
      ].join("\n")
    ),
    [
      { path: "/p/locked", reason: "permission denied" },
      { path: "/p/app.py", reason: "permission denied" },
      { path: "/p/nox/app.py", reason: "could not get info: lstat /p/nox/app.py: permission denied" },
      { path: "/p/my notes.txt", reason: "permission denied" },
    ]
  );

  // A scan that ran out of time: four lines, said once.
  assert.deepEqual(
    skipped(
      [
        '9:36AM ERR failed scan directory error="context deadline exceeded"',
        "9:36AM WRN scanned ~82895616 bytes (82.90 MB)",
        "9:36AM WRN partial scan completed in 993ms",
        "9:36AM WRN no leaks found in partial scan",
      ].join("\n")
    ),
    [{ path: null, reason: "the scan stopped before it finished: context deadline exceeded" }]
  );

  // Warnings about something else. The second quotes a line of whatever file it was reading, so it
  // must not come back in any form.
  const quoted = skipped(
    [
      `9:37AM WRN Invalid .gitleaksignore entry fingerprint="STRIPE = \\"${STRIPE}\\""`,
      '9:37AM WRN Disabled rule doesn\'t exist in extended config. config=default rule-id=nope',
    ].join("\n")
  );
  assert.deepEqual(quoted, []);

  // A line it has not seen before is counted, in the line's own words: a gitleaks that words a skip
  // differently is noticed. Its other kinds, from the source: a walk error, a read that failed
  // part-way, an error with no message.
  assert.deepEqual(
    skipped(
      [
        '9:36AM WRN skipping error="lstat /p/gone: no such file or directory" path=/p/gone',
        '9:36AM WRN issue reading file error="read /p/big.txt: input/output error"',
        '9:36AM ERR error="could not read file: could not determine type: boom" path=/p/odd.bin',
        "9:36AM WRN something new in a later release path=/p/x",
        "\x1b[33m9:36AM WRN\x1b[0m skipping file: permission denied path=/p/coloured.py",
      ].join("\n")
    ),
    [
      { path: "/p/gone", reason: "lstat /p/gone: no such file or directory" },
      { path: null, reason: "issue reading file: read /p/big.txt: input/output error" },
      { path: "/p/odd.bin", reason: "could not read file: could not determine type: boom" },
      { path: "/p/x", reason: "something new in a later release" },
      { path: "/p/coloured.py", reason: "permission denied" },
    ]
  );
});

// A scan stopped by its time limit writes "[]" and exits 1, which the wrapper read as a clean scan:
// it takes exit 1 for "findings", and there were none. The limit is 120 seconds, so the real thing
// is not run here; a stand-in for gitleaks prints what the real one printed (measured with
// --timeout 1 on a tree of 1.6 GB) and the wrapper is run against it.
//
// The stand-in reads its input first, as gitleaks does. It did not, and scanContent writes the
// content to it: when the stand-in had gone before the write, the wrapper got EPIPE and the test
// failed on "gitleaks failed to run: spawnSync gitleaks EPIPE". Measured at 0e211e4, 400 runs of
// this child, 12 at a time: 6 on macOS, and 195 in a node:22 container on Linux (1 of 300 one at a
// time). `reads: false` is for the tests of exactly that, and `content` is the JavaScript for what
// scanContent is given.
const MORE_THAN_A_PIPE_HOLDS = '"x = 1\\n".repeat(200000)';
function withStandIn(script, fn, { reads = true, content = '"x = 1\\n"' } = {}) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secret-guard-standin-")));
  try {
    writeFileSync(path.join(dir, "gitleaks"), `#!/bin/sh\n${reads ? "cat > /dev/null\n" : ""}${script}\n`, { mode: 0o755 });
    mkdirSync(path.join(dir, "project"));
    writeFileSync(path.join(dir, "project", "ok.py"), "x = 1\n");
    const lib = pathToFileURL(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "lib", "gitleaks.mjs")).href;
    const code = `const { scanPath, scanContent } = await import(${JSON.stringify(lib)}); console.log(JSON.stringify([scanPath(${JSON.stringify(path.join(dir, "project"))}), scanContent(${content})]));`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${dir}${path.delimiter}${process.env.PATH}` },
    });
    assert.equal(r.status, 0, r.stderr);
    return fn(JSON.parse(r.stdout));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a scan that stopped before it finished is an error, though it wrote a report", () => {
  const stopped = [
    `echo '9:36AM ERR failed scan directory error="context deadline exceeded"' >&2`,
    `echo '9:36AM WRN scanned ~82895616 bytes (82.90 MB)' >&2`,
    `echo '9:36AM WRN partial scan completed in 993ms' >&2`,
    `echo '9:36AM WRN no leaks found in partial scan' >&2`,
    `echo '[]'`,
    `exit 1`,
  ].join("\n");
  withStandIn(stopped, (results) => {
    for (const r of results) {
      assert.equal(r.ok, false);
      assert.equal(r.error, "not a clean scan: the scan stopped before it finished: context deadline exceeded");
    }
  });
  // The same held without the log: gitleaks exits non-zero for findings or for a scan that did not
  // finish, so a non-zero exit with no finding is the second, whatever it printed.
  withStandIn(`echo '[]'\nexit 1`, (results) => {
    for (const r of results) {
      assert.equal(r.ok, false);
      assert.match(r.error, /^not a clean scan: gitleaks exited 1 with no finding, which it does when a scan did not finish$/);
    }
  });
  // And the stand-in is believed when it says the scan was whole.
  withStandIn(`echo '[]'\nexit 0`, (results) => {
    assert.deepEqual(results, [{ ok: true, findings: [] }, { ok: true, findings: [] }]);
  });
});

// gitleaks ending before it has read the content it was given. The content is more than a pipe
// holds, so the write cannot finish and the wrapper gets EPIPE every time, where with a few bytes
// it is a race. At 0e211e4 each of these came back "gitleaks failed to run: spawnSync gitleaks
// EPIPE": gitleaks' own reason was replaced, and so was a finding it had reported.
test("gitleaks ending before it has read the content is said in its own words, and is never a clean scan", () => {
  const early = { reads: false, content: MORE_THAN_A_PIPE_HOLDS };
  // It says why and writes no report: a config it could not load does this.
  const fatal = `echo '9:36AM FTL Failed to load config error="failed to load extended config, err: open not-there.toml: no such file or directory"' >&2\nexit 1`;
  withStandIn(fatal, ([, content]) => {
    assert.equal(content.ok, false);
    assert.equal(
      content.error,
      'gitleaks produced no parseable output (exit 1). stderr: 9:36AM FTL Failed to load config error="failed to load extended config, err: open not-there.toml: no such file or directory"'
    );
  }, early);
  // The same words when the content was small enough to be written before it went: what a caller
  // is told does not depend on how much it handed over.
  withStandIn(fatal, ([, content]) => {
    assert.match(content.error, /^gitleaks produced no parseable output \(exit 1\)\. stderr: 9:36AM FTL Failed to load config /);
  });
  // It panics, which is how 8.30.1 ends on a rule whose regex does not compile: the first line is
  // the reason, and the stack under it is not passed on.
  withStandIn(`echo 'panic: regexp: Compile(\`(\`): error parsing regexp' >&2\necho >&2\necho 'goroutine 1 [running]:' >&2\nexit 2`, ([, content]) => {
    assert.equal(content.ok, false);
    assert.equal(content.error, "gitleaks produced no parseable output (exit 2). stderr: panic: regexp: Compile(`(`): error parsing regexp");
  }, early);
  // It reports no findings and exits 0, having read none of the content: not a clean scan.
  withStandIn(`echo '[]'\nexit 0`, ([, content]) => {
    assert.deepEqual(content, {
      ok: false,
      error: "not a clean scan: gitleaks ended before it had read all of the content",
      findings: [],
      skipped: [{ path: null, reason: "gitleaks ended before it had read all of the content" }],
    });
  }, early);
  // It reports a finding: the finding stands, and that it stopped early is listed beside it.
  withStandIn(`echo '[{"RuleID":"generic-api-key","StartLine":3,"EndLine":3,"Fingerprint":":generic-api-key:3"}]'\nexit 1`, ([, content]) => {
    assert.equal(content.ok, true);
    assert.deepEqual(content.findings.map((f) => [f.rule, f.startLine, f.secret]), [["generic-api-key", 3, "<redacted>"]]);
    assert.deepEqual(content.skipped, [{ path: null, reason: "gitleaks ended before it had read all of the content" }]);
  }, early);
});

test("the real gitleaks ending before it has read the content: its reason comes through", needsBinary, () => {
  const t = tree({ "extends-nothing.toml": '[extend]\npath = "not-there.toml"\n', "bad-regex.toml": 'title = "x"\n[[rules]]\nid = "r"\nregex = "("\n' });
  try {
    const big = "x = 1\n".repeat(200000);
    for (const content of [big, "x = 1\n"]) {
      const missing = scanContent(content, { configPath: path.join(t.dir, "extends-nothing.toml") });
      assert.equal(missing.ok, false);
      assert.match(missing.error, /^gitleaks produced no parseable output \(exit 1\)\. stderr: .*not-there\.toml/);
      const panics = scanContent(content, { configPath: path.join(t.dir, "bad-regex.toml") });
      assert.equal(panics.ok, false);
      assert.match(panics.error, /^gitleaks produced no parseable output \(exit 2\)\. stderr: panic: regexp: /);
      assert.ok(!panics.error.includes("goroutine"), "the stack is not passed on");
    }
  } finally {
    t.remove();
  }
});
