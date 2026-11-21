import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createPrivateKey } from "crypto";
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

import { checkGitleaksInstalled, scanContent, scanPath } from "../lib/gitleaks.mjs";

// gitleaks' default global allowlist holds the regex (?i)^true|false|null$. By precedence that is
// "starts with true, OR contains false, OR ends with null", and a finding of any rule whose secret
// matched was dropped. Measured on v1.0.3 with gitleaks 8.30.1: of 120,000 texts of a private key's
// shape, 5 were not reported, each with "false" somewhere in its base64 in some letter case; and
// through wolfproof, a generated RSA key with five characters of its body spelling the word exited 0
// where the same key without it exited 1. A connection-string password that starts with "True" was
// dropped the same way. Open upstream as gitleaks/gitleaks#2293.
//
// An extending config cannot take a default allowlist entry out, so the defaults are now the copy in
// gitleaks/default.gitleaks.toml, with that regex anchored.

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULTS = path.join(HERE, "..", "gitleaks", "default.gitleaks.toml");

const haveGitleaks = checkGitleaksInstalled();
const needsBinary = { skip: haveGitleaks ? false : "gitleaks not installed" };

// A private key, the same one on every run and written nowhere in this repository: an Ed25519 key
// in PKCS#8 whose secret bytes are the hash of a sentence. It opens nothing. Not a new key each
// run: what a scanner makes of random base64 depends on the draw, which is how the miss was found.
function privateKey() {
  const secret = createHash("sha256").update("secret-guard test fixture: a key that opens nothing").digest();
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), secret]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" }).export({ type: "pkcs8", format: "pem" });
}

/** The same text with five characters of its body spelling the word. Not a usable key; a scanner cannot tell. */
function withTheWord(pem, word) {
  const lines = pem.trim().split("\n");
  lines[1] = lines[1].slice(0, 30) + word + lines[1].slice(30 + word.length);
  return lines.join("\n") + "\n";
}

const dsn = (password) => `database_url: postgres://admin:${password}@db.internal:5432/app\n`;  // identity-guard:allow test material for the scanner under test
// Twelve characters that are not a word, the same on every run.
const filler = createHash("sha256").update("secret-guard test fixture: filler").digest("hex").slice(0, 12);

function withDir(files) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secret-guard-defaults-")));
  for (const [rel, contents] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), contents);
  }
  return dir;
}

const rules = (r) => {
  assert.ok(r.ok, r.error);
  return r.findings.map((f) => f.rule);
};

test("a private key is found whatever its base64 spells", needsBinary, () => {
  const pem = privateKey();
  assert.ok(!/false/i.test(pem), "the fixture as built does not hold the word");
  assert.deepEqual(rules(scanContent(pem)), ["private-key"], "as built");
  for (const word of ["false", "FALSE", "FaLsE"]) {
    const text = withTheWord(pem, word);
    assert.ok(text.includes(word));
    assert.deepEqual(rules(scanContent(text)), ["private-key"], `with ${word} in its body, scanned as content`);
    const dir = withDir({ "deploy/server.pem": text });
    try {
      const found = scanPath(dir);
      assert.deepEqual(rules(found), ["private-key"], `with ${word} in its body, scanned as a file`);
      assert.equal(found.findings[0].startLine, 1);
      assert.equal(found.findings[0].endLine, 3, "the finding still spans the whole key");
      assert.ok(!JSON.stringify(found).includes(text.split("\n")[1]), "and the key is not in the report");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("a password that holds false, starts with true or ends with null is still a password", needsBinary, () => {
  const passwords = {
    "holds false": `${filler.slice(0, 6)}False${filler.slice(6)}`,
    "starts with true": `True${filler}`,
    "ends with null": `${filler}Null`,
  };
  for (const [what, password] of Object.entries(passwords)) {
    assert.deepEqual(rules(scanContent(dsn(password))), ["connection-string-password"], what);
  }
  const dir = withDir(Object.fromEntries(Object.values(passwords).map((p, i) => [`config/${i}.yaml`, dsn(p)])));
  try {
    assert.deepEqual(rules(scanPath(dir)), ["connection-string-password", "connection-string-password", "connection-string-password"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// What the allowlist entry was written for, and still does. Passes before the change as well.
test("a value that IS true, false or null is not a credential", needsBinary, () => {
  for (const word of ["true", "false", "null", "True", "FALSE", "Null"]) {
    assert.deepEqual(rules(scanContent(dsn(word))), [], word);
  }
});

// The defaults no longer arrive with the binary, so nothing but this says when the two have parted.
const UPSTREAM = {
  version: "8.30.1",
  // sha256 of config/gitleaks.toml at that tag.
  sha256: "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf",
  line: "    '''(?i)^true|false|null$''',",
  ours: "    '''(?i)^(?:true|false|null)$''',",
};

test("the default rules are gitleaks' own at one release, changed in one line and nowhere else", () => {
  const lines = readFileSync(DEFAULTS, "utf8").split("\n");
  const body = lines.slice(lines.findIndex((l) => !l.startsWith("# secret-guard:")));
  const changed = body.flatMap((l, i) => (l === UPSTREAM.ours ? [i] : []));
  assert.equal(changed.length, 1, "the anchored regex is there once");
  assert.ok(!body.includes(UPSTREAM.line), "and upstream's form of it is not");
  body[changed[0]] = UPSTREAM.line;
  assert.equal(
    createHash("sha256").update(body.join("\n")).digest("hex"),
    UPSTREAM.sha256,
    `with that line put back, gitleaks/default.gitleaks.toml is not gitleaks ${UPSTREAM.version}'s config/gitleaks.toml`
  );
});

test("the installed gitleaks is the release the default rules were taken from", needsBinary, () => {
  const out = spawnSync("gitleaks", ["version"], { encoding: "utf8" }).stdout.trim();
  assert.ok(
    out.includes(UPSTREAM.version),
    `gitleaks reports ${JSON.stringify(out)}, and gitleaks/default.gitleaks.toml holds the rules of ${UPSTREAM.version}: ` +
      "the rules no longer come with the binary, so take that release's config/gitleaks.toml as the top of the file describes"
  );
});

// Measured on v1.0.3: each of these came back { ok: true, findings: [] }. gitleaks ended with a
// fatal error and no report, or reported "[]" for a path that is not there, and both read as clean.
test("a scan that did not happen is not a clean scan", needsBinary, () => {
  const dir = withDir({ "extends-nothing.toml": '[extend]\npath = "not-there.toml"\n', "tree/app.py": "x = 1\n" });
  try {
    const tree = path.join(dir, "tree");

    const missing = scanPath(tree, { configPath: path.join(dir, "no-such-config.toml") });
    assert.equal(missing.ok, false, "a config that is not there");
    assert.match(missing.error, /no-such-config\.toml is not there/);
    assert.equal(scanContent("x = 1\n", { configPath: path.join(dir, "no-such-config.toml") }).ok, false);

    const broken = scanPath(tree, { configPath: path.join(dir, "extends-nothing.toml") });
    assert.equal(broken.ok, false, "a config whose [extend] names a file that is not there");
    assert.match(broken.error, /not-there\.toml/, "and the error says which");
    assert.ok(!broken.error.includes("\x1b["), "without terminal colour codes");
    assert.equal(scanContent("x = 1\n", { configPath: path.join(dir, "extends-nothing.toml") }).ok, false);

    const nowhere = scanPath(path.join(dir, "no-such-directory"));
    assert.equal(nowhere.ok, false, "a path that is not there");
    assert.match(nowhere.error, /no-such-directory is not there/);

    // And the scans that did happen still say so.
    assert.deepEqual(scanPath(tree), { ok: true, findings: [] });
    assert.deepEqual(scanContent(""), { ok: true, findings: [] });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// gitleaks is started in the config's directory now, so a relative path must be settled first.
// Passes before the change as well: there, gitleaks was started where the caller was.
test("a relative path is read from where the caller is, not from where the rules are", needsBinary, () => {
  const dir = withDir({ "project/config.yaml": dsn(`${filler}xyz`), "project/.keep": "" });
  const was = process.cwd();
  try {
    process.chdir(dir);
    assert.deepEqual(rules(scanPath("project")), ["connection-string-password"]);
    assert.deepEqual(rules(scanPath(".")), ["connection-string-password"]);
  } finally {
    process.chdir(was);
    rmSync(dir, { recursive: true, force: true });
  }
});
