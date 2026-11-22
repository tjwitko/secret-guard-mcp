import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createPrivateKey } from "crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

import { checkGitleaksInstalled, scanPath } from "../lib/gitleaks.mjs";

// What the scan leaves unread by path, and that gitleaks/unread-paths.json says so. A caller that
// blocks a write where the scan does not look reads that file instead of parsing Go regular
// expressions, so a name it gets wrong in either direction is a hole or a false block.
//
// Credentials are assembled here at run time and written only to temporary directories.

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GITLEAKS = path.join(HERE, "..", "gitleaks");
const LIST = JSON.parse(readFileSync(path.join(GITLEAKS, "unread-paths.json"), "utf8"));
const compiled = LIST.entries.map((e) => ({ ...e, re: new RegExp(e.pattern, e.flags) }));
const listedUnread = (rel) => compiled.some((e) => e.re.test(rel));

const needsBinary = { skip: checkGitleaksInstalled() ? false : "gitleaks not installed" };

const digest = (what) => createHash("sha256").update(`secret-guard test fixture: ${what}`).digest();
const B62 = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
const chars = (what, n, set) => Array.from({ length: n }, (_, i) => set[digest(`${what} ${i}`)[0] % set.length]).join("");
const githubToken = (what) => ["gh", "p_"].join("") + chars(`token ${what}`, 36, B62);
const awsKeyId = () => ["AK", "IA"].join("") + chars("aws", 16, "BCDFGHJKLMNPQRSTVWXZ234567");
const privateKey = () =>
  createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), digest("go.sum key")]), format: "der", type: "pkcs8" })
    .export({ type: "pkcs8", format: "pem" });
const hash = (what) => `h1:${digest(`hash ${what}`).toString("base64")}`;

/** Which of `names` the real scan reports a token in, each file holding one. */
function read(names) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secret-guard-unread-")));
  try {
    for (const n of names) {
      mkdirSync(path.dirname(path.join(dir, n)), { recursive: true });
      writeFileSync(path.join(dir, n), `deploy token: ${githubToken(n)}\n`);
    }
    const r = scanPath(dir);
    assert.ok(r.ok, r.error);
    return new Set(r.findings.map((f) => path.relative(dir, f.file).split(path.sep).join("/")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function scanGoSum(text, name = "go.sum") {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secret-guard-gosum-")));
  try {
    writeFileSync(path.join(dir, name), text);
    const r = scanPath(dir);
    assert.ok(r.ok, r.error);
    return r.findings.map((f) => f.rule);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// One or more names for every entry on the list.
const UNREAD = {
  "rule-file": ["my.gitleaks.toml", ".gitleaks.toml", "conf/gitleaks.toml"],
  image: ["logo.png", "a.JPG", "a.jpeg", "a.gif", "a.bmp", "a.tif", "a.tiff"],
  font: ["a.eot", "a.ttf", "a.otf", "a.woff", "a.woff2"],
  binary: ["a.doc", "a.docx", "a.xls", "a.xlsx", "a.pdf", "a.vsidx", "a.suo", "a.wsuo", "a.pdb", "a.exe"],
  "go-vendor-list": ["vendor/modules.txt"],
  "go-vendor": ["vendor/github.com/x/y/z.go", "vendor/golang.org/x/y.go"],
  "node-modules": ["node_modules/x/y.js"],
  "bower-components": ["bower_components/x/y.js"],
  virtualenv: ["venv/lib/site.py", "env/lib64/x.py", "virtualenv/lib/x.py"],
  "python-lib": ["lib/python3.11/x.py", "python/3.11/lib/x.py"],
  "dist-info": ["pkg-1.2.dist-info/RECORD"],
  "ruby-vendor": ["vendor/bundle/x.rb", "vendor/ruby/x.rb"],
  gem: ["x.gem"],
  git: ["sub/.git"],
  terraform: [".terraform/modules/x.tf"],
  "external-modules": [".external_modules/x.tf"],
  "node-modules-dir": ["a/node_modules/y.js"],
  vendor: ["vendor/a.js"],
  venv: [".venv/x.py"],
  pycache: ["__pycache__/x.txt"],
  archive: [
    "data.zip", "UPPER.ZIP", "data.tar", "data.tar.gz", "data.gz", "data.bz2", "data.xz", "data.7z", "data.rar",
    "data.br", "data.lz", "data.lz4", "data.mz", "data.sz", "data.s2", "data.zst", "data.zstd", "data.zz",
    // Not archives. gitleaks goes by the name, and for most formats by the name holding the ending.
    "app.browser.js", "deploy.target.yaml", "messages.pt.br.json", "a.zip.txt", "a.zipcode.js", "a.gzip", "a.xz.md", "a.rar.txt", "a.zİp.js",
  ],
};

// Each kind taken out of the list, or a name a corrected entry used to reach.
const READ = [
  "go.sum", "go.mod", "go.work", "go.work.sum",
  "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "deno.lock", "poetry.lock", "Pipfile.lock", "gradle.lockfile",
  "art.svg", "UPPER.SVG",
  "gradlew", "gradlew.bat", "mvnw", "mvnw.cmd", ".mvn/wrapper/MavenWrapperDownloader.java",
  "bootstrap.js", "src/bootstrap-app.js", "angular.config.js", "jquery-ui.custom.js", "plotly-setup.js", "swagger-ui-init.js", "bootstrap.min.js.map",
  "config/javascript.json", "gradle/verification-metadata.xml", "Database.refactorlog",
  "a.socket", "model.gltf", "blob.bin", "a.v2", "settings.v2",
  "mango.sum", "logo.mod", "x.adll", "lib.dll", "mygitleaks.toml", "gitleaks.toml.bak",
  // Names next to an archive's that hold no ending.
  "zipcode.js", "data.tgz", "app.jar", "a.lzma", "a.lz.js", "a.mz.js", "a.size.js", "x.gz/inner.js", "data.tar/inner.yaml",
];

test("the list is every path pattern in the two config files, as they are written, and the archive entry", () => {
  const paths = (file, heading) => {
    const text = readFileSync(path.join(GITLEAKS, file), "utf8");
    const block = /paths = \[([\s\S]*?)\n\]/.exec(text.slice(text.search(new RegExp(`^\\[${heading}\\]`, "m"))));
    return [...block[1].matchAll(/'''(.+?)'''/g)].map((m) => m[1]);
  };
  const go = (e) => `${e.flags === "i" ? "(?i)" : ""}${e.pattern}`;
  const from = (name) => LIST.entries.filter((e) => e.from === name).map(go);
  assert.deepEqual(from("default.gitleaks.toml"), paths("default.gitleaks.toml", "allowlist"));
  assert.deepEqual(from("extra-rules.toml"), paths("extra-rules.toml", "allowlist"));
  assert.equal(LIST.entries.filter((e) => !e.from.endsWith(".toml")).length, 1, "and one entry that is in neither");
  assert.ok(LIST.entries.some((e) => e.kind === "archive"), "which is archives");
  assert.equal(new Set(LIST.entries.map((e) => e.kind)).size, LIST.entries.length, "kinds are unique");
  assert.deepEqual(Object.keys(UNREAD).sort(), LIST.entries.map((e) => e.kind).sort(), "every kind has a name below");
});

test("each kind on the list is in fact unread, and the list says so of it", needsBinary, () => {
  const names = Object.values(UNREAD).flat();
  const found = read([...names, "control.js"]);
  assert.ok(found.has("control.js"), "the scan reads an ordinary file beside them");
  for (const [kind, list] of Object.entries(UNREAD)) {
    const entry = compiled.find((e) => e.kind === kind);
    for (const n of list) {
      assert.ok(!found.has(n), `${n} (${kind}) was read`);
      assert.ok(entry.re.test(n), `${n} is not matched by the ${kind} entry`);
    }
  }
});

test("each kind taken off the list is read, and the list does not claim it", needsBinary, () => {
  const found = read(READ);
  for (const n of READ) {
    assert.ok(found.has(n), `${n} was not read`);
    assert.ok(!listedUnread(n), `${n} is listed as unread`);
  }
});

test("go.sum: its hash lines are not keys, and a credential in it is reported", needsBinary, () => {
  const lines = [
    `golang.org/x/oauth2 v0.21.0 ${hash(1)}`,
    `golang.org/x/oauth2 v0.21.0/go.mod ${hash(2)}`,
    `github.com/getkin/kin-openapi v0.127.0 ${hash(3)}`,
    `github.com/golang-jwt/jwt/v5 v5.2.1 ${hash(4)}`,
    `github.com/example/token v1.0.0+incompatible ${hash(5)}`,
    `github.com/example/auth v0.0.0-20240101000000-abcdef123456 ${hash(6)}`,
    `github.com/example/secret-store v1.2.3/go.mod ${hash(7)}`,
  ];
  const text = lines.join("\n") + "\n";
  for (const name of ["go.sum", "go.work.sum"]) assert.deepEqual(scanGoSum(text, name), [], name);
  assert.deepEqual(scanGoSum(lines.join("\r\n") + "\r\n"), [], "with CRLF line endings");
  // The same text under another name is not a go.sum: the rule is for that file.
  assert.ok(scanGoSum(text, "notes.txt").includes("generic-api-key"), "the lines do fire the rule elsewhere");

  assert.deepEqual(scanGoSum(`${text}aws = ${awsKeyId()}\n`), ["aws-access-token"]);
  assert.deepEqual(scanGoSum(`${text}// ${githubToken("gosum")}\n`), ["github-pat"]);
  assert.deepEqual(scanGoSum(`${text}${privateKey()}`), ["private-key"]);
  // A vendor format in the hash's place is still that format.
  assert.deepEqual(scanGoSum(`github.com/a/b v1.0.0 h1:${githubToken("hash place")}\n`), ["github-pat"]);

  const password = chars("password", 22, B62);
  assert.deepEqual(scanGoSum(`${text}password = "${password}"\n`), ["generic-api-key"], "a password on a line of its own");
  assert.deepEqual(scanGoSum(`github.com/a/password=${password} v1.0.0 ${hash(8)}\n`), ["generic-api-key"], "in the module's place");
  assert.deepEqual(scanGoSum(`github.com/a/token v1.0.0 h1:${password}\n`), ["generic-api-key"], "a value not of a hash's length");
});

// Not on the list, because no name says it: gitleaks looks at a file's first bytes as well. Held
// here so that the README's sentence about it stays true, and is noticed if a release changes it.
test("text that begins with a binary format's first bytes is not read under any name", needsBinary, () => {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secret-guard-magic-")));
  try {
    writeFileSync(path.join(dir, "config.js"), `%PDF-1.7\n// ${githubToken("magic")}\n`);
    // What a real DLL begins with, which is why .dll need not be on the list.
    writeFileSync(path.join(dir, "real.dll"), Buffer.concat([Buffer.from("MZ"), Buffer.alloc(62), Buffer.from(`\n// ${githubToken("dll")}\n`)]));
    writeFileSync(path.join(dir, "plain.js"), `// ${githubToken("plain")}\n`);
    assert.ok(!listedUnread("config.js"));
    assert.ok(!listedUnread("real.dll"));
    const r = scanPath(dir);
    assert.ok(r.ok, r.error);
    assert.deepEqual(r.findings.map((f) => path.basename(f.file)), ["plain.js"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
