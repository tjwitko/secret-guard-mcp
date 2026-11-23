import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createPrivateKey } from "crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { checkGitleaksInstalled, leftUnread, scanContent, scanPath } from "../lib/gitleaks.mjs";

// What the scan leaves unread by path, and that gitleaks/unread-paths.json says so. A caller that
// blocks a write where the scan does not look reads that file instead of parsing Go regular
// expressions, so a name it gets wrong in either direction is a hole or a false block.
//
// Credentials are assembled here at run time and written only to temporary directories.

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GITLEAKS = path.join(HERE, "..", "gitleaks");
const LIST = JSON.parse(readFileSync(path.join(GITLEAKS, "unread-paths.json"), "utf8"));
const compiled = LIST.entries.map((e) => ({ ...e, re: new RegExp(e.pattern, e.flags) }));
// As the file's "about" says: the whole path against every entry, its parent directories against
// those that apply to directories.
const parents = (rel) => rel.split("/").slice(0, -1).map((_, i, all) => all.slice(0, i + 1).join("/"));
const listedUnread = (rel) => compiled.some((e) => e.re.test(rel) || (e.directories && parents(rel).some((d) => e.re.test(d))));

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
  const go = (e) => (e.flags === "iu" ? `(?i:${e.pattern})` : e.pattern);
  const from = (name) => LIST.entries.filter((e) => e.from === name).map(go);
  assert.deepEqual(from("default.gitleaks.toml"), paths("default.gitleaks.toml", "allowlist"));
  assert.deepEqual(from("extra-rules.toml"), paths("extra-rules.toml", "allowlist"));
  assert.equal(LIST.entries.filter((e) => !e.from.endsWith(".toml")).length, 1, "and one entry that is in neither");
  assert.ok(LIST.entries.some((e) => e.kind === "archive"), "which is archives");
  assert.equal(new Set(LIST.entries.map((e) => e.kind)).size, LIST.entries.length, "kinds are unique");
  assert.deepEqual(Object.keys(UNREAD).sort(), LIST.entries.map((e) => e.kind).sort(), "every kind has a name below");
  assert.deepEqual(LIST.entries.filter((e) => !e.directories).map((e) => e.kind), ["archive"], "only the archive entry goes by a file's own name");
  assert.deepEqual([...new Set(LIST.entries.filter((e) => e.from.endsWith(".toml")).map((e) => e.flags))].sort(), ["", "iu"], "a config's (?i) is iu here");
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

/** Each name alone in a directory, because a case-folding disk (macOS) holds a.suo and a.\u017fuo as one file. */
function readAlone(name) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secret-guard-alone-")));
  try {
    mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    writeFileSync(path.join(dir, name), `deploy token: ${githubToken(name)}\n`);
    writeFileSync(path.join(dir, "control.js"), `deploy token: ${githubToken("control")}\n`);
    const r = scanPath(dir);
    assert.ok(r.ok, r.error);
    const files = r.findings.map((f) => path.basename(f.file));
    assert.ok(files.includes("control.js"), `${name}: the file beside it is read`);
    return r.findings.length === 2;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a directory named like an unread file is not gone into, and the list says so; an archive's name is not a directory's", needsBinary, () => {
  for (const n of ["logo.png/config.js", "docs.pdf/notes.md", "fonts.ttf/a.css", "pkg.gem/lib/x.rb", "tool.exe/run.sh", "a.docx/b.txt", "x.gitleaks.toml/y.js", "img.JPG/z.yaml", "a.suo/b.env", "deep/er/logo.png/x/y.js"]) {
    assert.equal(readAlone(n), false, `${n} was read`);
    assert.ok(listedUnread(n), `${n} is not listed`);
  }
  for (const n of ["x.gz/inner.js", "data.zip/a.js", "a.br/b.yaml", "x.tar/y/z.py"]) {
    assert.equal(readAlone(n), true, `${n} was not read`);
    assert.ok(!listedUnread(n), `${n} is listed`);
  }
});

test("an entry's letter case is its own: a (?i) does not reach the entries after it", needsBinary, () => {
  for (const n of ["X.GEM", "a.Gem", "NODE_MODULES/x.js", "Node_Modules/x.js", "Bower_Components/x.js", "VENDOR/MODULES.TXT", "Vendor/Github.com/x/y.go", "Vendor/Bundle/x.rb", "GITLEAKS.TOML", ".TERRAFORM/x.tf", "Vendor/a.js"]) {
    assert.equal(readAlone(n), true, `${n} was not read`);
    assert.ok(!listedUnread(n), `${n} is listed`);
  }
  for (const n of ["A.PNG", "a.Pdf", "ENV/LIB/x.py", "Lib/Python3.11/x.py", "PKG-1.2.DIST-INFO/RECORD"]) {
    assert.equal(readAlone(n), false, `${n} was read`);
    assert.ok(listedUnread(n), `${n} is not listed`);
  }
});

test("the list folds case as Go does: U+017F is s and U+212A is k, in a config's entries and not in the archive's", needsBinary, () => {
  for (const n of ["a.xl\u017fx", "a.\u017fuo", "a.w\u017fuo", "a.v\u017fidx", "pkg-1.2.di\u017ft-info/RECORD", "pkg\u212a-1.2.dist-info/RECORD"]) {
    assert.equal(readAlone(n), false, `${JSON.stringify(n)} was read`);
    assert.ok(listedUnread(n), `${JSON.stringify(n)} is not listed`);
  }
  // gitleaks compares an archive's name after ToLower, which leaves U+017F as it is.
  for (const n of ["a.\u017fz", "a.\u017f2", "a.z\u017ft"]) {
    assert.equal(readAlone(n), true, `${JSON.stringify(n)} was not read`);
    assert.ok(!listedUnread(n), `${JSON.stringify(n)} is listed`);
  }
});

// Not on the list, because no name says it: gitleaks looks at a file's first bytes as well, and
// says so in its log. Two ordinary letters are enough.
const SKIPPED_HEADS = {
  "MZ, as a setting": "MZ_REGION=maputo\n",
  "%PDF": "%PDF-1.7\n",
  "%!PS": "%!PS-Adobe-3.0\n",
  zip: "PK\x03\x04\n",
  "7z": Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x0a]),
  gzip: Buffer.from([0x1f, 0x8b, 0x08, 0x0a]),
  SQLite: "SQLite format 3\0\n",
  ELF: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x0a]),
  "rar, the whole signature": "Rar!\x1a\x07\x00\n",
};
const READ_HEADS = { BM: "BM\n", GIF: "GIF89a\n", "Rar! alone": "Rar!\n", ID3: "ID3\n", OggS: "OggS\n", wOFF: "wOFF\n", "a leading NUL": "\0\n", text: "# settings\n" };
const withHead = (head, what) => Buffer.concat([Buffer.from(head, typeof head === "string" ? "latin1" : undefined), Buffer.from(`deploy token: ${githubToken(what)}\n`)]);

function inDir(fn) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secret-guard-heads-")));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("handed one file or content that gitleaks skips for its first bytes, the scan is an error and not clean", needsBinary, () => {
  for (const [what, head] of Object.entries(SKIPPED_HEADS)) {
    const body = withHead(head, what);
    inDir((dir) => {
      const file = path.join(dir, "settings.env");
      writeFileSync(file, body);
      assert.ok(!listedUnread("settings.env"));
      const one = scanPath(file);
      assert.equal(one.ok, false, `${what}: scan_path of the file`);
      assert.match(one.error, /^not a clean scan: .*first bytes/, what);
      assert.deepEqual(one.findings, []);
      assert.equal(one.skipped[0].path, file);
    });
    const content = scanContent(body);
    assert.equal(content.ok, false, `${what}: scan_content`);
    assert.match(content.error, /^not a clean scan: .*first bytes/, what);
  }
  for (const [what, head] of Object.entries(READ_HEADS)) {
    const body = withHead(head, what);
    inDir((dir) => {
      writeFileSync(path.join(dir, "settings.env"), body);
      assert.deepEqual(scanPath(path.join(dir, "settings.env")).findings.map((f) => f.rule), ["github-pat"], `${what}: scan_path`);
    });
    assert.deepEqual(scanContent(body).findings.map((f) => f.rule), ["github-pat"], `${what}: scan_content`);
  }
});

test("in a tree, what is left unread by design is reported, and the scan is complete", needsBinary, () => {
  inDir((dir) => {
    writeFileSync(path.join(dir, "settings.env"), withHead("MZ_REGION=maputo\n", "tree"));
    writeFileSync(path.join(dir, "logo.png"), `token: ${githubToken("png")}\n`);
    mkdirSync(path.join(dir, "fonts.ttf"));
    writeFileSync(path.join(dir, "fonts.ttf", "a.css"), `/* ${githubToken("dir")} */\n`);
    writeFileSync(path.join(dir, "plain.js"), `// ${githubToken("plain")}\n`);
    assert.equal(scanPath(dir).unread, undefined, "the entries are there for paths a caller names");
    assert.equal(scanPath(dir).unreadCount, 3);
    assert.deepEqual(scanPath(dir, { unreadOf: ["plain.js"] }).unread, [], "and only for those");
    const r = scanPath(dir, { unreadOf: ["settings.env", "logo.png", "fonts.ttf/a.css", "plain.js"] });
    assert.ok(r.ok, r.error);
    assert.equal(r.skipped, undefined, "not an incomplete scan");
    assert.deepEqual(r.findings.map((f) => path.basename(f.file)), ["plain.js"]);
    const by = Object.fromEntries(r.unread.map((u) => [path.relative(dir, u.path), u]));
    assert.deepEqual(Object.keys(by).sort(), ["fonts.ttf", "logo.png", "settings.env"]);
    assert.equal(by["logo.png"].kind, "file");
    assert.equal(by["fonts.ttf"].kind, "directory");
    assert.equal(by["settings.env"].kind, "first-bytes");
    assert.equal(by["settings.env"].mime, "application/vnd.microsoft.portable-executable");
    assert.ok(!JSON.stringify(r).includes(githubToken("tree")), "and the report holds no value");
  });
});

test("a target that is itself unread is an error: a file by name, or a directory the walk would not enter", needsBinary, () => {
  inDir((dir) => {
    for (const n of ["logo.png", "data.zip", "app.browser.js", "a.gem"]) {
      writeFileSync(path.join(dir, n), `token: ${githubToken(n)}\n`);
      const r = scanPath(path.join(dir, n));
      assert.equal(r.ok, false, n);
      assert.match(r.error, /not a clean scan/, n);
    }
    for (const sub of ["vendor/app", "a/node_modules/app", "env/lib/app", "vendor", "b/.venv"]) {
      const t = path.join(dir, sub);
      mkdirSync(t, { recursive: true });
      writeFileSync(path.join(t, "config.js"), `token: ${githubToken(sub)}\n`);
      const r = scanPath(t);
      assert.equal(r.ok, false, `${sub}: ${JSON.stringify(r)}`);
      assert.equal(r.skipped.at(-1).path, t, sub);
    }
    // Not the parent's name: the walk tests the path it starts from, and this one does not match.
    const parent = path.join(dir, "x.png", "app");
    mkdirSync(parent, { recursive: true });
    writeFileSync(path.join(parent, "config.js"), `token: ${githubToken("parent")}\n`);
    assert.deepEqual(scanPath(parent).findings.map((f) => f.rule), ["github-pat"]);
    // An empty file was read, and held nothing.
    writeFileSync(path.join(dir, "empty.js"), "");
    assert.deepEqual(scanPath(path.join(dir, "empty.js")), { ok: true, findings: [] });
  });
});

test("leftUnread reads only gitleaks' own lines, and a name or a value cannot write one", () => {
  const lines = [
    "5:04PM DBG skipping directory: global allowlist path=/p/a.pdf",
    "5:04PM DBG skipping file: global allowlist path=/p/logo.png",
    '5:04PM DBG skipping file: global allowlist path="/p/my logo\\n\\u017f\\x01.png"',
    "5:04PM DBG skipping binary file mime_type=application/pdf path=/p/s.env",
    "5:04PM DBG skipping binary file mime_type=application/pdf path=",
    '5:04PM DBG skipping finding: global fingerprint finding="skipping file: global allowlist path=/forged" fingerprint=x',
    '5:04PM TRC skipping file: global allowlist path=/trace-level',
    '5:04PM DBG scanning path="5:04PM DBG skipping file: global allowlist path=/forged"',
    "not a log line skipping file: global allowlist path=/forged",
  ].join("\n");
  assert.deepEqual(leftUnread(lines), [
    { path: "/p/a.pdf", kind: "directory" },
    { path: "/p/logo.png", kind: "file" },
    { path: "/p/my logo\n\u017f\x01.png", kind: "file" },
    { path: "/p/s.env", kind: "first-bytes", mime: "application/pdf" },
    { path: null, kind: "first-bytes", mime: "application/pdf" },
  ]);
});

test("at this log level a finding that .gitleaksignore dropped is logged with its value, and none of it is passed on", needsBinary, () => {
  inDir((dir) => {
    const token = githubToken("ignored");
    writeFileSync(path.join(dir, "a.js"), `// ${token}\n`);
    const first = scanPath(dir);
    writeFileSync(path.join(dir, ".gitleaksignore"), `${first.findings[0].fingerprint}\n`);
    writeFileSync(path.join(dir, "logo.png"), "x\n");
    const r = scanPath(dir);
    assert.deepEqual(r.findings, []);
    assert.ok(!JSON.stringify(r).includes(token));
  });
});

test("the server gives the count, and the paths only when asked", needsBinary, async () => {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secret-guard-server-")));
  writeFileSync(path.join(dir, "logo.png"), "x\n");
  writeFileSync(path.join(dir, "a.js"), "export const a = 1;\n");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(HERE, "..", "index.mjs")],
    env: { PATH: process.env.PATH, HOME: process.env.HOME || "", SCAN_ROOT: dir },
    stderr: "ignore",
  });
  const client = new Client({ name: "unread-test", version: "1" });
  try {
    await client.connect(transport);
    const plain = JSON.parse((await client.callTool({ name: "scan_path", arguments: { target: "." } })).content[0].text);
    assert.equal(plain.clean, true);
    assert.equal(plain.unreadCount, 1);
    assert.equal(plain.unread, undefined);
    const listed = JSON.parse((await client.callTool({ name: "scan_path", arguments: { target: ".", unread_of: ["logo.png", "a.js"] } })).content[0].text);
    assert.deepEqual(listed.unread, [{ path: path.join(dir, "logo.png"), kind: "file" }]);
    const content = await client.callTool({ name: "scan_content", arguments: { content: `MZ_REGION=maputo\n${githubToken("server")}\n` } });
    assert.equal(content.isError, true);
    assert.match(content.content[0].text, /^not a clean scan/);
  } finally {
    await client.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// The log at "debug" grows with the tree, and spawnSync holds a child's whole output: 330,000 one-byte
// .png files with paths of about 220 characters came back "spawnSync gitleaks ENOBUFS" at 46d9779,
// from a tree v1.0.4 called clean. A stand-in prints that much log, so the test needs no such tree.
function withLoudGitleaks(script, call) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secret-guard-loud-")));
  try {
    writeFileSync(path.join(dir, "gitleaks"), `#!/bin/sh\ncat > /dev/null\n${script}\n`, { mode: 0o755 });
    mkdirSync(path.join(dir, "project"));
    writeFileSync(path.join(dir, "project", "ok.py"), "x = 1\n");
    const lib = pathToFileURL(path.join(HERE, "..", "lib", "gitleaks.mjs")).href;
    const code = `const { scanPath, scanContent } = await import(${JSON.stringify(lib)});
      const target = ${JSON.stringify(path.join(dir, "project"))};
      const r = ${call};
      console.log(JSON.stringify({ ok: r.ok, error: r.error, findings: r.findings?.length, unreadCount: r.unreadCount, listed: r.unread?.length, skipped: r.skipped?.length }));`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${dir}${path.delimiter}${process.env.PATH}` },
    });
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(r.stdout);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const MANY_LINES = 1_200_000; // about 70 MB of log, past the 50 MB spawnSync was given
const manyUnread = `yes '9:36AM DBG skipping file: global allowlist path=/p/a/logo.png' | head -n ${MANY_LINES} >&2\necho '[]'`;

test("a tree's log cannot overflow: the scan is clean and counts what it left unread", () => {
  assert.deepEqual(withLoudGitleaks(manyUnread, "scanPath(target)"), { ok: true, findings: 0, unreadCount: MANY_LINES });
  // Asked about one path: its entry is kept, and the million others are not.
  const oneHit = `echo "9:36AM DBG skipping file: global allowlist path=$2/logo.png" >&2\n${manyUnread}`;
  assert.deepEqual(withLoudGitleaks(oneHit, 'scanPath(target, { unreadOf: ["logo.png"] })'), { ok: true, findings: 0, unreadCount: MANY_LINES + 1, listed: 1 });
  // Debug lines that say nothing the wrapper reads are dropped too.
  assert.deepEqual(withLoudGitleaks(`yes '9:36AM DBG skipping empty file path=/p/a' | head -n ${MANY_LINES} >&2\necho '[]'`, "scanPath(target)"), { ok: true, findings: 0 });
});

test("a ceiling that is reached is an error that names it and what to do", () => {
  // Past what one reply can carry: an error only for the caller who asked about those paths.
  const repeated = `yes "9:36AM DBG skipping file: global allowlist path=$2/logo.png" | head -n 300000 >&2\necho '[]'`;
  const asked = withLoudGitleaks(repeated, 'scanPath(target, { unreadOf: ["logo.png"] })');
  assert.equal(asked.ok, false);
  assert.match(asked.error, /^not a clean scan: the unread paths asked about passed the 8 MB one reply can carry.*Ask about fewer paths/);
  assert.deepEqual(withLoudGitleaks(repeated, "scanPath(target)"), { ok: true, findings: 0, unreadCount: 300000 });

  const report = withLoudGitleaks("head -c 60000000 /dev/zero | tr '\\0' ' '", "scanPath(target)");
  assert.equal(report.ok, false);
  assert.match(report.error, /^gitleaks' report passed the 50 MB a scan holds.*Scan a smaller directory/);

  const warnings = `yes '9:36AM WRN skipping file: permission denied path=/p/x' | head -n ${MANY_LINES} >&2\necho '[]'`;
  const warned = withLoudGitleaks(warnings, "scanPath(target)");
  assert.equal(warned.ok, false);
  assert.match(warned.error, /gitleaks' warnings about what it could not read passed the 50 MB a scan holds.*Scan a smaller directory/);

  const content = withLoudGitleaks(warnings, 'scanContent("x = 1\\n")');
  assert.equal(content.ok, false);
  assert.match(content.error, /^gitleaks' output on this content passed the 50 MB a scan holds.*smaller parts/);
});
