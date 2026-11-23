# secret-guard-mcp

[![release](https://img.shields.io/github/v/release/tjwitko/secret-guard-mcp)](https://github.com/tjwitko/secret-guard-mcp/releases/latest)
[![license](https://img.shields.io/github/license/tjwitko/secret-guard-mcp)](LICENSE)

An MCP server that keeps hardcoded credentials out of source and configuration — any language, any
format — and can check a file **before it is written**.

It wraps [gitleaks](https://github.com/gitleaks/gitleaks) (~170 vendor credential formats) and adds
one rule of its own. Two things make it different from running gitleaks in CI: it can scan a string
that has not touched disk yet, and **its findings never contain the secret**.

---

## Getting started

### Requirements

- **Node.js 20 or newer**
- **`gitleaks`** on your `PATH`:

  ```bash
  brew install gitleaks
  ```

  If it is missing the tools say so. They do not return a clean result.

  The rules are those of **gitleaks 8.30.1** (see [The default rules](#the-default-rules)), so that is
  the release to install. A newer binary runs them; it does not bring newer rules with it.

### Install

```bash
npm install --save-dev github:tjwitko/secret-guard-mcp#v1.0.4
```

### Register it with an MCP client

```json
{
  "mcpServers": {
    "secret-guard": {
      "command": "node",
      "args": ["/absolute/path/to/secret-guard-mcp/index.mjs"],
      "env": { "SCAN_ROOT": "/absolute/path/to/your/project" }
    }
  }
}
```

---

## The tools

| tool | parameter | use it |
|---|---|---|
| `scan_content` | `content` — the bytes you are about to write | **before** writing a file |
| `scan_path` | `path` — a file or directory inside `SCAN_ROOT` | on something that already exists |

**Prefer `scan_content`.** A secret caught there never reaches disk, so it never reaches git
history, so there is nothing to rotate. Scanning afterwards is strictly worse — and every finding
says "rotate", because deleting the line fixes nothing once it is committed: it remains in history
and anyone who fetched the repository already has it.

Both return the same shape:

```json
{
  "clean": false,
  "summary": {
    "total": 2,
    "confirmed": 1,
    "heuristic": 1,
    "byRule": { "aws-access-token": 1, "generic-api-key": 1 }
  },
  "findings": [
    {
      "rule": "aws-access-token",
      "description": "Identified a pattern that may indicate AWS credentials…",
      "file": "src/config.py",
      "startLine": 14,
      "heuristic": false,
      "secret": "<redacted>",
      "fingerprint": "src/config.py:aws-access-token:14"
    }
  ],
  "remediation": "…"
}
```

**A scan that left something unread is not a clean scan.** gitleaks walks past a file or a
directory it is not permitted to read, and past the rest of a tree when its time limit (120
seconds) runs out, and still reports no findings. Here, if nothing was found, that is an error
naming what was not read. If something was found, the findings are returned as usual with a
`skipped` list beside them, each entry a `path` and a `reason`; once the findings are fixed, the
next scan is the error. The error's first block is the sentence; a second block holds
`{ target, incomplete: true, skipped }` as JSON, for a caller with a rule of its own about a
directory it already knows it cannot read. `scanPath` as a library does the same: `{ ok: false, error, skipped }`
with no findings, `{ ok: true, findings, skipped }` with some.

The same holds for content: if gitleaks ends before it has read all of what `scan_content` handed
it, a report from it is a report on part of the content, and is treated the same way. When it
wrote no report, because it could not load its config for instance, the error is gitleaks' own
reason whatever the size of the content.

**Nor is a scan of something gitleaks skipped whole.** `scan_content`, or `scan_path` given one file,
is an error when gitleaks left that one thing unread: for its first bytes, its name, or its place on
the path allowlist. So is `scan_path` on a directory the walk would not enter, because gitleaks tests
the whole path: a checkout at `.../vendor/app` or `.../env/lib/app` used to read nothing and report
clean.

**In a tree, what is left unread by design is reported and the scan stays complete.** The report has
`unreadCount`, and for the paths named in `unread_of` an `unread` list of `{ path, kind }`: `directory` and
`file` for the path allowlist, `first-bytes` (with `mime`) for the rest. It comes from gitleaks' log at
`debug`, read as it is written, so a tree's size cannot overflow it. The count has no cap. The entries
for the paths asked about are capped at 8 MB, under the 10 MB an MCP client reads in one message, and
reaching that is an error that says so. Archives are not in it, because gitleaks names them only at `trace`, which also logs candidate
values; they go by name alone, so the `archive` entry of `gitleaks/unread-paths.json` is exact for them.

---

## Findings never contain the secret

`--redact` is passed on every invocation **and** every finding is rewritten before it is returned:
`secret` is overwritten unconditionally and `Match` is dropped entirely, because with `--redact`
gitleaks still returns the characters bracketing the value.

Two layers, deliberately. A finding from this server lands in a model's context, the run transcript,
and any log capturing either — a scanner that prints what it found becomes the leak it exists to
prevent. There is a test pinning both layers; neither is a simplification opportunity.

---

## Confidence, not severity

gitleaks publishes no severity, so none is invented. Findings from its keyword-and-entropy
heuristics (`generic-api-key`, `jwt`, …) are marked `heuristic: true`; vendor-format matches like
`aws-access-token` are not.

Dismiss a confirmed false positive by adding its `fingerprint` to `.gitleaksignore` — precise and
auditable — rather than lowering a threshold and losing a whole class of detection.

**Suppressions are counted and reported even on a clean scan.** A suppressed finding produces no
output at all, which makes allowlisting the cheapest way to make a real finding disappear. One agent
run did exactly that and its commit went through.

---

## The extra rule

**`connection-string-password`** — a credential inside a DSN, such as
`postgres://admin:<password>@db.internal:5432/app`.

This closes a verified gap, not a guessed one: gitleaks 8.30.1 with default rules does not flag it,
and a password inside a connection string is one of the most common ways a real credential reaches a
config file. Placeholders (`password`, `changeme`, `${VAR}`, `<your-password>`) are allowlisted, so a
README showing the URI format is not a finding — a scanner that flags every example gets switched
off, and then it protects nothing.

---

## The default rules

The ~170 default rules are gitleaks' own, but they are read from a copy in this repository,
`gitleaks/default.gitleaks.toml`, and not from the ones built into the binary. The copy is
gitleaks 8.30.1's `config/gitleaks.toml` with **two changes**: one regex anchored, and a shorter path
allowlist ([below](#what-is-read-and-what-is-not)).

gitleaks' default allowlist holds the regex `(?i)^true|false|null$`. It was written to dismiss a
"secret" that is the literal `true`, `false` or `null`. By precedence it means *starts with
true, or contains false, or ends with null*, in any letter case, and it applies to every rule. So a
credential whose text happened to contain "false" was not reported at all:

- of 120,000 texts of a private key's shape, 5 were missed, each with the word somewhere in its
  base64. That is one text of an RSA-2048 key's size in 24,000, and more often for longer keys;
- a connection-string password that merely starts with `True` was missed every time.

The copy anchors it, `(?i)^(?:true|false|null)$`. On 35 real projects the findings were the same
447 before and after, so nothing that was reported has gone and nothing new appears there. It is
reported upstream as [gitleaks#2293](https://github.com/gitleaks/gitleaks/issues/2293); a config that
extends the built-in defaults cannot take an allowlist entry out, which is why the copy exists.

The cost is that rules no longer arrive with a gitleaks upgrade. The top of the file says how to
take a newer release's, and a test fails when the installed gitleaks is not the release the copy
came from, or when the copy differs from that release's file in anything but the changes it lists.

### What is read and what is not

gitleaks' default path allowlist skipped text a person writes or a tool generates, so a key in
`go.sum`, in a comment in an `.svg`, or in a file called `bootstrap.js` was never seen. Those are read
now: lockfiles, `go.mod`, `go.sum`, `go.work`, `.svg`, the gradle and maven wrappers, any `.js` named
for a library, `javascript.json`, `verification-metadata.xml`, `.refactorlog`, `.gltf`, `.socket`,
`.bin`, `.v2` and `.dll` (a real DLL is still skipped, by its first bytes).

Still not read: third-party trees (`node_modules`, `bower_components`, `vendor/`, virtualenvs,
`site-packages` paths, `.dist-info`), images, fonts, Office files, PDFs, `.exe` and Visual Studio's binary files, gems, rule
files named `gitleaks.toml` or `*.gitleaks.toml`, and archives.

[`gitleaks/unread-paths.json`](gitleaks/unread-paths.json) lists all of it as JavaScript regular
expressions, for a caller that blocks a write where the scan does not look, including a path that is
not on disk. A test holds the list to the two config files and to what the binary does, in both
directions. Test a path and each of its parent directories: gitleaks does not go into a directory
that matches, so `logo.png/config.js` is unread. The archive entry is the exception and applies to a
file's own name, so `x.gz/inner.js` is read.

- **An entry's letter case is its own.** gitleaks joins the entries into one expression, where
  upstream's first `(?i)` reached every entry after it, so `NODE_MODULES/x.js` and `X.GEM` went unread
  without any entry saying so. Each `(?i)` now ends with its entry, and those names are read.

- **Archives go by name, and the name need only hold the ending.** gitleaks treats any file whose name
  contains `.zip`, `.tar`, `.gz`, `.br`, `.bz2`, `.xz`, `.7z`, `.rar`, `.lz4`, `.sz`, `.s2`, `.zst` or `.zz`,
  or ends in `.lz` or `.mz`, as an archive and skips it. So `app.browser.js`, `deploy.target.yaml` and
  `messages.pt.br.json` are not read, and they are on the list.
- **`go.sum` has one narrow rule.** `generic-api-key` read a module named for a keyword (`oauth2`,
  `token`) as a key whose value is the hash. That rule, and only that rule, skips a line of exactly the
  form `<module> <version> h1:<hash>` in a file named `go.sum` or `go.work.sum`. An AWS key ID, a GitHub
  token or a private key there is reported, and so is a password on a line of any other shape. A value
  of 43 base64 characters and `=`, written where a hash goes, is not: it looks like a hash.

---

## A scan that could not run says so

A clean result means gitleaks read the target and wrote a report with nothing in it. If the config
cannot be loaded, if the path is not there, or if gitleaks ends without a report, the tools return
an error. Up to v1.0.3 the first two came back as a clean scan.

---

## Configuration

| variable | default | purpose |
|---|---|---|
| `SCAN_ROOT` | the process's working directory at startup | bounds every scan; `path` must exist and its real path, after symlinks, must be inside it |
| `SECRET_GUARD_CONFIG` | the bundled `gitleaks/extra-rules.toml` | override the gitleaks config. A relative `[extend] path` in it is read from that file's own directory. A config of your own that says `useDefault = true` gets the built-in allowlist described above |

**Path containment matters more here than for most scanners.** One pointed at `~/.aws` does not
merely read it — it *reports what it found*, so traversal becomes credential disclosure. Redaction
only limits the blast radius; containment is the control. It compares real paths: a symlink in
the project that points outside `SCAN_ROOT` is refused, and gitleaks does not follow symlinks
while it walks a directory. `scanPath`, used as a library, has no `SCAN_ROOT`: it scans the real
path of what it is given, so a link to a directory or a file is scanned as what it points at.

Only `PATH`, `HOME`, `SCAN_ROOT` and `SECRET_GUARD_CONFIG` survive startup. Everything else in
`process.env` is deleted, so the server never inherits secrets from whatever spawned it.

---

## Limitations

- **A raw shell bypasses it.** `cat > config.yaml` reaches no MCP tool. A pre-commit hook is what
  holds that boundary.
- **No live verification.** trufflehog can call a provider's API to check whether a candidate is
  real, which cuts false positives sharply — by sending the candidate credential to a third party.
  Deliberately out of v1; it would be opt-in.
- **`scan_content` has no filename**, so path-based allowlists and `.gitleaksignore` do not apply.
  It can flag something `scan_path` would suppress on the same bytes. That includes a
  `.gitleaksignore` in the directory the caller is in, which through v1.0.3 could silence it with a
  `:<rule>:<line>` entry; the only one read now is one beside the config in use.
- **Working tree only.** `scan_path` does not scan git history.
- **Text can begin like a binary file.** gitleaks skips a file whose first bytes match a format of type
  `application/*`, under any name, and two ordinary letters are enough: `settings.env` with
  `MZ_REGION=maputo` on line 1 and a token on line 2 is not read. So are `%PDF`, `%!PS`, and the zip,
  7z, gzip, SQLite, ELF and rar signatures. No name can say this, so it is not in
  `unread-paths.json`; a scan of that one thing is an error, and in a tree the path is in `unread`.
- **What gitleaks leaves unread by design in a tree is not reported as `skipped`:** archives, files
  with those first bytes, empty files, symlinks, and the paths on its allowlist. See `unread` above. A
  file it could not open for a reason other than permission is passed without a word at any log level.
- **Detection is not the real fix.** The best protection is having no static credential to leak —
  workload identity, IRSA, short-lived STS credentials.

---

## Development

```bash
npm install
npm test          # 41 tests; the gitleaks-backed ones report if it is absent
```

If you write a test credential, assemble it at runtime rather than writing the literal. GitHub's
push protection scans every commit in a push, and a scanner's own fixtures are exactly what it
rejects.

---

## Part of wolfproof

This is one of four control servers behind
[wolfproof](https://github.com/tjwitko/wolfproof), which runs them together and fails a build on
what they find. Unlike the dependency scan beside it, this check is never advisory: a credential in
a tracked file is a fact, not a version-resolution guess. It works standalone with any MCP client.

## License

[GNU Affero General Public License v3.0](LICENSE) © 2026 Tom Witkowski, for everything after v1.0.2. Releases up to and including v1.0.2 remain under Apache-2.0.

`gitleaks/default.gitleaks.toml` is gitleaks' default configuration, © 2019 Zachary Rice, under the
MIT License: see `gitleaks/LICENSE-gitleaks`.
