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

### Install

```bash
npm install --save-dev github:tjwitko/secret-guard-mcp#v1.0.0
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

## Configuration

| variable | default | purpose |
|---|---|---|
| `SCAN_ROOT` | the process's working directory at startup | bounds every scan; `path` must resolve inside it |
| `SECRET_GUARD_CONFIG` | the bundled `gitleaks/extra-rules.toml` | override the gitleaks config |

**Path containment matters more here than for most scanners.** One pointed at `~/.aws` does not
merely read it — it *reports what it found*, so traversal becomes credential disclosure. Redaction
only limits the blast radius; containment is the control.

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
  It can flag something `scan_path` would suppress on the same bytes.
- **Working tree only.** `scan_path` does not scan git history.
- **Detection is not the real fix.** The best protection is having no static credential to leak —
  workload identity, IRSA, short-lived STS credentials.

---

## Development

```bash
npm install
npm test          # 15 tests; the gitleaks-backed ones report if it is absent
```

If you write a test credential, assemble it at runtime rather than writing the literal. GitHub's
push protection scans every commit in a push, and a scanner's own fixtures are exactly what it
rejects.

---

## Part of agent-gate

This is one of four control servers behind
[agent-gate](https://github.com/tjwitko/agent-gate), which runs them together and fails a build on
what they find. Unlike the dependency scan beside it, this check is never advisory: a credential in
a tracked file is a fact, not a version-resolution guess. It works standalone with any MCP client.

## License

[Apache License 2.0](LICENSE) © 2026 Tom Witkowski
