# secret-guard-mcp

An MCP server that keeps hardcoded credentials out of source and configuration files — any
language, any format. Wraps [gitleaks](https://github.com/gitleaks/gitleaks) (~170 built-in
credential formats) and adds one rule of its own.

Two tools:

| tool | when |
|---|---|
| `scan_content` | **before** writing a file — the string is checked in memory and never touches disk |
| `scan_path` | a file or directory that already exists |

Prefer `scan_content`. A secret caught there never reaches disk, so it never reaches git history,
so there is nothing to rotate. Scanning after the write is strictly worse.

## Install

```sh
npm install
brew install gitleaks
```

Register with an MCP client:

```json
{"command": "node", "args": ["/absolute/path/to/secret-guard-mcp/index.mjs"]}
```

`SCAN_ROOT` (default: the server's cwd) bounds every scan. `SECRET_GUARD_CONFIG` overrides the
bundled gitleaks config.

## What it catches

Everything in gitleaks' default rule set — AWS keys, GitHub PATs, Slack tokens, Stripe keys,
private keys, and ~170 other vendor formats — across `.py`, `.js`, `.go`, `.yaml`, `.json`,
`.toml`, `.env`, `.tf`, and plain text, plus one added rule:

**`connection-string-password`** — a credential inside a DSN, e.g.
`postgres://admin:hunter2@db.internal:5432/app`. Verified gap: gitleaks 8.30.1's default rules do
not flag this, and a password inside a connection string is one of the most common ways a real
credential ends up in a config file. Placeholders (`password`, `changeme`, `${VAR}`,
`<your-password>`) are allowlisted so a README showing the URI format isn't a finding.

## Findings never contain the secret

`--redact` is passed on every invocation *and* every finding is rewritten in
`normalizeFindings()` so the value cannot survive a gitleaks upgrade or a call site that forgets
the flag. `Match` is dropped entirely — with `--redact` gitleaks still returns the characters
bracketing the secret.

This matters more than it does in CI. A finding here goes into a model's context, the run
transcript, and any log capturing either. A scanner that prints the secret it found becomes the
leak it exists to prevent.

## Confidence, not severity

gitleaks publishes no severity. Rather than invent one, findings from its keyword-and-entropy
heuristics (`generic-api-key`, `jwt`, …) are marked `heuristic: true`; vendor-format matches like
`aws-access-token` are not. Dismiss a confirmed false positive by adding its `fingerprint` to a
`.gitleaksignore` file — precise and auditable, rather than lowering a threshold and losing a
whole class of detection.

## Where it actually blocks

Registration makes a tool available; nothing makes a model call it. Measured across five runs of
one task with identical tooling, a local model invoked the Terraform validator 3, 1, 4, 0 and 5
times. So the real enforcement is not this server's tools:

1. **`write_file` interception** in `local-delegate-mcp/agent/agent-loop.mjs` — the loop calls
   `scanContent()` inside its own write handler and refuses the write. Verified: asked to write a
   file with a hardcoded GitHub PAT and Stripe key, the model got
   `REFUSED: settings.py was NOT written` and the file never appeared on disk.
2. **The loop's validation gate** — `scan_path` over the whole tree, covering files the model
   didn't write. Verified: a `.env` seeded before the run failed the gate.
3. **`local-copilot-stack/githooks/pre-commit`** — the boundary that holds for editor-driven
   agents, where the loop belongs to VS Code rather than to us.

Unlike the dependency scan next to it, this check is never advisory. A credential in a tracked
file is a fact, not a version-resolution guess.

## Honest limitations

- **A raw shell bypasses it.** `cat > config.yaml` reaches no MCP tool. Same boundary as
  `terraform-guard-mcp` and `local-delegate-mcp`; the git hook is what holds.
- **No verification.** trufflehog can call a provider's API to check whether a candidate is live,
  which cuts false positives sharply — but it does so by sending the candidate credential to a
  third party. That is deliberately out of v1 and would be opt-in, like `--web-search`.
- **`scan_content` has no filename**, so path-based allowlists and `.gitleaksignore` don't apply;
  it can flag something `scan_path` on the same bytes would suppress.
- **Deleting the line does not fix a committed secret.** It stays in history and must be rotated
  at the provider. Every finding says so, because "remove the text and report success" is exactly
  what a model does otherwise.
- **Detection is not the real fix.** The best protection is having no static credential to leak —
  workload identity, IRSA, and the short-lived STS credentials `terraform-guard-mcp` mints.
