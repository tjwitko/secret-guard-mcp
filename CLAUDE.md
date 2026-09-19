# CLAUDE.md

An MCP server exposing `scan_path` and `scan_content`: finds hardcoded credentials in source and
configuration of any language or format, via gitleaks. Third instance of the same shape as
`dep-audit-mcp` (osv-scanner) and `terraform-guard-mcp` — a thin, path-contained, env-sanitized
wrapper around an external scanner with structured output.

## Architecture

Calling model → MCP tool → this server (`index.mjs`, Node/stdio) → `gitleaks dir` or
`gitleaks stdin` with `gitleaks/extra-rules.toml` → normalized, redacted findings.
Requires `gitleaks` on `PATH` (`brew install gitleaks`).

## Key files

- `index.mjs` — env sanitization, the two tools
- `lib/gitleaks.mjs` — spawn wrappers, `normalizeFindings()` (the redaction layer), `REMEDIATION`
- `lib/paths.mjs` — `resolveScanPath()`, `SCAN_ROOT` containment
- `gitleaks/extra-rules.toml` — `[extend] useDefault = true` plus the connection-string rule
- `test/gitleaks.test.mjs` — 15 tests; the gitleaks-dependent ones skip cleanly if it isn't installed

## Common commands

```sh
npm install
node --test
gitleaks version                # confirm the prerequisite
```

## Things to know

- **`[extend] useDefault = true` is load-bearing.** Without it, defining any rule in
  `extra-rules.toml` REPLACES gitleaks' ~170 built-in rules instead of adding to them — a config
  that looks like it tightened the scan while actually gutting it.
- **`gitleaks stdin` is why `scan_content` exists at all.** The alternative — write a temp file
  and scan that — would put the candidate secret on disk, which is the thing the pre-write check
  is called to prevent. Trade-off: with no filename, path-based allowlists and `.gitleaksignore`
  don't apply, so `scan_content` can flag what `scan_path` on the same bytes suppresses.
- **Redaction is enforced twice, deliberately.** `--redact` is passed on every invocation *and*
  `normalizeFindings()` overwrites `secret` unconditionally and drops `Match` entirely (with
  `--redact` gitleaks still returns the bracketing characters). Verified without the flag:
  `Secret` comes back as full plaintext. A finding here lands in a model's context and the run
  transcript, so a scanner that echoes the value spreads the leak rather than containing it.
  Don't "simplify" either layer away; there's a test pinning it.
- **`-i <target>` is required, not optional.** gitleaks resolves `.gitleaksignore` against `"."`
  by default, which is *this server's* cwd, not the scanned project's. Without it a project's
  allowlisted false positives keep failing the gate, and a gate that fails on known-good code
  gets removed.
- **gitleaks exits 1 when it finds leaks** — success-with-results, not failure. Same shape as
  osv-scanner in dep-audit-mcp. Only unparseable output is a real error.
- **gitleaks allowlists well-known documentation values.** `AKIAIOSFODNN7EXAMPLE` (AWS's own docs
  example) is NOT flagged; a realistic key like a realistically-shaped one (see `test/gitleaks.test.mjs`, where it is assembled at runtime) is. Don't use published
  example credentials to test whether the scanner works — it will look broken.
- **`heuristic: true` is a confidence flag, not a severity.** gitleaks publishes no severity, and
  inventing one would put a number on a judgement the tool never made. The heuristic rules
  (`generic-api-key`, `jwt`, …) are the false-positive source; the fix for a confirmed one is a
  `.gitleaksignore` fingerprint, not a lower threshold.
- **The connection-string rule closes a verified gap, not a guessed one.** gitleaks 8.30.1 with
  default rules does not flag `REDACTED_DSN_TEST_FIXTURE` in a YAML
  file. `secretGroup = 1` reports only the password — without it the host and username get
  redacted too and the finding is unreadable. The placeholder allowlist is not optional: a
  scanner that flags every README showing a URI format gets switched off, and then it protects
  nothing. Same lesson as terraform-guard's Deny-statement false positive.
- **The tools are the weak half of this project.** Registration makes a tool available; nothing
  makes a model call it. The enforcement that holds is the `write_file` interception in
  `../local-delegate-mcp/agent/agent-loop.mjs`, the loop's validation gate, and
  `../local-copilot-stack/githooks/pre-commit`. If you change `normalizeFindings`' output shape,
  those three call sites read `findings[].rule/startLine/fingerprint` and `summary.total`.
- **`readSuppressions()` exists because silence is the failure mode.** A suppressed finding
  produces no output at all — the scan simply passes — so allowlisting is the cheapest way to make
  a real finding go away. An agent run did exactly that and its commit went through. Every
  consumer should report the count even on a clean scan. `SUPPRESSION_FILES` is exported from
  here so the list of files that can switch this scanner off lives in one place; the git hook and
  the agent loop both consume it. Note gitleaks discovers `.gitleaksignore` from the scan target
  regardless of `-i`, verified directly, so you cannot ask it what it suppressed — the file has to
  be read.
- **The remediation text says "rotate", on purpose.** A model's instinct is to delete the line
  and report success; for an already-committed secret that fixes nothing, since it remains in
  history and anyone who fetched the repo has it.
- **Path containment matters more here than in the siblings.** A secret scanner pointed at
  `~/.aws` doesn't merely read it, it *reports what it found* — traversal becomes credential
  disclosure. `resolveScanPath` is the control; redaction only limits the blast radius.
- **Not covered:** live verification of whether a credential still works (trufflehog does this,
  but by sending the candidate to a third party — deliberately out of v1), and git *history*.
  `scan_path` sees the working tree; `gitleaks git` would cover history and hasn't been wired up.
