#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import path from "path";

import { resolveScanPath } from "./lib/paths.mjs";
import {
  checkGitleaksInstalled,
  NOT_INSTALLED_MESSAGE,
  REMEDIATION,
  scanContent,
  scanPath,
  summarize,
} from "./lib/gitleaks.mjs";

// A stdio MCP server inherits its entire parent environment by default even though it only needs
// its own config vars — drop the rest, same guardrail as the sibling servers. It matters more
// here: this process is one whose whole job is recognising credential-shaped strings, and an
// inherited AWS_SECRET_ACCESS_KEY would be exactly that.
function sanitizeEnv(allowlist) {
  for (const key in process.env) {
    if (!allowlist.includes(key)) delete process.env[key];
  }
}
sanitizeEnv(["PATH", "HOME", "SCAN_ROOT", "SECRET_GUARD_CONFIG"]);

const SCAN_ROOT = path.resolve(process.env.SCAN_ROOT || process.cwd());
const CONFIG_PATH = process.env.SECRET_GUARD_CONFIG || undefined;

const server = new McpServer({ name: "secret-guard", version: "1.0.0" });

function notInstalled() {
  return { content: [{ type: "text", text: NOT_INSTALLED_MESSAGE }], isError: true };
}

function report(findings, extra) {
  const body = {
    ...extra,
    clean: findings.length === 0,
    summary: summarize(findings),
    findings,
    ...(findings.length ? { remediation: REMEDIATION } : {}),
  };
  return { content: [{ type: "text", text: JSON.stringify(body, null, 2) }] };
}

server.tool(
  "scan_path",
  "Scan a file or directory for hardcoded credentials — API keys, tokens, private keys, " +
    "passwords in connection strings — in source code and configuration of any language or " +
    "format (YAML, JSON, TOML, .env, HCL, plain text). Run it before committing, and after " +
    "generating or editing configuration. Findings never include the credential value itself. " +
    "Advisory: this reports, it cannot prevent a file from being written or committed — the " +
    "enforcement points are the caller's validation gate and a git pre-commit hook.",
  {
    target: z
      .string()
      .describe(
        "File or directory to scan, relative to this server's working directory or absolute " +
          "within it. Directories are scanned recursively."
      ),
  },
  async ({ target }) => {
    let resolved;
    try {
      resolved = resolveScanPath(target, SCAN_ROOT);
    } catch (error) {
      return { content: [{ type: "text", text: `Refusing to scan: ${error.message}` }], isError: true };
    }

    if (!checkGitleaksInstalled()) return notInstalled();

    const result = scanPath(resolved, { configPath: CONFIG_PATH });
    if (!result.ok) return { content: [{ type: "text", text: result.error }], isError: true };

    return report(result.findings, { target: resolved });
  }
);

server.tool(
  "scan_content",
  "Check a string for hardcoded credentials BEFORE writing it to a file. Use this when " +
    "generating or modifying file contents: a secret caught here never reaches disk, so it never " +
    "reaches git history, so there is nothing to rotate. Scanning after the write is strictly " +
    "worse. Findings never include the credential value itself.",
  {
    content: z.string().describe("The file contents to check. Not written anywhere by this tool."),
    path_label: z
      .string()
      .optional()
      .describe(
        "The path this content is destined for. Used only to label findings; no file is read " +
          "or written."
      ),
  },
  async ({ content, path_label }) => {
    if (!checkGitleaksInstalled()) return notInstalled();

    const result = scanContent(content, { pathLabel: path_label, configPath: CONFIG_PATH });
    if (!result.ok) return { content: [{ type: "text", text: result.error }], isError: true };

    return report(result.findings, { pathLabel: path_label || "(content)" });
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("secret-guard MCP server running on stdio");
}
main().catch(console.error);
