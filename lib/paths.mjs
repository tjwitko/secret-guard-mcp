import path from "path";

// Sole allowed scan boundary — defaults to this process's cwd (wherever the MCP client launched
// it from). Same containment pattern as dep-audit-mcp's SCAN_ROOT and local-delegate-mcp's
// CONTEXT_ROOT: a careless or attacker-influenced argument can't point the scanner at ~/.aws,
// ~/.ssh, or a sibling project.
//
// This matters more here than in the sibling servers. A secret scanner pointed somewhere
// unintended does not merely read those files, it reports what it found in them -- turning a
// path-traversal bug into credential disclosure. The redaction in lib/gitleaks.mjs limits the
// damage; this is what prevents it.
export function resolveScanPath(relOrAbsPath, scanRoot) {
  const resolved = path.resolve(scanRoot, relOrAbsPath);
  if (resolved !== scanRoot && !resolved.startsWith(scanRoot + path.sep)) {
    throw new Error(`refuses to scan outside ${scanRoot}: ${relOrAbsPath}`);
  }
  return resolved;
}
