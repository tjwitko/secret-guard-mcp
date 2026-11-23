// Reading gitleaks' log, a line at a time. Shared by the wrapper (lib/gitleaks.mjs) and the process
// that reads a tree's log as it is written (lib/gitleaks-run.mjs).

export const ANSI = /\x1b\[[0-9;]*m/g;

const MB = 1024 * 1024;

// What a scan holds. How much a tree leaves unread by design reaches none of them: the log is read
// and dropped, what was left unread is counted, and only the entries for the paths a caller named
// are kept. Reaching one is an error that says which.
export const LIMITS = {
  // gitleaks' JSON report.
  report: 50 * MB,
  // Its warnings and errors, which is what skipped() reads.
  log: 50 * MB,
  // The entries for the paths a caller asked about, as JSON. Under the 10 MB the MCP SDK's stdio
  // transport reads in one message: a reply of 122 MB closed the connection.
  unread: 8 * MB,
  // One line of the log. A path is far shorter; only a candidate value on a debug line can be longer,
  // and those lines are not read.
  line: MB,
};

export const inMB = (bytes) => `${Math.round(bytes / MB)} MB`;

// A field of gitleaks' log. Its logger quotes a value with Go's strconv.Quote when it holds a space,
// a quote, a control character or anything outside ASCII, so a file name cannot start a line or a
// field of its own. A byte that is not UTF-8 stays as the \xNN Go wrote.
const GO_ESCAPES = { a: "\x07", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", "\\": "\\", '"': '"', "'": "'" };
export const logValue = (text) => {
  if (!text.startsWith('"')) return text;
  return text.slice(1, -1).replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[\s\S])/g, (whole, e) => {
    if (e.length === 1) return GO_ESCAPES[e] ?? whole;
    const code = parseInt(e.slice(1), 16);
    return e[0] === "x" && code >= 0x80 ? whole : String.fromCodePoint(code);
  });
};

export const logField = (rest, name) => {
  const m = new RegExp(`(?:^|\\s)${name}=("(?:[^"\\\\]|\\\\.)*"|\\S*)`).exec(rest);
  return m ? logValue(m[1]) : null;
};

// One line saying gitleaks left something unread by design: { path, kind, mime? }, or null.
//
//   DBG skipping directory: global allowlist path=...      kind "directory", and all that is under it
//   DBG skipping file: global allowlist path=...           kind "file"
//   DBG skipping binary file mime_type=... path=...        kind "first-bytes", under any name
export function unreadLine(raw) {
  const line = /^\S+\s+DBG\s+skipping (directory: global allowlist|file: global allowlist|binary file)(?=\s|$)(.*)$/.exec(raw.replace(ANSI, "").trim());
  if (!line) return null;
  const p = logField(line[2], "path");
  if (line[1] === "binary file") return { path: p || null, kind: "first-bytes", mime: logField(line[2], "mime_type") };
  return { path: p || null, kind: line[1].startsWith("directory") ? "directory" : "file" };
}

// A line the wrapper reads afterwards: gitleaks' warnings, errors and fatal errors, or a panic.
// Every other line is dropped as it is read, the debug lines that can hold a candidate value among them.
export const keptLine = (raw) => {
  const line = raw.replace(ANSI, "").trim();
  return /^\S+\s+(WRN|ERR|FTL)\b/.test(line) || /^(panic|fatal error): /.test(line);
};
