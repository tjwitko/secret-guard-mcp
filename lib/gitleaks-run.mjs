// Runs gitleaks over a tree and reads its log as it is written, for scanPath.
//
// scanPath is synchronous, because its callers are, and spawnSync holds a child's whole output in one
// buffer. At --log-level debug that output grows with the tree: 330,000 one-byte .png files with paths
// of about 220 characters ended in "spawnSync gitleaks ENOBUFS", where a scan at "warn" was clean. So
// scanPath starts this process, which reads the log line by line, keeps only what the wrapper needs,
// and prints one JSON result. Not a temporary file for the log: a debug line can hold a candidate
// value, and a disk that fills up would lose lines without a word.

import { spawn } from "child_process";
import { readFileSync } from "fs";
import path from "path";

import { LIMITS, inMB, keptLine, unreadLine } from "./gitleaks-log.mjs";

// On stdin, because the paths a caller asks about can be longer than a command line.
const { args, target, unreadOf } = JSON.parse(readFileSync(0, "utf8"));

// Those paths and the directories above them, up to the target: a directory gitleaks did not enter
// is what leaves a file in it unread.
let wanted = null;
if (unreadOf) {
  wanted = new Set();
  for (const rel of unreadOf) {
    for (let p = path.join(target, rel); p !== target && p.startsWith(target + path.sep); p = path.dirname(p)) wanted.add(p);
  }
}

const stdout = [];
let reportBytes = 0;
let reportTooLarge = false;

const kept = [];
let keptBytes = 0;
let logTooLarge = false;

let unreadCount = 0;
let targetEntry = null;
let unread = wanted ? [] : null;
let unreadBytes = 0;
let unreadTooLarge = false;

function readLine(raw) {
  const said = unreadLine(raw);
  if (said) {
    unreadCount++;
    if (said.path === target) targetEntry = said;
    if (unread && wanted.has(said.path)) {
      unreadBytes += JSON.stringify(said).length + 1;
      if (unreadBytes > LIMITS.unread) {
        unreadTooLarge = true;
        unread = null;
      } else {
        unread.push(said);
      }
    }
    return;
  }
  if (!keptLine(raw)) return;
  keptBytes += raw.length + 1;
  if (keptBytes > LIMITS.log) logTooLarge = true;
  else kept.push(raw);
}

const child = spawn("gitleaks", args, { stdio: ["ignore", "pipe", "pipe"] });

child.stdout.on("data", (chunk) => {
  if (reportTooLarge) return;
  reportBytes += chunk.length;
  if (reportBytes > LIMITS.report) {
    reportTooLarge = true;
    stdout.length = 0;
    child.kill();
    return;
  }
  stdout.push(chunk);
});

let partial = "";
let overLong = false;
child.stderr.setEncoding("utf8");
child.stderr.on("data", (text) => {
  let from = 0;
  for (;;) {
    const end = text.indexOf("\n", from);
    if (end === -1) break;
    if (!overLong) readLine(partial + text.slice(from, end));
    partial = "";
    overLong = false;
    from = end + 1;
  }
  if (overLong) return;
  partial += text.slice(from);
  if (partial.length > LIMITS.line) {
    // Longer than any path: a candidate value on a debug line. A warning this long keeps its start.
    if (keptLine(partial)) readLine(partial.slice(0, LIMITS.line));
    partial = "";
    overLong = true;
  }
});

// Once: a child that could not be started can report both "error" and "close".
let finished = false;
const finish = (result) => {
  if (finished) return;
  finished = true;
  process.stdout.write(JSON.stringify(result));
};

child.on("error", (err) => finish({ spawnError: err.message }));

child.on("close", (status) => {
  if (partial && !overLong) readLine(partial);
  if (reportTooLarge) {
    finish({ error: `gitleaks' report passed the ${inMB(LIMITS.report)} a scan holds, so its findings are not all known. Scan a smaller directory.` });
    return;
  }
  const ceilings = [];
  if (logTooLarge) ceilings.push(`gitleaks' warnings about what it could not read passed the ${inMB(LIMITS.log)} a scan holds, so the list of them is not whole. Scan a smaller directory.`);
  if (unreadTooLarge) {
    ceilings.push(`the unread paths asked about passed the ${inMB(LIMITS.unread)} one reply can carry, so the answer is not whole. Ask about fewer paths at a time.`);
  }
  finish({ status, stdout: Buffer.concat(stdout).toString("utf8"), stderr: kept.join("\n"), unread, unreadCount, targetEntry, ceilings });
});
