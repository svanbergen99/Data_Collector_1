import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import net from "node:net";
import path from "node:path";
import process from "node:process";

const ROOT = process.cwd();
const MODE = process.argv[2] ?? "audit";
const REQUIRED = [".github/workflows/security-audit.yml", ".gitignore", "SECURITY.md", "package.json", "server.mjs", "tools/security-suite.mjs"];
const SKIP_DIRS = new Set([".git", "node_modules", "coverage", "dist", "build", ".cache", ".tmp", "tmp"]);
const FORBIDDEN_EXTENSIONS = new Set([".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".sqlite", ".sqlite3", ".db", ".dump", ".backup", ".bak", ".log", ".zip", ".tar", ".tgz", ".gz", ".7z", ".rar", ".map", ".html", ".htm", ".css"]);
function fail(message) { throw new Error(message); }
async function walk(dir = ROOT) {
  const out = [];
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    const rel = path.relative(ROOT, full).split(path.sep).join("/");
    if (entry.isDirectory()) out.push(...await walk(full));
    else if (entry.isFile()) out.push(rel);
    else fail(`Symlink/special filesystem entry forbidden: ${rel}`);
  }
  return out.sort();
}
async function audit() {
  const files = await walk();
  for (const required of REQUIRED) if (!files.includes(required)) fail(`Missing required security file: ${required}`);
  for (const rel of files) {
    const lower = rel.toLowerCase(), base = path.basename(lower), ext = path.extname(lower);
    if (base === ".env" || base.startsWith(".env.")) fail(`Environment file forbidden: ${rel}`);
    if (FORBIDDEN_EXTENSIONS.has(ext)) fail(`Forbidden repository artifact: ${rel}`);
    const stat = await fs.stat(path.join(ROOT, rel));
    if (stat.size > 1_048_576) fail(`Repository file exceeds 1 MiB security limit: ${rel}`);
    const bytes = await fs.readFile(path.join(ROOT, rel));
    if (bytes.subarray(0, Math.min(bytes.length, 4096)).includes(0)) fail(`Binary repository file forbidden: ${rel}`);
    if (rel === "tools/security-suite.mjs") continue;
    const text = bytes.toString("utf8");
    const checks = [
      [/(?:ghp|github_pat)_[A-Za-z0-9_\-]{20,}/, "GitHub token-like value"], [/AKIA[0-9A-Z]{16}/, "AWS access-key-like value"], [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/, "private key material"], [/\bBearer\s+[A-Za-z0-9._~+\/-]{16,}/i, "Bearer credential"], [/\bBasic\s+[A-Za-z0-9+/=]{12,}/i, "Basic credential"], [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, "JWT-like value"], [/(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s:@/]+:[^\s@/]+@/i, "credential-bearing database URI"], [/https?:\/\/[^\s/:]+:[^\s@/]+@/i, "credential-bearing URL"], [/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/, "private network literal"], [/\.railway\.app\b/i, "public Railway hostname"], [/\beval\s*\(/, "eval"], [/new\s+Function\s*\(/, "dynamic Function constructor"], [/node:child_process|require\(["']child_process["']\)/, "child process execution"], [/rejectUnauthorized\s*:\s*false/, "disabled TLS verification"], [/NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/, "disabled TLS verification"], [/document\.cookie|localStorage|sessionStorage|innerHTML\s*=|outerHTML\s*=/, "browser persistence/injection surface"]
    ];
    for (const [regex, description] of checks) if (regex.test(text)) fail(`${description} found in ${rel}`);
  }
  const pkg = JSON.parse(await fs.readFile(path.join(ROOT, "package.json"), "utf8"));
  if (pkg.private !== true || pkg.type !== "module") fail("package.json hardening fields missing");
  if (Object.keys(pkg.dependencies ?? {}).length || Object.keys(pkg.devDependencies ?? {}).length) fail("Runtime security shell must remain dependency-free");
  if (pkg.engines?.node !== ">=22 <23") fail("Node runtime must remain pinned to major 22");
  const server = await fs.readFile(path.join(ROOT, "server.mjs"), "utf8");
  for (const fragment of ["maxHeaderSize: 8192", "requestTimeout: 5000", "headersTimeout: 4000", "connectionsCheckingInterval: 1000", "keepAliveTimeout: 5000", "server.maxHeadersCount = 64", "server.maxRequestsPerSocket = 100", "CONTROL_CHARS.test(pathname)", "pathname.includes(\"..\")", "parsed.pathname !== \"/healthz\"", "server.on(\"upgrade\"", "server.on(\"connect\"", "default-src 'none'", "frame-ancestors 'none'"]) if (!server.includes(fragment)) fail(`Required server hardening missing: ${fragment}`);
  const envReads = [...server.matchAll(/process\.env\.([A-Z0-9_]+)/g)].map((m) => m[1]);
  const unexpectedEnv = [...new Set(envReads)].filter((name) => name !== "PORT");
  if (unexpectedEnv.length) fail(`Unexpected runtime environment variable in deny shell: ${unexpectedEnv.join(", ")}`);
  if (/\bfetch\s*\(|node:https|node:http2|node:fs|node:dgram|node:tls/.test(server)) fail("Deny shell may not perform outbound/data/file operations");
  const digest = createHash("sha256").update(files.join("\n")).digest("hex").slice(0, 16);
  process.stdout.write(`security-audit-ok files=${files.length} manifest=${digest}\n`);
}
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function startServer() {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, ["server.mjs"], { cwd: ROOT, env: { ...process.env, PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "", stderr = "";
  child.stdout.on("data", (c) => { stdout += c.toString(); }); child.stderr.on("data", (c) => { stderr += c.toString(); });
  const deadline = Date.now() + 5000;
  while (!stdout.includes(`collector-runtime-ready:${port}`)) { if (child.exitCode !== null) fail(`Server exited during startup: ${stderr}`); if (Date.now() > deadline) fail(`Server startup timeout: ${stderr}`); await wait(25); }
  return { child, port };
}
async function stopServer(child) { if (child.exitCode !== null) return; child.kill("SIGTERM"); const deadline = Date.now() + 2000; while (child.exitCode === null && Date.now() < deadline) await wait(20); if (child.exitCode === null) child.kill("SIGKILL"); }
function rawRequest(port, payload, timeoutMs = 3000) { return new Promise((resolve) => { const socket = net.createConnection({ host: "127.0.0.1", port }); let data = "", settled = false; const finish = () => { if (settled) return; settled = true; socket.destroy(); resolve(data); }; socket.setTimeout(timeoutMs, finish); socket.on("connect", () => socket.write(payload)); socket.on("data", (c) => { data += c.toString("latin1"); }); socket.on("end", finish); socket.on("close", finish); socket.on("error", finish); }); }
const statusFromRaw = (raw) => { const match = raw.match(/^HTTP\/1\.1\s+(\d{3})/); return match ? Number(match[1]) : null; };
async function health(port, method = "GET") { const response = await fetch(`http://127.0.0.1:${port}/healthz`, { method, redirect: "manual", cache: "no-store" }); const body = await response.text(); return { response, body }; }
async function openSlowloris(port, count) { const sockets = []; let opened = 0; for (let i = 0; i < count; i += 1) { const socket = new net.Socket(); socket.setNoDelay(true); socket.on("data", () => {}); socket.on("error", () => {}); await new Promise((resolve) => { const timer = setTimeout(() => { socket.destroy(); resolve(); }, 1000); socket.once("connect", () => { clearTimeout(timer); opened += 1; socket.write("GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Slow: "); resolve(); }); socket.once("error", () => { clearTimeout(timer); resolve(); }); socket.connect(port, "127.0.0.1"); }); sockets.push(socket); } return { sockets, opened }; }
async function assertSlowlorisClosed(sockets, timeoutMs = 6500) { const deadline = Date.now() + timeoutMs; while (Date.now() < deadline) { if (sockets.every((s) => s.destroyed)) return; await wait(100); } const survivors = sockets.filter((s) => !s.destroyed); for (const s of survivors) s.destroy(); if (survivors.length) fail(`Slowloris survivors after timeout: ${survivors.length}`); }
async function runConcurrent(total, concurrency, fn) { let next = 0, ok = 0, failed = 0; async function worker() { while (true) { const index = next++; if (index >= total) return; try { if (await fn(index)) ok += 1; else failed += 1; } catch { failed += 1; } } } await Promise.all(Array.from({ length: concurrency }, () => worker())); return { ok, failed }; }
async function runtime() {
  const { child, port } = await startServer();
  try {
    const get = await health(port); if (get.response.status !== 204 || get.body !== "") fail("GET /healthz must be empty 204");
    const head = await health(port, "HEAD"); if (head.response.status !== 204 || head.body !== "") fail("HEAD /healthz must be empty 204");
    for (const [name, expected] of Object.entries({ "cache-control": "no-store", "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff", "x-frame-options": "DENY" })) if (get.response.headers.get(name) !== expected) fail(`Security header mismatch: ${name}`);
    if (get.response.headers.has("set-cookie") || get.response.headers.has("access-control-allow-origin")) fail("Cookie/CORS exposure forbidden");
    for (const target of ["/", "/index.html", "/app.js", "/styles.css", "/.env", "/.git/config", "/server.mjs", "/package.json", "/admin", "/internal", "/debug", "/metrics", "/api"]) if (statusFromRaw(await rawRequest(port, `GET ${target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n`)) !== 404) fail(`Hidden/backdoor route did not return 404: ${target}`);
    for (const target of ["/%00", "/%09", "/%0a", "/%0d", "/%1f", "/%7f", "/%5c", "/%2e%2e", "/../", "/%ZZ"]) if (statusFromRaw(await rawRequest(port, `GET ${target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n`)) !== 400) fail(`Hostile path did not fail closed: ${target}`);
    const longRaw = await rawRequest(port, `GET /${"a".repeat(2050)} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n`); if (statusFromRaw(longRaw) !== 414) fail("Oversized target must return 414");
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]) if (statusFromRaw(await rawRequest(port, `${method} /healthz HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`)) !== 405) fail(`Forbidden method not rejected: ${method}`);
    if (statusFromRaw(await rawRequest(port, "POST /healthz HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n")) !== 400) fail("CL+TE smuggling probe must fail 400");
    if (statusFromRaw(await rawRequest(port, `GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Big: ${"b".repeat(9000)}\r\n\r\n`)) !== 400) fail("Oversized header must fail 400");
    if (statusFromRaw(await rawRequest(port, "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")) === 101) fail("WebSocket upgrade forbidden");
    const slow = await openSlowloris(port, 64); if (slow.opened < 48) fail(`Too few Slowloris sockets: ${slow.opened}`);
    const legitimate = await runConcurrent(500, 50, async () => (await health(port)).response.status === 204); if (legitimate.ok !== 500 || legitimate.failed) fail(`Legitimate traffic degraded: ${JSON.stringify(legitimate)}`);
    await assertSlowlorisClosed(slow.sockets); if ((await health(port)).response.status !== 204 || child.exitCode !== null) fail("Server failed recovery");
    process.stdout.write(`runtime-security-ok slowloris=${slow.opened} legitimate=${legitimate.ok}\n`);
  } finally { await stopServer(child); }
}
async function siege() {
  if (process.argv.length > 3) fail("Local siege accepts no remote target or additional arguments");
  const { child, port } = await startServer();
  try {
    const slow = await openSlowloris(port, 300); if (slow.opened < 240) fail(`Too few siege sockets: ${slow.opened}`);
    const normal = await runConcurrent(6000, 250, async () => (await health(port)).response.status === 204); if (normal.ok !== 6000 || normal.failed) fail(`Siege normal failures: ${JSON.stringify(normal)}`);
    const targets = ["/.env", "/.git/config", "/admin", "/internal", "/%00", "/%0d", "/%7f", "/%5c", "/%2e%2e", "/../"];
    const hostile = await runConcurrent(1000, 100, async (i) => { const status = statusFromRaw(await rawRequest(port, `GET ${targets[i % targets.length]} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n`)); return status === 400 || status === 404; }); if (hostile.ok !== 1000 || hostile.failed) fail(`Siege hostile failures: ${JSON.stringify(hostile)}`);
    await assertSlowlorisClosed(slow.sockets); const recovery = await runConcurrent(1000, 100, async () => (await health(port)).response.status === 204); if (recovery.ok !== 1000 || recovery.failed || child.exitCode !== null) fail(`Siege recovery failed: ${JSON.stringify(recovery)}`);
    process.stdout.write(`local-siege-ok normal=${normal.ok} hostile=${hostile.ok} slowloris=${slow.opened} recovery=${recovery.ok}\n`);
  } finally { await stopServer(child); }
}
if (MODE === "audit") await audit(); else if (MODE === "runtime") await runtime(); else if (MODE === "siege") await siege(); else fail(`Unknown mode: ${MODE}`);
