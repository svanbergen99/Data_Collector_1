import { createServer } from "node:http";

const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;
const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);

if (!Number.isInteger(PORT) || PORT < 0 || PORT > 65535) throw new Error("Invalid PORT");
if (process.execArgv.some((arg) => arg.startsWith("--inspect"))) throw new Error("Node inspector is disabled for this service");

const SECURITY_HEADERS = Object.freeze({
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-Robots-Tag": "noindex, nofollow, noarchive"
});

function parsePath(requestTarget) {
  if (typeof requestTarget !== "string" || requestTarget.length > 2048) return { error: 414 };
  const queryIndex = requestTarget.indexOf("?");
  const rawPath = queryIndex === -1 ? requestTarget : requestTarget.slice(0, queryIndex);
  if (!rawPath.startsWith("/") || rawPath.includes("\\")) return { error: 400 };
  let pathname;
  try { pathname = decodeURIComponent(rawPath); } catch { return { error: 400 }; }
  if (!pathname.startsWith("/") || pathname.includes("\\") || CONTROL_CHARS.test(pathname) || pathname.includes("..")) return { error: 400 };
  return { pathname };
}

function empty(res, statusCode, extra = {}) {
  res.writeHead(statusCode, { ...SECURITY_HEADERS, "Content-Length": "0", ...extra });
  res.end();
}

const server = createServer({ maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 4000, connectionsCheckingInterval: 1000, keepAliveTimeout: 5000 }, (req, res) => {
  const parsed = parsePath(req.url ?? "");
  if (parsed.error) { req.resume(); empty(res, parsed.error); return; }
  if (req.method !== "GET" && req.method !== "HEAD") { req.resume(); empty(res, 405, { Allow: "GET, HEAD" }); return; }
  if (parsed.pathname !== "/healthz") { req.resume(); empty(res, 404); return; }
  req.resume();
  empty(res, 204);
});

server.maxHeadersCount = 64;
server.maxRequestsPerSocket = 100;
server.on("clientError", (_error, socket) => {
  if (!socket.writable) { socket.destroy(); return; }
  socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
});
server.on("upgrade", (_req, socket) => socket.destroy());
server.on("connect", (_req, socket) => socket.destroy());
server.listen(PORT, "0.0.0.0", () => {
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : PORT;
  process.stdout.write(`collector-runtime-ready:${port}\n`);
});
