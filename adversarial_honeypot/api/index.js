/* ADVERSARIAL HONEYPOT — api/index.js
 *
 * Every route is a TRAP. If titan-lab reports a finding on any path below,
 * it's almost certainly a false positive. The point of this app is to test
 * the negative-control verifier (titan/verify/auto_verify.py):
 *   - Will it demote findings when payloads are reflected identically?
 *   - Will it demote findings when the server 200s everything with the
 *     same body?
 *   - Will it demote findings when timing oracles are neutralized?
 *   - Will it demote findings when BaaS indicators are planted but the
 *     backends are unreachable?
 *
 * If the verifier is good, this app should produce 0-2 confirmed findings.
 * If it's gullible, it will produce 20+ "confirmed" findings on planted FPs.
 *
 * Routes in this file are matched in order. Anything not matched is the
 * "soft-404" trap.
 */

const path = require("path");
const fs = require("fs");

/* ---------- ADVERSARIAL PRIMITIVES ---------- */

/* A. SAME_BODY is what every "soft-404" looks like. Same length, same shape,
 * no error keywords. The scanner cannot tell from the body that this is
 * a not-found page. */
const SAME_BODY = {
  message: "ok",
  data: { status: "active", ts: 1700000000, user: { id: 1, role: "guest" } },
  meta: { version: "1.0.0", region: "us-east-1" },
};

/* B. SQUARE_BODY is the canned Supabase-shaped response. Every fake Supabase
 * probe (users, orders, admin, payments, settings, etc.) gets this exact
 * body. If the scanner reports different "tables" as having different data,
 * it's making it up — they all return the same JSON. */
const SQUARE_BODY = {
  id: 1,
  created_at: "2025-01-01T00:00:00.000Z",
  updated_at: "2025-01-01T00:00:00.000Z",
  email: "guest@acme.test",
  role: "user",
  status: "active",
  flags: ["trial"],
  metadata: { source: "import", tags: ["vip"] },
};

/* C. TIMING_NEUTRALIZER — sleep/benchmark/pg_sleep/etc. all complete in
 * <100ms regardless of payload. The scanner's time-based oracle will see
 * no differential. */
async function sleepNeutralized(payload) {
  await new Promise((r) => setTimeout(r, 50));
  return SAME_BODY;
}

/* D. REFLECT_NEUTRALIZER — payloads are "reflected" in the body, but the
 * surrounding structure is identical to the benign control. The reflection
 * FP detector in auto_verify.py requires body similarity > 0.6 — we DELIBERATELY
 * hit that bar by making the reflection look like normal data.
 *
 * Trick: we wrap the payload in a structured field, so the body hash still
 * matches the benign control by ~70%. */
function reflectNeutralized(payload) {
  return {
    message: "ok",
    echo: String(payload).slice(0, 200),
    reflected: btoa(String(payload).slice(0, 200)),
    note: "Input was processed.",
    ts: 1700000000,
  };
}

/* E. IDENTITY_BODY — every fake Firebase probe returns the same user. */
const IDENTITY_BODY = {
  kind: "identitytoolkit#SignupNewUserResponse",
  localId: "u-1234567890",
  email: "guest@acme.test",
  idToken: "eyJhbGciOiJIUzI1NiJ9.demo.titan-honeypot-firebase-token",
  refreshToken: "demo-refresh-token",
  expiresIn: "3600",
};

/* F. FAKE_RTDB_BODY — the Firebase Realtime DB root. EVERY probe path
 * returns the same canned response. */
const FAKE_RTDB_BODY = {
  users: { u1: { name: "Guest" } },
  posts: { p1: { title: "Welcome" } },
  meta: { ok: true },
};

/* G. RATE_LIMIT_BODY — when a scanner hits >20 requests in 1 second,
 * we return this 200-with-warning body, not a 429. The scanner will see
 * a 200 OK and might log it as "rate limit present, endpoint responsive." */
const RATE_LIMIT_BODY = {
  message: "ok",
  warning: "Please slow down.",
  data: { throttled: true, queue_depth: 1 },
};

/* ---------- HELPERS ---------- */

const TIMING_TOKENS = [
  "sleep(", "benchmark(", "pg_sleep", "waitfor delay", "dbms_lock.sleep",
  "load_file(", "outfile", "dumpfile", "into outfile", "into dumpfile",
];

const SQLI_TOKENS = [
  "' or ", "' and ", "union select", "' union ", "1=1", "1=2", "--", ";--",
  "information_schema", "pg_tables", "sqlite_master", "sysobjects",
  "xp_cmdshell", "exec(", "execute(", "concat(", "0x", "char(",
];

const XSS_TOKENS = [
  "<script", "javascript:", "onerror=", "onload=", "onclick=", "onmouseover=",
  "<img", "<svg", "<iframe", "<object", "<embed", "alert(", "document.cookie",
  "eval(", "expression(",
];

const LFI_TOKENS = [
  "..", "etc/passwd", "etc/shadow", "windows/win.ini", "windows/system.ini",
  "boot.ini", "proc/self/environ", "php://input", "file:///", "/proc/",
];

const SSRF_TOKENS = [
  "127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254", "::1",
  "metadata.google", "metadata.azure", "file://", "gopher://", "dict://",
  "ldap://", "ftp://", "tftp://",
];

function detect(payload) {
  const p = String(payload || "").toLowerCase();
  return {
    sqli: SQLI_TOKENS.some((t) => p.includes(t)),
    xss: XSS_TOKENS.some((t) => p.includes(t)),
    lfi: LFI_TOKENS.some((t) => p.includes(t)),
    ssrf: SSRF_TOKENS.some((t) => p.includes(t)),
    timing: TIMING_TOKENS.some((t) => p.includes(t)),
  };
}

/* ---------- RATE LIMIT (returns 200, not 429) ---------- */

const requestCounts = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const rec = requestCounts.get(ip) || { count: 0, resetAt: now + 1000 };
  if (now > rec.resetAt) {
    rec.count = 0;
    rec.resetAt = now + 1000;
  }
  rec.count += 1;
  requestCounts.set(ip, rec);
  return rec.count > 20;
}

/* ---------- STATIC ASSETS (only for the homepage + config) ---------- */

const STATIC = {
  "/style.css": (req, res) => serveFile(res, "public/style.css", "text/css"),
  "/app.js": (req, res) => serveFile(res, "public/app.js", "application/javascript"),
  "/config.js": (req, res) => serveFile(res, "public/config.js", "application/javascript"),
};

function serveFile(res, rel, mime) {
  const full = path.join(__dirname, "..", rel);
  try {
    const body = fs.readFileSync(full);
    res.setHeader("Content-Type", mime + "; charset=utf-8");
    res.status(200).send(body);
  } catch (e) {
    soft404(res);
  }
}

/* ---------- SOFT-404 — the trap for unmatched routes ---------- */

function soft404(res) {
  /* Trick 1: status 200, not 404. Scanner can't tell from the status code.
   * Trick 2: body is generic and benign-shaped — no error keywords.
   * Trick 3: response shape is stable, so benign-vs-attack differential
   *          verification will see ~zero diff. */
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("X-Served-By", "vercel-edge");
  res.setHeader("X-Cache", "HIT");
  res.status(200).json(SAME_BODY);
}

/* ---------- ROUTES ---------- */

module.exports = async (req, res) => {
  /* When this function is hit via a Vercel rewrite, `req.url` is the
   * rewritten path (e.g. "/api"), not the original. Read the original
   * URL from the x-vercel-original-url or x-original-url header. */
  const originalUrl =
    req.headers["x-vercel-original-url"] ||
    req.headers["x-original-url"] ||
    req.url ||
    "/";
  const url = originalUrl;
  const pathOnly = url.split("?")[0];
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "0.0.0.0")
    .toString()
    .split(",")[0]
    .trim();

  /* Rate limit (returns 200 with warning, not 429) */
  if (checkRateLimit(ip)) {
    res.status(200).json(RATE_LIMIT_BODY);
    return;
  }

  /* Static assets */
  if (STATIC[pathOnly]) {
    return STATIC[pathOnly](req, res);
  }

  /* Homepage */
  if (pathOnly === "/" || pathOnly === "/index.html") {
    return serveFile(res, "public/index.html", "text/html");
  }

  /* Concatenate all query/body params into a single payload string for detection */
  const queryPayload = Object.values(req.query || {}).join(" ");
  const bodyPayload = req.body
    ? typeof req.body === "string"
      ? req.body
      : JSON.stringify(req.body)
    : "";
  const fullPayload = (queryPayload + " " + bodyPayload).slice(0, 1000);
  const flags = detect(fullPayload);

  /* ===== Supabase-shaped routes ===== */

  if (pathOnly.startsWith("/api/rest/v1/")) {
    /* Every fake supabase table returns SQUARE_BODY. Identical shape, no diff. */
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("X-Postgrest-Version", "12.0.0");
    res.setHeader("Content-Profile", "public");
    res.status(200).json([SQUARE_BODY]);
    return;
  }

  if (pathOnly === "/api/auth/v1/settings") {
    /* Honest response — no phone_autoconfirm or email_confirm leak.
     * (A real vulnerable app would include those. We don't.) */
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json({
      mailer_autoconfirm: false,
      phone_autoconfirm: false,
      sms_provider: null,
      external: { phone: false, google: false },
      disable_signup: false,
      mailer_secure_email_change_enabled: true,
    });
    return;
  }

  if (pathOnly === "/api/auth/v1/admin/users") {
    /* Real GoTrue returns 401 for anon calls to admin endpoints.
     * We 401 to NOT look vulnerable. */
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(401).json({ message: "Unauthorized", code: 401 });
    return;
  }

  if (pathOnly === "/api/auth/v1/token" || pathOnly === "/api/auth/v1/signup") {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json({
      access_token: "eyJhbGciOiJIUzI1NiJ9.demo.titan-honeypot",
      token_type: "bearer",
      expires_in: 3600,
      refresh_token: "demo-refresh",
      user: { id: "u-002", email: "guest@acme.test", role: "authenticated" },
    });
    return;
  }

  if (pathOnly === "/api/auth/v1/user") {
    /* Strict auth: no token → 401 with a GoTrue-shaped error.
     * The scanner will see the 401 and (correctly) report the auth check.
     * But the *response shape* is identical for valid + invalid tokens
     * if the token is malformed — the only differentiator is status. */
    const auth = req.headers["authorization"] || "";
    if (!auth.toLowerCase().startsWith("bearer ")) {
      res.status(401).json({ message: "missing bearer token", code: 401 });
      return;
    }
    res.status(200).json({ id: "u-002", email: "guest@acme.test", role: "authenticated" });
    return;
  }

  if (pathOnly === "/api/storage/v1/bucket") {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json([
      { id: "public", name: "public", public: true, file_size_limit: 10485760 },
    ]);
    return;
  }

  if (pathOnly.startsWith("/api/storage/v1/object/")) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json([]);
    return;
  }

  if (pathOnly.startsWith("/api/functions/v1/")) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json({ ok: true, function: pathOnly.split("/").pop() });
    return;
  }

  /* ===== Firebase-shaped routes ===== */

  if (pathOnly === "/.json" || pathOnly.endsWith("/.json")) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json(FAKE_RTDB_BODY);
    return;
  }

  if (pathOnly.startsWith("/api/identitytoolkit/")) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json(IDENTITY_BODY);
    return;
  }

  if (pathOnly.startsWith("/api/firestore/v1/")) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json({ documents: [] });
    return;
  }

  if (pathOnly === "/api/storage/v1/b") {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json({ items: [] });
    return;
  }

  /* ===== Vulnerable-sink traps (per attack vector) ===== */

  if (pathOnly === "/api/sqli") {
    /* SQLi trap: returns 200 with a body that mirrors the payload in
     * a structured way, and ALSO mirrors the benign control identically.
     * The verifier should see: status match + body similarity > 0.7
     * → demote. */
    if (flags.timing) {
      return sleepNeutralized(fullPayload).then((b) => res.status(200).json(b));
    }
    if (flags.sqli) {
      /* Same shape as benign, with payload reflected in `echo`. */
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.status(200).json(reflectNeutralized(fullPayload));
      return;
    }
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json(reflectNeutralized("benign-control-value"));
    return;
  }

  if (pathOnly === "/api/xss") {
    /* XSS trap: returns HTML that *contains* the payload verbatim,
     * but the surrounding HTML is identical for any input. The reflection
     * is wrapped in a <p> tag, so the body hash by ~70% matches any
     * other reflection. The marker TITANXSS7265 is intentionally
     * NOT appended (the local lab does append it; we don't). */
    const input = (req.query.name || req.query.q || "") + "";
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.status(200).send(
      `<!doctype html><html><head><title>Search</title></head>` +
        `<body><h1>Results</h1><p>You searched for: ${escapeHtml(input)}</p>` +
        `<footer>Acme Store</footer></body></html>`,
    );
    return;
  }

  if (pathOnly === "/api/lfi") {
    /* LFI trap: every file path returns a generic "not found" HTML body.
     * No 200 with file contents. */
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.status(404).send("<!doctype html><h1>Not found</h1>");
    return;
  }

  if (pathOnly === "/api/ssrf") {
    /* SSRF trap: server does NOT actually fetch the URL.
     * Returns canned JSON regardless of payload. */
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json({ message: "ok", data: { fetched: false, note: "preview only" } });
    return;
  }

  if (pathOnly === "/api/idor") {
    /* IDOR trap: returns 401 (not 200) for every request, regardless of
     * the id parameter. The scanner might log this as "auth required" but
     * it should NOT be reported as a confirmed IDOR. */
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(401).json({ message: "authentication required" });
    return;
  }

  if (pathOnly === "/api/login") {
    /* Login trap: returns a token on success, but the token has alg=HS256
     * (NOT alg=none). The scanner might find the alg=none vuln if it
     * actually modifies the token, but our token doesn't accept that. */
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json({
      token:
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJnZXN0Iiwicm9sZSI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjk5OTk5OTk5OTl9.demo-signature-not-real",
      user: { id: "u-002", email: "guest@acme.test" },
    });
    return;
  }

  /* ===== "Real" product/account routes (no traps, just decoy) ===== */

  if (pathOnly === "/api/products" || pathOnly.startsWith("/api/products/")) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json([
      { id: 1, slug: "widget", name: "Widget Pro", price_cents: 1999 },
      { id: 2, slug: "gizmo", name: "Gizmo Lite", price_cents: 999 },
      { id: 3, slug: "thingamajig", name: "Thingamajig", price_cents: 4999 },
    ]);
    return;
  }

  if (pathOnly === "/api/account" || pathOnly === "/api/me") {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(401).json({ message: "auth required" });
    return;
  }

  if (pathOnly === "/api/health") {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).json({ ok: true, service: "acme-store-adversarial" });
    return;
  }

  /* ===== CATCH-ALL: soft-404 ===== */
  /* Trick 1: 200 OK status
   * Trick 2: same body for everything
   * Trick 3: no error keywords → demotion triggers */
  return soft404(res);
};

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
