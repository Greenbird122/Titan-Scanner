"""S5 — interactive HTML dashboard from a site's persisted findings.

Reads ``findings.json`` + ``scan_meta.json`` from a per-site directory (as
written by SiteReportWriter) and renders a SINGLE self-contained HTML file —
all CSS and JS inlined, zero external resources, opens offline in any
browser. This is the operator-facing exploration surface the markdown report
can't be: filter by severity/attack-type, full-text search, sortable rows,
expandable finding details (payload, evidence markers, PoC with copy buttons),
attack chains, and exploitation sessions.

Usage::

    from titan.reporting.dashboard import build_dashboard
    out = build_dashboard(Path("findings/localhost-5000"))   # -> dashboard.html
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unconfirmed"]
_SEVERITY_COLORS = {
    "critical": "#d93025",
    "high": "#e37400",
    "medium": "#f5a623",
    "low": "#6a9955",
    "info": "#3b82f6",
    "unconfirmed": "#9e9e9e",
}


def _esc(value: Any) -> str:
    """HTML-escape a value for safe inline rendering (XSS-safe by construction)."""
    return html.escape(str(value), quote=True)


def _iso(epoch: Optional[float]) -> str:
    if not epoch:
        return "n/a"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def _finding_rows(site_dir: Path) -> List[Dict[str, Any]]:
    """Normalize findings.json into render-ready rows (defensive defaults)."""
    data = _load_json(site_dir / "findings.json") or {}
    raw_findings = data.get("findings") or []
    rows: List[Dict[str, Any]] = []
    for f in raw_findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "unconfirmed").lower()
        if sev not in _SEVERITY_COLORS:
            sev = "unconfirmed"
        attack = f.get("attack_type") or "Unknown"
        rows.append(
            {
                "severity": sev,
                "attack_type": str(attack),
                "verified": bool(f.get("verified")),
                "confidence": float(f.get("confidence") or 0.0),
                "evidence": str(f.get("evidence") or "no-grade"),
                "tier": str(f.get("tier") or ""),
                "method": str(f.get("method") or "GET"),
                "url": str(f.get("url") or ""),
                "param": str(f.get("param") or ""),
                "location": str(f.get("location") or ""),
                "payload": str(f.get("payload") or ""),
                "status": f.get("status"),
                "cvss_score": f.get("cvss_score"),
                "cvss_vector": str(f.get("cvss_vector") or ""),
                "diffs": [str(d) for d in (f.get("diffs") or [])],
                "tags": [str(t) for t in (f.get("tags") or [])],
                "poc_curl": str(f.get("poc_curl") or ""),
                "poc_python": str(f.get("poc_python") or ""),
                "chain": [str(c) for c in (f.get("chain") or [])],
                "body": str(f.get("body") or "")[:2000],
            }
        )
    return rows


def _severity_order_key(sev: str) -> int:
    try:
        return _SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(_SEVERITY_ORDER)


def build_dashboard(site_dir: Path, out_path: Optional[Path] = None) -> Path:
    """Render the interactive dashboard for a site directory.

    Reads findings.json + scan_meta.json (optional). Writes ``dashboard.html``
    next to them by default, or to ``out_path``. Returns the written path.
    """
    site_dir = Path(site_dir)
    meta = _load_json(site_dir / "scan_meta.json") or {}
    findings_data = _load_json(site_dir / "findings.json") or {}
    rows = _finding_rows(site_dir)
    chains = [c for c in (findings_data.get("chains") or []) if isinstance(c, dict)]
    sessions = [s for s in (findings_data.get("exploit_sessions") or []) if isinstance(s, dict)]
    # Track G — hostile & ad-monetized surface (hostile.json written alongside
    # findings.json by SiteReportWriter when the scan ran profile: hostile).
    hostile = _load_json(site_dir / "hostile.json") or {}

    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unconfirmed": 0}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    verified = sum(1 for r in rows if r["verified"])
    attacks = sorted({r["attack_type"] for r in rows})

    target = str(meta.get("target") or findings_data.get("target") or site_dir.name)
    total = len(rows)
    duration = meta.get("duration_seconds")
    techs = meta.get("technologies") or []
    errors = meta.get("errors") or []

    # --- JSON payload embedded for the JS table ---------------------------------
    # OWASP rule for embedding JSON in <script>: escape <, > and & as unicode
    # escapes so a payload containing `</script>` can never terminate the
    # script block (json.dumps alone does NOT escape these).
    def _json_embed(data: Any) -> str:
        return (
            json.dumps(data, ensure_ascii=False)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
        )

    json_rows = _json_embed(rows)
    json_chains = _json_embed(chains)

    stat_cards = [
        ("Total", str(total), "#e8eaed"),
        ("Verified", str(verified), "#34a853"),
        ("Critical", str(counts["critical"]), _SEVERITY_COLORS["critical"]),
        ("High", str(counts["high"]), _SEVERITY_COLORS["high"]),
        ("Chains", str(len(chains)), "#9334e6"),
        ("Sessions", str(len(sessions)), "#e91e8c"),
    ]
    if hostile:
        hprof = hostile.get("profile", {})
        stat_cards.append(("Ad origins", str(len(hprof.get("origins", []))), "#ff8a65"))
        stat_cards.append(("MScore", str(hprof.get("monetization_score", 0)), "#ffb74d"))
    cards_html = "\n".join(
        f'<div class="stat"><div class="stat-num" style="color:{color}">{num}</div>'
        f'<div class="stat-label">{label}</div></div>'
        for label, num, color in stat_cards
    )

    chain_cards = ""
    for i, c in enumerate(chains, 1):
        hops = c.get("hops") or []
        hop_lines = "\n".join(
            f'<li><span class="tag">{_esc(h.get("attack_type") or "Unknown")}</span> '
            f"{_esc(h.get('method', 'GET'))} <code>{_esc(h.get('url') or '')}</code></li>"
            for h in hops
        )
        caps = " ".join(f'<span class="chip">{_esc(cap)}</span>' for cap in (c.get("capabilities") or []))
        chain_cards += (
            f'<details class="chain"><summary>Chain {i}: '
            f'<strong>{_esc(c.get("name") or "Unknown")}</strong> '
            f'<span class="sev sev-{(str(c.get("severity") or "medium")).lower()}">'
            f"{_esc(c.get('severity') or 'MEDIUM')}</span></summary>"
            f"<p>{_esc(c.get('impact') or '')}</p>{caps}<ul>{hop_lines}</ul></details>"
        )
    if not chain_cards:
        chain_cards = '<p class="muted">No attack chains composed for this site.</p>'

    session_lines = ""
    for s in sessions:
        detail = ""
        if s.get("webshell_url"):
            detail += f"<p>Webshell: <code>{_esc(s['webshell_url'])}</code></p>"
        if s.get("dump"):
            d = s["dump"]
            detail += f"<p>Dump: {_esc(d.get('technique'))} on {_esc(d.get('table'))} ({_esc(d.get('rows'))} rows)</p>"
        if s.get("dir"):
            detail += f"<p class='muted'>{_esc(s['dir'])}</p>"
        session_lines += (
            f'<div class="session"><span class="tag">{_esc(s.get("channel") or "?")}</span> '
            f"session <code>{_esc(s.get('session_id') or '?')}</code> {detail}</div>"
        )
    if not session_lines:
        session_lines = '<p class="muted">No consent-gated exploitation sessions for this site.</p>'

    hostile_lines = ""
    if hostile:
        hprof = hostile.get("profile", {})
        h_origins = hprof.get("origins", []) or []
        rows_html = "".join(
            f'<tr><td><code>{_esc(r.get("host"))}</code></td>'
            f'<td>{_esc(r.get("category") or "unknown")}</td>'
            f'<td>{_esc(", ".join(r.get("kinds", [])))}</td>'
            f'<td>{r.get("count")}</td>'
            f'<td>{"cleartext!" if r.get("cleartext") else "ok"}</td>'
            f'<td>{"missing" if r.get("sri_missing") else "ok"}</td>'
            f'<td>{r.get("risk_score")}</td></tr>'
            for r in h_origins[:25]
        ) or '<tr><td colspan="7" class="muted">No third-party origins detected.</td></tr>'
        clickbait = hprof.get("clickbait", {}) or {}
        sigs = (hprof.get("cloaks") or []) + (hprof.get("miners") or []) \
            + (hprof.get("push") or []) + (hprof.get("mechanics") or [])
        sig_html = "".join(f"<li>{_esc(s.get('signal'))}</li>" for s in sigs[:14])
        hostile_lines = (
            f'<div class="meta-grid">'
            f'<div><span class="k">Monetization score</span> {hprof.get("monetization_score", 0)}/100</div>'
            f'<div><span class="k">Clickbait index</span> {clickbait.get("score", 0)}/100 ({_esc(clickbait.get("grade", "low"))})</div>'
            f'<div><span class="k">Cloaks</span> {len(hprof.get("cloaks", []))}</div>'
            f'<div><span class="k">Miners</span> {len(hprof.get("miners", []))}</div>'
            f'<div><span class="k">Push-abuse</span> {len(hprof.get("push", []))}</div>'
            f'<div><span class="k">Active probes</span> '
            f'{"on (consent held)" if hostile.get("active_probes") else "off (read-only)"}</div>'
            '</div>'
            '<table><thead><tr><th>Host</th><th>Category</th><th>Kinds</th>'
            '<th>Count</th><th>TLS</th><th>SRI</th><th>Risk</th></tr></thead>'
            f'<tbody>{rows_html}</tbody></table>'
            + (f"<strong>Hostile-content signals</strong><ul>{sig_html}</ul>" if sig_html else "")
        )
    hostile_block = (
        f'<h2>Monetization &amp; Hostile Surface (Track G)</h2>\n{hostile_lines}'
        if hostile else ""
    )

    error_lines = "\n".join(f"<li>{_esc(e)}</li>" for e in errors)
    error_section = (
        f'<div class="errors"><h3>Scan errors ({len(errors)})</h3><ul>{error_lines}</ul></div>'
        if errors
        else ""
    )

    attack_options = "\n".join(
        f'<option value="{_esc(a)}">{_esc(a)}</option>' for a in attacks
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Titan Scan Dashboard — {_esc(target)}</title>
<style>
  :root {{
    --bg:#0f1115; --panel:#171a21; --panel2:#1d2129; --text:#e8eaed;
    --muted:#9aa0a6; --border:#2a2f3a; --accent:#8ab4f8;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif; padding:24px; }}
  header {{ margin-bottom:20px; }}
  h1 {{ font-size:22px; letter-spacing:.3px; }}
  h1 .muted {{ font-weight:400; font-size:14px; }}
  h2 {{ font-size:16px; margin:28px 0 12px; border-bottom:1px solid var(--border); padding-bottom:6px; }}
  .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:12px; }}
  .stat {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px 16px; }}
  .stat-num {{ font-size:28px; font-weight:700; }}
  .stat-label {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
  .controls {{ display:flex; gap:10px; flex-wrap:wrap; margin:16px 0; }}
  .controls input, .controls select {{ background:var(--panel2); color:var(--text); border:1px solid var(--border); border-radius:8px; padding:8px 12px; font-size:13px; }}
  .controls input {{ flex:1; min-width:200px; }}
  .sev-filters {{ display:flex; gap:6px; flex-wrap:wrap; }}
  .sev-btn {{ border:1px solid var(--border); background:var(--panel2); color:var(--muted); border-radius:20px; padding:4px 12px; cursor:pointer; font-size:12px; }}
  .sev-btn.active {{ border-color:var(--accent); color:var(--text); }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border-radius:10px; overflow:hidden; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--border); font-size:13px; vertical-align:top; }}
  th {{ background:var(--panel2); color:var(--muted); font-weight:600; cursor:pointer; user-select:none; white-space:nowrap; }}
  th:hover {{ color:var(--text); }}
  tr.row {{ cursor:pointer; }}
  tr.row:hover {{ background:var(--panel2); }}
  tr.detail-row > td {{ background:var(--panel2); padding:0; }}
  .detail {{ display:none; padding:14px 16px; }}
  .detail.open {{ display:block; }}
  .sev {{ display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; text-transform:uppercase; color:#0f1115; }}
  .sev-critical {{ background:#d93025; }} .sev-high {{ background:#e37400; }}
  .sev-medium {{ background:#f5a623; }} .sev-low {{ background:#6a9955; }}
  .sev-info {{ background:#3b82f6; }} .sev-unconfirmed {{ background:#9e9e9e; }}
  .tag {{ display:inline-block; background:var(--panel2); border:1px solid var(--border); border-radius:6px; padding:1px 7px; font-size:11px; color:var(--accent); }}
  .chip {{ display:inline-block; background:#2b1f4d; color:#c7b4ff; border-radius:6px; padding:1px 7px; font-size:11px; margin-right:4px; }}
  .verified {{ color:#34a853; font-weight:600; }}
  .unverified {{ color:var(--muted); }}
  code {{ background:#0b0d10; border:1px solid var(--border); border-radius:6px; padding:1px 5px; font-size:12px; word-break:break-all; }}
  pre {{ background:#0b0d10; border:1px solid var(--border); border-radius:8px; padding:10px; overflow-x:auto; font-size:12px; margin:8px 0; white-space:pre-wrap; word-break:break-word; }}
  .copy {{ background:var(--accent); color:#0f1115; border:0; border-radius:6px; padding:3px 10px; font-size:11px; font-weight:600; cursor:pointer; }}
  .copy:hover {{ opacity:.85; }}
  .muted {{ color:var(--muted); }}
  .meta-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:8px; margin:8px 0; }}
  .meta-grid div {{ background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:8px 12px; font-size:12px; }}
  .meta-grid .k {{ color:var(--muted); }}
  .chain {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:12px 16px; margin-bottom:8px; }}
  .chain summary {{ cursor:pointer; font-size:13px; }}
  .chain ul {{ margin:8px 0 0 18px; }}
  .chain li {{ margin:3px 0; font-size:12px; }}
  .session {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:10px 14px; margin-bottom:8px; font-size:12px; }}
  .errors {{ background:#3a1414; border:1px solid #6b2323; border-radius:10px; padding:12px 16px; margin-top:20px; }}
  .errors li {{ font-size:12px; margin:3px 0; }}
  .count-line {{ color:var(--muted); font-size:12px; margin-top:6px; }}
  .no-result {{ padding:20px; text-align:center; color:var(--muted); }}
  @media (max-width:700px) {{ body {{ padding:12px; }} table {{ font-size:12px; }} }}
</style>
</head>
<body>
<header>
  <h1>Titan Scan Dashboard — <span class="muted">{_esc(target)}</span></h1>
  <div class="meta-grid">
    <div><span class="k">Scanned</span> {_esc(_iso(meta.get('started_at')))}</div>
    <div><span class="k">Duration</span> {_esc(f"{duration:.1f}s" if duration is not None else 'n/a')}</div>
    <div><span class="k">Findings</span> {total}</div>
    <div><span class="k">Technologies</span> {_esc(", ".join(techs[:8]) or 'unknown')}</div>
  </div>
</header>

<div class="stats">{cards_html}</div>

<h2>Findings</h2>
<div class="controls">
  <input id="q" type="text" placeholder="Search URL, payload, param, tag, marker…" oninput="render()">
  <select id="attack-filter" onchange="render()">
    <option value="">All attack types</option>{attack_options}
  </select>
  <select id="evidence-filter" onchange="render()">
    <option value="">Any evidence grade</option>
    <option value="confirmed">confirmed</option>
    <option value="corroborated">corroborated</option>
    <option value="indicative">indicative</option>
  </select>
  <select id="tier-filter" onchange="render()">
    <option value="">Any tier</option>
    <option value="confirmed">confirmed</option>
    <option value="suspicious">suspicious</option>
  </select>
</div>
<div class="sev-filters" id="sev-filters"></div>
<div id="count-line" class="count-line"></div>
<table>
  <thead><tr>
    <th data-k="severity">Severity</th>
    <th data-k="attack_type">Attack type</th>
    <th data-k="url">Endpoint</th>
    <th data-k="confidence">Confidence</th>
    <th>Verified</th>
  </tr></thead>
  <tbody id="tbody"></tbody>
</table>
<div id="empty" class="no-result" style="display:none">No findings match the current filters.</div>

<h2>Attack chains</h2>
{chain_cards}

<h2>Exploitation sessions</h2>
{session_lines}
{hostile_block}
{error_section}

<p class="muted" style="margin-top:24px">Generated by Titan Scanner — self-contained report (open offline).</p>

<script>
const ROWS = {json_rows};
const CHAINS = {json_chains};
const SEV_ORDER = {json.dumps(_SEVERITY_ORDER, ensure_ascii=False)};
const SEV_COLORS = {json.dumps(_SEVERITY_COLORS)};
let sortKey = "severity";
let sortAsc = false;

function sevRank(s) {{ return SEV_ORDER.indexOf(s) >= 0 ? SEV_ORDER.indexOf(s) : SEV_ORDER.length; }}

function renderSevFilters() {{
  const wrap = document.getElementById("sev-filters");
  const active = new Set((document.querySelectorAll(".sev-btn.active") || []).map(b => b.dataset.s));
  wrap.innerHTML = SEV_ORDER.map(s =>
    `<button class="sev-btn" data-s="${{s}}" onclick="toggleSev(this)">${{s}} (${{ROWS.filter(r=>r.severity===s).length}})</button>`
  ).join("");
}}

function toggleSev(btn) {{
  btn.classList.toggle("active");
  render();
}}

function esc(s) {{
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}}

function copyText(id) {{
  const el = document.getElementById(id);
  const val = el ? el.textContent : "";
  if (navigator.clipboard) {{ navigator.clipboard.writeText(val); }}
  const btn = event.target;
  const old = btn.textContent;
  btn.textContent = "copied!";
  setTimeout(() => btn.textContent = old, 900);
}}

function render() {{
  const q = (document.getElementById("q").value || "").toLowerCase();
  const atk = document.getElementById("attack-filter").value;
  const ev = document.getElementById("evidence-filter").value;
  const tier = document.getElementById("tier-filter").value;
  const sevSet = new Set(
    Array.from(document.querySelectorAll(".sev-btn.active")).map(b => b.dataset.s)
  );
  let rows = ROWS.filter(r => {{
    if (atk && r.attack_type !== atk) return false;
    if (ev && r.evidence !== ev) return false;
    if (tier && (r.tier || "") !== tier) return false;
    if (sevSet.size && !sevSet.has(r.severity)) return false;
    if (q) {{
      const hay = (r.url + " " + r.payload + " " + r.param + " " + r.attack_type +
                   " " + r.tags.join(" ") + " " + r.diffs.join(" ")).toLowerCase();
      if (!hay.includes(q)) return false;
    }}
    return true;
  }});
  rows.sort((a,b) => {{
    let av = a[sortKey], bv = b[sortKey];
    if (sortKey === "severity") {{ av = sevRank(a.severity); bv = sevRank(b.severity); }}
    if (typeof av === "string") {{ av = av.toLowerCase(); bv = String(bv).toLowerCase(); }}
    const cmp = av > bv ? 1 : av < bv ? -1 : 0;
    return sortAsc ? cmp : -cmp;
  }});
  document.getElementById("count-line").textContent =
    `Showing ${{rows.length}} of ${{ROWS.length}} findings · sorted by ${{sortKey}} ${{sortAsc ? "asc" : "desc"}}`;
  const tbody = document.getElementById("tbody");
  tbody.innerHTML = rows.map((r,i) => {{
    const idx = ROWS.indexOf(r);
    const sev = SEV_COLORS[r.severity] || "#9e9e9e";
    const vCls = r.verified ? "verified" : "unverified";
    const vTxt = r.verified ? "verified" : "unverified";
    const urlShort = r.url.length > 110 ? r.url.slice(0,107) + "…" : r.url;
    const diffs = (r.diffs || []).map(d => `<li><code>${{esc(d)}}</code></li>`).join("");
    const tags = (r.tags || []).map(t => `<span class="tag">${{esc(t)}}</span>`).join(" ");
    const pocC = r.poc_curl ? `<div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px"><strong>curl PoC</strong><button class="copy" onclick="copyText('poc-${{idx}}')">copy</button></div><pre id="poc-${{idx}}">${{esc(r.poc_curl)}}</pre>` : "";
    const pocP = r.poc_python ? `<div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px"><strong>python PoC</strong><button class="copy" onclick="copyText('pocp-${{idx}}')">copy</button></div><pre id="pocp-${{idx}}">${{esc(r.poc_python)}}</pre>` : "";
    const payload = r.payload ? `<strong>Payload</strong><pre>${{esc(r.payload)}}</pre>` : "";
    return `<tr class="row" onclick="toggleDetail(this)">
      <td><span class="sev sev-${{r.severity}}">${{r.severity}}</span></td>
      <td>${{esc(r.attack_type)}}</td>
      <td><code>${{esc(r.method)}}</code> <code>${{esc(urlShort)}}</code> ${{r.param ? "<span class='tag'>param: " + esc(r.param) + "</span>" : ""}}</td>
      <td>${{(r.confidence*100).toFixed(0)}}%</td>
      <td class="${{vCls}}">${{vTxt}}</td>
    </tr>
    <tr class="detail-row"><td colspan="5"><div class="detail">
      <p><strong>Tier</strong> <span class="tag">${{r.tier || "none"}}</span>
         <strong>Evidence grade</strong> <span class="tag">${{esc(r.evidence)}}</span>
         · <strong>CVSS</strong> ${{r.cvss_score != null ? r.cvss_score : "n/a"}}
         · <strong>Location</strong> ${{esc(r.location)}} · <strong>HTTP</strong> ${{r.status != null ? r.status : "n/a"}}</p>
      ${{payload}}
      ${{diffs ? "<strong>Evidence markers</strong><ul>" + diffs + "</ul>" : ""}}
      ${{tags ? "<div style='margin-top:6px'>" + tags + "</div>" : ""}}
      ${{pocC}}
      ${{pocP}}
    </div></td></tr>`;
  }}).join("");
  document.getElementById("empty").style.display = rows.length ? "none" : "block";
}}

function toggleDetail(tr) {{
  const next = tr.nextElementSibling;
  const det = next ? next.querySelector(".detail") : null;
  if (det) det.classList.toggle("open");
}}

document.querySelectorAll("th").forEach(th => {{
  th.onclick = () => {{
    const k = th.dataset.k;
    if (k === sortKey) {{ sortAsc = !sortAsc; }} else {{ sortKey = k; sortAsc = false; }}
    render();
  }};
}});

renderSevFilters();
render();
</script>
</body>
</html>
"""
    out = (out_path or site_dir / "dashboard.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_doc, encoding="utf-8")
    return out
