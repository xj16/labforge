"""labforge SIEM web UI — read-only, dependency-free, http.server based.

Endpoints
---------
  GET /                       host list + recent-events dashboard + alerts
  GET /host/<name>            last N lines for one host
  GET /search?q=<term>        grep across every host's logs
  GET /alerts                 the detection findings, rendered
  GET /api/hosts              JSON list of hosts + line counts
  GET /api/tail/<name>?n=200  JSON tail of a host's log
  GET /api/detections         JSON detection findings
  GET /healthz                liveness probe

Config comes from the environment (so the same file runs in CI, on the SIEM
box, and behind the Ansible template):

  LABFORGE_LOG_ROOT     directory the collector writes into
  LABFORGE_WEB_PORT     port to bind (default 8000)
  LABFORGE_SYSLOG_PORT  collector port, shown in the header (default 5514)
"""
from __future__ import annotations

import html
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .detections import SAVED_SEARCHES
from .store import DEFAULT_TAIL, LogStore

PAGE_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { font: 14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
       background:#0b1622; color:#d7e2ef; margin:0; }
header { background:#0f2f4a; padding:16px 24px; border-bottom:2px solid #1f7a8c; }
header h1 { margin:0; font-size:18px; color:#fff; }
header .sub { color:#8fb3c9; font-size:12px; }
main { padding:24px; max-width:1100px; margin:0 auto; }
a { color:#4fc3d7; text-decoration:none; } a:hover { text-decoration:underline; }
.card { background:#12212f; border:1px solid #1d3446; border-radius:8px;
        padding:16px; margin-bottom:16px; }
.card h2 { margin-top:0; font-size:15px; }
.host-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr));
             gap:12px; }
.host { display:block; background:#16293a; border:1px solid #244055;
        border-radius:8px; padding:14px; }
.host b { color:#fff; } .host span { color:#7fa8c2; font-size:12px; }
pre { background:#08111b; border:1px solid #1d3446; border-radius:6px;
      padding:12px; overflow:auto; white-space:pre-wrap; word-break:break-word;
      max-height:70vh; font:12px/1.5 ui-monospace,Menlo,Consolas,monospace; }
form { margin:0 0 12px; } input[type=text] { width:60%; padding:8px 10px;
      background:#08111b; border:1px solid #244055; border-radius:6px; color:#d7e2ef; }
button { padding:8px 14px; background:#1f7a8c; border:0; border-radius:6px;
         color:#fff; cursor:pointer; }
.hit b { color:#ffcf5c; }
.saved { display:flex; flex-wrap:wrap; gap:8px; margin:4px 0 4px; }
.saved a { background:#16293a; border:1px solid #244055; border-radius:999px;
           padding:4px 12px; font-size:12px; color:#9fd6e2; }
.alerts { display:flex; flex-direction:column; gap:10px; }
.alert { border-left:4px solid #888; background:#14212e; border-radius:6px;
         padding:10px 14px; }
.alert.critical { border-left-color:#ff4d6d; }
.alert.high { border-left-color:#ff8a3d; }
.alert.medium { border-left-color:#ffcf5c; }
.alert.low { border-left-color:#4fc3d7; }
.alert .t { font-weight:600; color:#fff; }
.alert .sev { font-size:11px; text-transform:uppercase; letter-spacing:.05em;
              padding:1px 8px; border-radius:999px; margin-left:8px; }
.alert.critical .sev { background:#ff4d6d; color:#1a0008; }
.alert.high .sev { background:#ff8a3d; color:#1a0d00; }
.alert.medium .sev { background:#ffcf5c; color:#1a1600; }
.alert.low .sev { background:#4fc3d7; color:#001416; }
.alert .meta { color:#8fb3c9; font-size:12px; margin-top:2px; }
.alert code { color:#c9e6ef; }
.banner { background:#2a0d14; border:1px solid #ff4d6d; color:#ffd7de;
          border-radius:8px; padding:12px 16px; margin-bottom:16px; }
.banner b { color:#ff9db0; }
.ok { color:#5fd68a; }
"""


def render_layout(title: str, body: str, syslog_port: str, log_root: str) -> str:
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'>
<title>{html.escape(title)} — labforge SIEM</title><style>{PAGE_CSS}</style></head>
<body><header><h1>labforge SIEM &mdash; detection lab</h1>
<div class=sub>read-only &middot; collector on {html.escape(str(syslog_port))} (tcp+udp) &middot; {html.escape(log_root)}</div>
</header><main>{body}</main></body></html>"""


def _render_alerts(dets) -> str:
    if not dets:
        return "<div class=card><h2>Detections</h2><p class=ok>No attacks detected in the current logs.</p></div>"
    items = []
    for d in dets:
        ev = html.escape(d.evidence[0]) if d.evidence else ""
        items.append(
            f"<div class='alert {html.escape(d.severity)}'>"
            f"<span class=t>{html.escape(d.title)}</span>"
            f"<span class=sev>{html.escape(d.severity)}</span>"
            f"<div class=meta>{html.escape(d.summary)} "
            f"&middot; {html.escape(d.technique)} &middot; host "
            f"<a href='/host/{html.escape(d.host)}'>{html.escape(d.host)}</a>"
            + (f" &middot; source {html.escape(d.source)}" if d.source else "")
            + "</div>"
            + (f"<div class=meta><code>{ev}</code></div>" if ev else "")
            + "</div>"
        )
    return f"<div class=card><h2>Detections ({len(dets)})</h2><div class=alerts>{''.join(items)}</div></div>"


def _saved_searches_html() -> str:
    chips = "".join(
        f"<a href='/search?q={html.escape(s['q'])}'>{html.escape(s['label'])}</a>"
        for s in SAVED_SEARCHES
    )
    return f"<div class=saved>{chips}</div>"


class Handler(BaseHTTPRequestHandler):
    server_version = "labforge-logviewer/1.1"
    store: LogStore = LogStore(".")
    syslog_port: str = "5514"

    # -- render helpers (instance-free so tests can call them via the store) --

    def _layout(self, title: str, body: str) -> str:
        return render_layout(title, body, self.syslog_port, self.store.log_root)

    def render_index(self) -> str:
        hosts = self.store.list_hosts()
        dets = self.store.detections()
        banner = ""
        crit = [d for d in dets if d.severity in ("critical", "high")]
        if crit:
            top = crit[0]
            banner = (
                f"<div class=banner><b>&#9888; {len(crit)} active alert(s).</b> "
                f"Top: {html.escape(top.title)} — {html.escape(top.summary)} "
                f"<a href='/alerts'>view all &rarr;</a></div>"
            )
        if not hosts:
            cards = "<div class=card>No logs yet. Once clients forward syslog they appear here.</div>"
        else:
            items = "".join(
                f"<a class=host href='/host/{html.escape(h['name'])}'>"
                f"<b>{html.escape(h['name'])}</b><br>"
                f"<span>{h['lines']:,} lines &middot; {h['bytes'] // 1024} KiB</span></a>"
                for h in hosts
            )
            cards = (
                f"<div class=card><h2>Hosts ({len(hosts)})</h2>"
                f"<div class=host-grid>{items}</div></div>"
            )
        search = (
            "<form action='/search'><input type=text name=q "
            "placeholder='search all hosts, e.g. Failed password'> "
            "<button>Search</button></form>" + _saved_searches_html()
        )
        return self._layout("Dashboard", banner + search + cards + _render_alerts(dets))

    def render_host(self, name: str) -> Optional[str]:
        lines = self.store.tail_host(name, DEFAULT_TAIL)
        if lines is None:
            return None
        pre = html.escape("\n".join(lines)) or "(empty)"
        back = "<a href='/'>&larr; all hosts</a>"
        return self._layout(
            name,
            f"{back}<div class=card><h2>{html.escape(name)} &mdash; last {len(lines)} lines</h2>"
            f"<pre>{pre}</pre></div>",
        )

    def render_search(self, term: str) -> str:
        hits = self.store.search_all(term) if term else []
        rows = "".join(
            f"<div class=hit><a href='/host/{html.escape(h)}'>{html.escape(h)}</a>: "
            f"{html.escape(line)}</div>"
            for h, line in hits
        )
        body = (
            "<a href='/'>&larr; back</a>"
            f"<form action='/search'><input type=text name=q value='{html.escape(term)}'>"
            " <button>Search</button></form>" + _saved_searches_html()
            + f"<div class=card><h2>{len(hits)} matches for &ldquo;{html.escape(term)}&rdquo;</h2>"
            f"<pre>{rows or '(no matches)'}</pre></div>"
        )
        return self._layout(f"search: {term}", body)

    def render_alerts(self) -> str:
        dets = self.store.detections()
        return self._layout("Alerts", "<a href='/'>&larr; back</a>" + _render_alerts(dets))

    # -- HTTP plumbing -------------------------------------------------------

    def _send(self, body: str, status: int = 200, ctype: str = "text/html; charset=utf-8"):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _json(self, obj, status: int = 200):
        self._send(json.dumps(obj), status, "application/json")

    def do_GET(self):  # noqa: N802 (stdlib naming)
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            return self._send(self.render_index())
        if path == "/healthz":
            return self._json({"status": "ok", "hosts": len(self.store.list_hosts())})
        if path == "/alerts":
            return self._send(self.render_alerts())
        if path == "/api/hosts":
            return self._json(self.store.list_hosts())
        if path == "/api/detections":
            return self._json([d.__dict__ for d in self.store.detections()])
        if path.startswith("/api/tail/"):
            name = path[len("/api/tail/"):]
            try:
                n = int(query.get("n", [DEFAULT_TAIL])[0])
            except ValueError:
                n = DEFAULT_TAIL
            lines = self.store.tail_host(name, n)
            if lines is None:
                return self._json({"error": "unknown host"}, 404)
            return self._json({"host": name, "lines": lines})
        if path.startswith("/host/"):
            page = self.render_host(path[len("/host/"):])
            if page is None:
                return self._send(self._layout("404", "<div class=card>Unknown host.</div>"), 404)
            return self._send(page)
        if path == "/search":
            return self._send(self.render_search(query.get("q", [""])[0]))
        return self._send(self._layout("404", "<div class=card>Not found.</div>"), 404)

    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def log_message(self, *_args):  # silence default stderr access log
        pass


def make_handler(log_root: str, syslog_port: str = "5514"):
    """Build a Handler subclass bound to a specific log root (used by tests)."""
    return type("BoundHandler", (Handler,), {
        "store": LogStore(log_root),
        "syslog_port": str(syslog_port),
    })


def serve(log_root: Optional[str] = None, port: Optional[int] = None,
          syslog_port: Optional[str] = None):
    """Start the blocking web server (used by the run_logviewer entrypoint)."""
    log_root = log_root or os.environ.get("LABFORGE_LOG_ROOT", "/opt/labforge-siem/logs")
    port = port or int(os.environ.get("LABFORGE_WEB_PORT", "8000"))
    syslog_port = syslog_port or os.environ.get("LABFORGE_SYSLOG_PORT", "5514")
    os.makedirs(log_root, exist_ok=True)
    handler = make_handler(log_root, syslog_port)
    server = ThreadingHTTPServer(("0.0.0.0", port), handler)
    print(f"labforge SIEM viewer serving {log_root} on :{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
