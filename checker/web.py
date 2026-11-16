"""Localhost-only web page. Nothing is stored or sent anywhere except the optional domain-age lookup."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from .pipeline import analyze

MAX_BYTES = 1_000_000
PAGE = """<!doctype html><meta charset=utf-8><title>Scam checker</title>
<style>body{font:16px system-ui;max-width:760px;margin:2rem auto;padding:0 1rem}textarea{width:100%;height:12rem}
.high{color:#b00020}.medium{color:#b26a00}.low{color:#1b6e2d}li{margin:.6rem 0}code{background:#eee;padding:0 .2rem}</style>
<h1>Scam checker</h1><p>Paste a job or interview message. It stays on this computer.</p>
<input id=s placeholder="Sender email (optional)" size=36><br><br>
<textarea id=t placeholder="Paste the message here"></textarea><br>
<label><input type=checkbox id=l> Look up domain age (sends only the domain name)</label><br><br>
<button id=b>Check</button><div id=o></div>
<script>
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e};
document.getElementById('b').onclick=async()=>{
 const o=document.getElementById('o');o.replaceChildren();
 const r=await fetch('/api/check',{method:'POST',body:JSON.stringify({text:t.value,sender:s.value,lookup:l.checked})});
 if(!r.ok){o.append(el('p','',await r.text()));return}
 const d=await r.json();
 o.append(el('h2',d.result.level,'Risk estimate: '+d.result.level.toUpperCase()));
 o.append(el('p','',d.result.confidence));o.append(el('p','',d.result.disclaimer));
 const ul=el('ul');
 for(const f of d.findings){const li=el('li');li.append(el('b',f.risk,f.title+' '));
  li.append(el('span','',f.verified?'(verified, line '+f.line_ids.join(',')+')':'(unverified)'));
  li.append(el('div','', 'Quote: '+f.quote));li.append(el('div','',f.explanation));ul.append(li)}
 o.append(ul);
 if(d.advice.length){o.append(el('h3','','What to do'));const u=el('ul');d.advice.forEach(a=>u.append(el('li','',a)));o.append(u)}
};
</script>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            self._send(200, PAGE, "text/html; charset=utf-8")
        else:
            self._send(404, "not found")

    def do_POST(self):
        if self.path != "/api/check":
            return self._send(404, "not found")
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BYTES:
            return self._send(413, "Message too large (1 MB max).")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
            rep = analyze(str(body.get("text", "")), sender=str(body.get("sender", "")),
                          lookup=bool(body.get("lookup")))
        except (ValueError, TypeError):
            return self._send(400, "Bad request.")
        self._send(200, json.dumps(rep.to_dict()), "application/json")

    def log_message(self, *a):
        pass


def make_server(port: int = 8765) -> HTTPServer:
    return HTTPServer(("127.0.0.1", port), Handler)


def serve(port: int = 8765) -> None:
    srv = make_server(port)
    print(f"Open http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
