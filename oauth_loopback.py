#!/usr/bin/env python3
"""oauth_loopback — serverino su 127.0.0.1:8000 che cattura il redirect OAuth e
mostra il `code` in evidenza, con un bottone "Copia".

Gira sul Mac (dove c'è il browser). Lancialo PRIMA di premere "Connetti" nella
sezione Tools di clodia-web:

    python3 oauth_loopback.py            # porta 8000 (default, = redirect registrato)

Dopo il consenso Google redirige su http://127.0.0.1:8000/?code=… : invece
della pagina "impossibile connettersi" vedrai una pagina che evidenzia il
`code`. Copialo e incollalo nel popup di clodia-web. Resta in ascolto (Ctrl-C
per fermarlo); puoi rifare il consenso quante volte vuoi.

Nota: il `code` resta sulla TUA macchina (browser + questo server in locale);
non viene inviato da nessuna parte. Lo scambio code→token lo fa il gateway.
"""
import html
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

_PAGE = """<!doctype html><html lang="it"><head><meta charset="utf-8">
<title>Clodia · OAuth code</title><style>
 body{{margin:0;height:100vh;display:grid;place-items:center;background:#0f1115;
   color:#e6e8ee;font-family:-apple-system,Segoe UI,Roboto,sans-serif}}
 .box{{width:min(620px,92vw);background:#181b22;border:1px solid #2a2f3a;
   border-radius:14px;padding:28px}}
 h1{{font-size:17px;margin:0 0 4px}} p{{color:#8a91a0;font-size:13px;margin:6px 0 18px}}
 .code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:15px;
   background:#0f1115;border:1px solid #2a2f3a;border-radius:8px;padding:14px;
   word-break:break-all;line-height:1.5;color:#5cb88a}}
 .row{{display:flex;gap:10px;margin-top:14px;align-items:center}}
 button{{background:#ff6b3d;color:#fff;border:0;border-radius:8px;padding:10px 16px;
   font-weight:700;cursor:pointer;font-size:13px}}
 button:active{{transform:translateY(1px)}} .ok{{color:#5cb88a;font-size:13px}}
 .err{{color:#e85d75}} .small{{color:#5a6270;font-size:11px;margin-top:16px}}
</style></head><body><div class="box">{body}</div>
<script>
function copyCode(){{const c=document.getElementById('c').textContent.trim();
 navigator.clipboard.writeText(c).then(()=>{{document.getElementById('s').textContent='✓ copiato negli appunti';}});}}
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silenzia il log di default (niente URL col code a schermo)
        pass

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        code = (q.get("code") or [""])[0]
        err = (q.get("error") or [""])[0]
        state = (q.get("state") or [""])[0]
        if code:
            body = (
                "<h1>✅ Codice OAuth ricevuto</h1>"
                "<p>Copialo e incollalo nel popup di <b>Clodia Web → Tools → Gmail</b>.</p>"
                f'<div class="code" id="c">{html.escape(code)}</div>'
                '<div class="row"><button onclick="copyCode()">Copia il code</button>'
                '<span class="ok" id="s"></span></div>'
                + (f'<div class="small">state: {html.escape(state)}</div>' if state else "")
            )
            print("✓ code ricevuto (mostrato nel browser).")
        elif err:
            body = (f'<h1 class="err">Errore OAuth</h1><p>{html.escape(err)}</p>'
                    "<p>Riprova il Connetti da clodia-web.</p>")
        else:
            body = ("<h1>In ascolto…</h1><p>Premi <b>Connetti</b> in clodia-web e "
                    "completa il consenso Google: il code apparirà qui.</p>")
        out = _PAGE.format(body=body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def main() -> int:
    try:
        srv = HTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as e:
        print(f"Impossibile aprire 127.0.0.1:{PORT} ({e}). "
              f"Forse è già in uso — chiudi l'altro processo o passa un'altra porta.",
              file=sys.stderr)
        return 1
    print(f"🟢 In ascolto su http://127.0.0.1:{PORT} — lascia aperto, poi premi "
          f"'Connetti' in clodia-web. Ctrl-C per fermare.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nfermato.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
