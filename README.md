# clodia-tools

Gateway **MCP HTTP** della colonia Clodia: espone agli agenti un insieme
**controllato** di tool, sostituendo l'accesso diretto a filesystem/shell/credenziali.

È il **reference monitor** della colonia: i veti e le regole vivono qui, in un
processo (e container, e repo) **separato dal runtime degli agenti**. Un agente
non possiede credenziali né CLI: l'unico modo di agire sul mondo è chiedere al
gateway, che **autentica (PKI ckt1) → applica la whitelist per-agente → esegue o nega**.

## Architettura

```
agent (clodia-logic / clodia-web)  ──  Authorization: Bearer ckt1.<token firmato>  ──▶  clodia-tools :7849
                                                                                        │ verify_session_token (cert PUBBLICI)
                                                                                        │ whitelist[agent].allowed_tools
                                                                                        └ exec adapter (trello/email/fs/agent)
```

- **Auth**: token di sessione `ckt1` firmato dalla chiave privata dell'agente
  (coniato lato clodia-logic, mai su disco). Qui si verifica **solo** coi
  certificati **pubblici** (`pki_verify.py`): firma del token → cert validato
  contro la CA → revoca → audience → scadenza. L'identità dell'agente viene dal
  token verificato (`payload.agent`), non da header spoofabili.
- **Whitelist**: `config.yaml`, per identità PKI. `call_tool` nega ciò che non è
  in `allowed_tools`.

## Tool esposti

`fs.list_dir`, `trello.*` (16), `email.send`, `agent.spawn`.

Gli adapter `trello`/`email` sono **vendorizzati** in `vendor/` (`trello_client.py`,
`email_client.py` — quest'ultimo è puro stdlib): il repo è autosufficiente, nessuna
dipendenza dal tree di clodia-logic.

## Avvio

```bash
pip install -r requirements.txt
python3 cli.py --http --port 7849      # gateway HTTP
python3 cli.py --version
```

Env runtime: `CLODIA_CA_CRT`, `CLODIA_PKI_CERTS`, `CLODIA_PKI_REVOKED`,
`CLODIA_WORKSPACE_ROOT`. I secret sono **montati**, mai dentro l'immagine.

## Genesi

Scorporato da `r-clodia/clodia-logic` (`tools/system/mcp-tools-server`) il 2026-06-14
con storia preservata, per separare il piano di enforcement dal runtime degli
agenti (vedi roadmap migrazione tool nel topic `clodia-agency`).

## Licenza

Copyright (C) 2026 Davide Carboni.

GNU AGPL v3 — con opzione di licenza commerciale: vedi [LICENSING.md](LICENSING.md).
Le versioni fino al tag `apache2-final` restano Apache 2.0.
