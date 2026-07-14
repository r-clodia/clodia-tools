# MCP-TOOLS-SERVER POLICY

**Versione**: 0.11.0
**Documento Normativo**

Server MCP (Model Context Protocol) che espone agli agenti della famiglia Clodia un insieme controllato di tool, sostituendo l'accesso diretto al filesystem/shell. È il gateway di sicurezza per agenti specializzati (Klaus, Adele, ecc.) che non sono autorizzati a usare strumenti built-in arbitrari.

---

## 1. Scopo

- Esporre i tool come API MCP con **whitelist per agent-name** (definita in `config.yaml`).
- Eseguire **guard a livello server** su path, comandi shell, operazioni di pubblicazione.
- Disaccoppiare gli agenti dall'implementazione concreta dei tool (cambio interno = nessun cambio per gli agenti).
- Logging centralizzato di ogni invocazione tool per audit.

L'agente identifica se stesso al server via env var `MCP_AGENT_NAME` impostata dal lancio.

---

## 2. Whitelist per agente

Ogni agente dichiarato in `config.yaml` ha:
- `allowed_paths`: lista di path (assoluti o relativi a workspace root) entro cui può leggere/scrivere
- `allowed_shell_cmds`: whitelist di comandi shell che può invocare via `shell.exec`
- `denied_shell_patterns`: pattern blacklist (es. `git push origin main`, `netlify deploy`)
- `allowed_tools`: lista esplicita dei nomi tool MCP che vede (sottoinsieme di quelli registrati)

Se l'agente chiamante non è dichiarato in `config.yaml`, il server **rifiuta tutte le chiamate**.

---

## 3. Tool esposti

**Filesystem**:
- `fs.list_dir(path)` — elenca file in una directory, **dopo verifica whitelist path**
- (in arrivo: `fs.read`, `fs.write`, `fs.edit`, `shell.exec`, `web.render_html`, `web.screenshot`)

**Trello** (wrapper di `tools/system/trello/trello_client.py`, credenziali in `secrets/`):
- `trello.list_boards`, `trello.show_board`, `trello.list_lists`, `trello.list_cards`, `trello.show_card`, `trello.list_comments`, `trello.resolve_member` — sola lettura
- `trello.move_card`, `trello.comment_card`, `trello.update_card`, `trello.create_card`, `trello.assign_member`, `trello.unassign_member` — scrittura
- `trello.archive_card`, `trello.unarchive_card` — archiviazione reversibile (NON è eliminazione, vedi sez. 5)

`trello.assign_member` / `trello.unassign_member` accettano in `member` un member id (24-hex), un alias breve della famiglia Clodia (es. `ada`, `clodia`, `klaus` → username `demo<alias>` per convenzione), o un username Trello arbitrario.

**Email** (wrapper sub-process di `vendor/email_client.py`, OAuth/IMAP in `secrets/`):
- `email.send(to, subject, body, account?, cc?, attachments?)` — invio plain text con allegati locali opzionali (`attachments` = lista di path file). Account: `demo` (default) o `studio`.
- `email.folders(account?)` — elenco cartelle IMAP.
- `email.list(account?, folder?, limit?)` — elenco messaggi di una cartella (default INBOX).
- `email.read(email_id, account?, folder?)` — lettura di un singolo messaggio.
- `email.search(query, account?, folder?, limit?)` — ricerca via query IMAP (es. `FROM "x@y.it"`).
- `email.reply(email_id, body, account?, folder?, cc?, attachments?)` — risposta mantenendo il threading (plain text con allegati locali opzionali).
- Le credenziali (refresh token OAuth/IMAP) non transitano mai dal motore di inferenza: il CLI le risolve internamente da `secrets/`. `download_attachments` non è ancora esposto (richiede la decisione sull'area di retention dei file scaricati).

**Agent control** (parla con l'agent-server REST locale a `127.0.0.1:7842`):
- `agent.spawn(agent_type, task, wait_for_reply?)` — crea una nuova chat dell'agent-type indicato e le consegna `task` come primo messaggio. Default fire-and-forget (`wait_for_reply=false`): il caller non aspetta la risposta dell'agente spawnato. Usato dal `looper` per dispacciare task ad altri agent senza bloccare il proprio ciclo.

---

## 4. Guard fondamentali

- **Path traversal**: ogni path viene normalizzato (`Path.resolve()`) e verificato di essere dentro almeno uno degli `allowed_paths` dell'agente
- **Shell whitelist**: `shell.exec` parsifica il comando (no shell injection), verifica il binario contro `allowed_shell_cmds`, e l'intero comando contro `denied_shell_patterns`
- **Denial by default**: chiamata a tool non in `allowed_tools` dell'agente → errore esplicito

---

## 5. Operazioni vietate (assolute)

- Esporre `secrets/` a qualsiasi agente
- Permettere a un agente non `clodia` di eseguire push verso branch protetti, deploy, npm publish, ecc.
- Eseguire codice arbitrario fuori dalle whitelist

---

## 6. Versionamento
Versione corrente: **0.14.0** — **`topic.attach` (allegati di canale path-based)**: nuovo tool MCP che carica un binario dallo scratch dell'agente in `files/` e pubblica il messaggio di canale con l'allegato, in un colpo solo — il gateway legge i byte dal path locale (niente base64 come parametro, che si troncava sui file grandi tipo i .docx). `src`=path scratch, `filename` opzionale (default basename), `text` opzionale. Scoped come gli altri verbi topic (richiede membership).

**0.13.0** — **Backend UI di acquisizione** (`server/tools_api.py`): accanto a `/mcp`, il gateway HTTP espone le route che la webui usa per acquisire le credenziali OAuth dei tool: `GET /tools` (stato connettori), `GET /tools/gmail/auth` (URL di consenso + state), `POST /tools/gmail/connect` (exchange code→refresh token → deposito nella vault). Auth bearer separata dal ckt1 degli agenti (`CLODIA_TOOLS_UI_TOKEN`; aperta se non impostata, assunzione rete interna). Il **client OAuth dell'app** è una credenziale d'infrastruttura `app_google_oauth` (deposita con `seed_app_credential.py`), letta solo da `vault.read_internal` — **mai** fetch-abile dagli agenti. Helper OAuth condivisi in `server/google_oauth.py` (anche `connect_email.py` li riusa). Lo scambio è server-side: client_secret e refresh token non raggiungono mai un modello.

**0.12.0** — **Vault delle credenziali** (`server/vault.py`): le credenziali dei tool escono da `secrets/` e vivono in un volume separato `~/.clodia` (`CLODIA_VAULT_DIR`) montato **solo** dal gateway. Il gateway è il custode: `get_secret(agent, credential)` restituisce il valore solo se l'agente (identità ckt1 verificata) ha grant `fetch` in `vault-policy.yaml`; ogni accesso è auditato in `~/.clodia/audit.log`. Il tool email instrada via vault quando l'account è "vault-backed" (`gmail_<account>` presente): materializza un `CLODIA_SECRETS_DIR` effimero, esegue il CLI, lo rimuove; altrimenti fallback legacy `secrets/`. `connect_email.py` deposita la credenziale OAuth nella vault. Distinta dal keystore-colonia (clodia-logic, broker git_push + lease execution-scoped), invariato.

Storico:
- **0.11.0** — aggiunti i tool email di lettura/risposta `email.folders`, `email.list`, `email.read`, `email.search`, `email.reply` (wrapper del CLI vendorizzato, XOAUTH2 OAuth/IMAP; credenziali mai esposte al motore). Concessi a `clodia` (super-agent) insieme a `email.send` e `agent.spawn`. `download_attachments` ancora non esposto (in attesa di decisione sull'area di retention dei file).
- **0.6.0** — aggiunti `trello.list_comments`, `trello.archive_card`, `trello.unarchive_card`, `email.send`, `agent.spawn`. Nuovo agent-type `looper` con whitelist dedicata (trello minimal + email.send + agent.spawn). `agent.spawn` di default è fire-and-forget per non bloccare il chiamante (es. il looper) in attesa della risposta dello spawned agent.
- **0.4.0** — `trello.comment_card` antepone automaticamente al testo un badge di attribuzione `**🤖 <Agent>**: ` (Opzione 2 della card BUG: commenti sulla card — https://trello.com/c/p0v7jDl8). Tutti i commenti su Trello restano attribuiti al titolare del token (oggi: owner), ma il badge esplicita l'agent autore. L'helper è idempotente: se il testo inizia già con `**🤖 ` non viene rietichettato.
- **0.3.0** — aggiunti `trello.assign_member` e `trello.unassign_member` (con risoluzione member tramite convenzione `demo<alias>` o username/id diretti). Clodia e Ada hanno entrambe accesso al set completo dei tool Trello.
- **0.2.0** — 9 tool Trello + `trello.create_card`.
