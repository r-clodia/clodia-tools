"""MCP stdio server entry point — Clodia tools gateway."""
import asyncio
import json
import sys

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from . import __version__
from . import proxy
from .tools import agent, email, fs, runtime
from .whitelist import agent_config, agent_name

import os as _os
from .topics.service import TopicService, TopicError
from .topics.local_fs import LocalFsStorage
from .topics.storage import VersionConflict

app = Server("clodia-tools")

# Topic System v2 (P1): storage local-fs in un'area dedicata del datadir del
# gateway (NUOVA e separata dai topic git esistenti). Enforcement tiering OFF in
# P1 (arriva in P3). Reference monitor: gli agenti toccano i topic solo da qui.
# Default in un'area montata SOLO dal gateway (la dir del vault: l'agent-server
# NON la monta) → gli agenti non possono raggiungere i file dei topic by-passando
# i verbi. Reference monitor: l'unica via ai topic è il gateway. Override via
# CLODIA_TOPICS_ROOT.
_TOPICS_ROOT = _os.environ.get("CLODIA_TOPICS_ROOT", "/datadir/clodia-vault/topics-store")
_topic_svc: TopicService | None = None


def _topics() -> TopicService:
    global _topic_svc
    if _topic_svc is None:
        _topic_svc = TopicService(LocalFsStorage(_TOPICS_ROOT))
    return _topic_svc




_EMAIL_TOOLS: list[Tool] = [
    Tool(
        name="email.send",
        description=(
            "Send an email via one of the configured accounts (demo, studio). "
            "Plain-text body, optional CC. No attachments in this version."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "recipient email address"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "account": {
                    "type": "string",
                    "description": "sender account (default 'demo')",
                },
                "cc": {"type": "string", "description": "optional CC address"},
            },
            "required": ["to", "subject", "body"],
        },
    ),
    Tool(
        name="email.folders",
        description="List the IMAP folders of a configured account (demo, studio).",
        inputSchema={
            "type": "object",
            "properties": {
                "account": {"type": "string",
                            "description": "account to inspect (default 'demo')"},
            },
        },
    ),
    Tool(
        name="email.list",
        description="List messages of a folder (default INBOX) for a configured account.",
        inputSchema={
            "type": "object",
            "properties": {
                "account": {"type": "string"},
                "folder": {"type": "string", "description": "IMAP folder, default INBOX"},
                "limit": {"type": "integer", "description": "max messages, default 10"},
            },
        },
    ),
    Tool(
        name="email.read",
        description="Read a single message by its IMAP id from a folder (default INBOX).",
        inputSchema={
            "type": "object",
            "properties": {
                "email_id": {"type": "string", "description": "IMAP message id"},
                "account": {"type": "string"},
                "folder": {"type": "string", "description": "IMAP folder, default INBOX"},
            },
            "required": ["email_id"],
        },
    ),
    Tool(
        name="email.get_attachment",
        description=("Contenuto di un allegato di un messaggio, in base64 (per nome file). "
                     "Componibile con topic.write_file(encoding='base64') o gli allegati profilo. "
                     "Usa email.read per scoprire i nomi degli allegati."),
        inputSchema={
            "type": "object",
            "properties": {
                "email_id": {"type": "string", "description": "IMAP message id"},
                "filename": {"type": "string", "description": "nome esatto dell'allegato (da email.read)"},
                "account": {"type": "string"},
                "folder": {"type": "string", "description": "IMAP folder, default INBOX"},
            },
            "required": ["email_id", "filename"],
        },
    ),
    Tool(
        name="email.search",
        description="Search messages with an IMAP query (e.g. FROM \"x@y.it\") in a folder.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "IMAP search query"},
                "account": {"type": "string"},
                "folder": {"type": "string", "description": "IMAP folder, default INBOX"},
                "limit": {"type": "integer", "description": "max results, default 20"},
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="email.reply",
        description="Reply to a message keeping the thread (plain-text body, optional CC).",
        inputSchema={
            "type": "object",
            "properties": {
                "email_id": {"type": "string", "description": "id of the message to reply to"},
                "body": {"type": "string"},
                "account": {"type": "string"},
                "folder": {"type": "string", "description": "IMAP folder, default INBOX"},
                "cc": {"type": "string", "description": "optional CC address"},
            },
            "required": ["email_id", "body"],
        },
    ),
]


_AGENT_TOOLS: list[Tool] = [
    Tool(
        name="agent.spawn",
        description=(
            "Spawn a new chat of the given agent-type via the local agent-server "
            "and hand it a first user message. Returns chat_id, kind, and (if "
            "wait_for_reply=true) the agent's reply. Used by 'looper' to dispatch "
            "tasks to other agents (e.g. ada)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "agent_type": {
                    "type": "string",
                    "description": "agent kind to spawn: 'ada', 'clodia', or 'looper'",
                    "enum": ["ada", "clodia", "looper"],
                },
                "task": {
                    "type": "string",
                    "description": "first user message to deliver to the spawned agent",
                },
                "wait_for_reply": {
                    "type": "boolean",
                    "description": "if true wait for the agent's reply before returning; default false (fire-and-forget): the message is queued and the spawned agent processes it in background",
                },
            },
            "required": ["agent_type", "task"],
        },
    ),
]


_FS_TOOLS: list[Tool] = [
    Tool(
        name="fs.list_dir",
        description=(
            "List the entries of a directory inside the agent's workspace whitelist. "
            "Returns name, kind (file/dir), and size for each child."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path relative to workspace root or absolute, must be in allowed_paths.",
                }
            },
            "required": ["path"],
        },
    ),
]


_TOPIC_TOOLS: list[Tool] = [
    Tool(
        name="topic.new",
        description=("Crea (idempotente) un topic. tier = SEAL-0..4 "
                     "(Public/Internal/Confidential/Restricted/Sovereign; default SEAL-0). "
                     "meta opzionale: title, type, tags, people, entity, deadline, contact_agent."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"],
                     "description": "classe/sovranità del topic — scala SEAL (default SEAL-0 Public)"},
            "name": {"type": "string", "description": "slug a-z0-9_-"},
            "meta": {"type": "object"},
        }, "required": ["name"]},
    ),
    Tool(
        name="topic.open",
        description=("Apre un topic (read-only): ritorna meta, summary (col "
                     "summary_version per l'optimistic lock), tldr, lista minute."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
        }, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.save_summary",
        description=("Riscrive il summary in optimistic lock. Passa base_version "
                     "ottenuto da topic.open. Su conflitto NON sovrascrive: rilegge ed escala."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "text": {"type": "string", "description": "prima riga = TLDR; sezione '## Prossimi passi'"},
            "base_version": {"type": ["string", "null"]},
        }, "required": ["tier", "name", "text"]},
    ),
    Tool(
        name="topic.add_minute",
        description="Aggiunge una minuta (file append-only datato). Niente contesa concorrente.",
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "text": {"type": "string"},
        }, "required": ["tier", "name", "text"]},
    ),
    Tool(
        name="topic.archive",
        description="Imposta status=archived nel meta (non sposta su storage inferiore).",
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
        }, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.list",
        description="Elenca i topic (riga sintetica). Gli archived sono nascosti salvo include_archived.",
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "include_archived": {"type": "boolean"},
        }},
    ),
    Tool(
        name="topic.search",
        description="Ricerca nei topic (P1: lessicale su meta/summary/minute).",
        inputSchema={"type": "object", "properties": {
            "query": {"type": "string"},
            "mode": {"type": "string", "enum": ["lexical", "semantic"]},
        }, "required": ["query"]},
    ),
    Tool(
        name="topic.files",
        description=("Elenca file e cartelle del topic/canale a partire da `subpath` "
                     "(relativo alla ROOT del topic; vuoto = root). Ritorna name, path, "
                     "kind (file|dir), size, mtime. I file caricati stanno di norma in "
                     "'files/'. Per vedere il CONTENUTO di una sottocartella passa il suo "
                     "path come subpath (es. subpath='files/expenses'). Usa il `path` "
                     "ritornato con topic.read_file."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "subpath": {"type": "string", "description": "cartella da elencare, relativa alla root del topic (es. 'files' o 'files/expenses'); vuoto = root"},
        }, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.read_file",
        description=("Legge il contenuto di un file del topic/canale. path relativo "
                     "(es. 'files/report.md'). I file di testo tornano come testo; "
                     "i binari (PDF/immagini) tornano come base64 con encoding='base64'."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "path": {"type": "string", "description": "path relativo al topic, es. files/foo.md"},
        }, "required": ["tier", "name", "path"]},
    ),
    Tool(
        name="topic.write_file",
        description=("Carica/sovrascrive un file nella cartella files/ del topic/canale "
                     "(es. un deliverable, o i file estratti da uno zip). filename può "
                     "includere sottocartelle (es. 'archivio/foto/1.jpg'); le dir padre "
                     "vengono create. content = testo; per i binari (xlsx/pdf/docx/"
                     "zip/immagini) passa il base64 COMPLETO del file e encoding='base64' "
                     "(i file con estensione binaria sono comunque decodificati da base64, "
                     "mai scritti come testo). Usa QUESTO, non hosting esterni."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "filename": {"type": "string", "description": "nome file semplice, finisce in files/"},
            "content": {"type": "string", "description": "contenuto (testo o base64)"},
            "encoding": {"type": "string", "enum": ["text", "base64"], "description": "default text"},
        }, "required": ["tier", "name", "filename", "content"]},
    ),
    Tool(
        name="topic.fetch",
        description=("Scarica una COPIA di un file del topic nel TUO scratch (path "
                     "locale), per trattarlo con le skill standard (xlsx/pdf/docx/…). "
                     "USA QUESTO per i BINARI invece di topic.read_file (che passa "
                     "base64 nel contesto e si tronca sui file grandi). `dest` = path "
                     "assoluto sotto il tuo scratch. Flusso: topic.fetch → skill "
                     "standard sul file locale → topic.put."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "path": {"type": "string", "description": "path nel topic, es. files/expenses/x.xlsx"},
            "dest": {"type": "string", "description": "path assoluto di destinazione nel tuo scratch"},
        }, "required": ["tier", "name", "path", "dest"]},
    ),
    Tool(
        name="topic.put",
        description=("Carica nel topic (files/) un file preparato nel TUO scratch. USA "
                     "QUESTO per i BINARI invece di topic.write_file: il gateway legge i "
                     "byte dal path locale, niente base64 nel modello. `src` = path "
                     "assoluto nel tuo scratch; `filename` può includere sottocartelle."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "filename": {"type": "string", "description": "nome file (può includere sottocartelle)"},
            "src": {"type": "string", "description": "path assoluto del file nel tuo scratch"},
        }, "required": ["tier", "name", "filename", "src"]},
    ),
    Tool(
        name="topic.delete_file",
        description=("Elimina un file o una cartella (ricorsivo) DENTRO files/ del topic. "
                     "Solo sotto files/ (la struttura del topic — meta, summary, minutes — "
                     "è protetta). path = path relativo alla root del topic, come restituito "
                     "da topic.files (es. 'files/old/x.pdf' o 'files/files')."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "path": {"type": "string", "description": "path da eliminare, dentro files/"},
        }, "required": ["tier", "name", "path"]},
    ),
]


_TRELLO_TOOLS: list[Tool] = [
    Tool(name="trello.boards",
         description="Le board Trello dell'account connesso (id, name, url).",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="trello.lists",
         description="Le liste (colonne) aperte di una board.",
         inputSchema={"type": "object", "properties": {
             "board_id": {"type": "string"}}, "required": ["board_id"]}),
    Tool(name="trello.cards",
         description="Le card di una lista (name, desc, due, url).",
         inputSchema={"type": "object", "properties": {
             "list_id": {"type": "string"}}, "required": ["list_id"]}),
    Tool(name="trello.create_card",
         description="Crea una card in una lista.",
         inputSchema={"type": "object", "properties": {
             "list_id": {"type": "string"}, "name": {"type": "string"},
             "desc": {"type": "string"}}, "required": ["list_id", "name"]}),
    Tool(name="trello.move_card",
         description="Sposta una card in un'altra lista (nome o id lista).",
         inputSchema={"type": "object", "properties": {
             "card_id": {"type": "string"}, "to": {"type": "string"}},
             "required": ["card_id", "to"]}),
    Tool(name="trello.comment",
         description="Aggiunge un commento a una card.",
         inputSchema={"type": "object", "properties": {
             "card_id": {"type": "string"}, "text": {"type": "string"}},
             "required": ["card_id", "text"]}),
]


_PROFILE_TOOLS: list[Tool] = [
    Tool(name="profile.get",
         description=("Dati personali (PII) di un agent/umano: email, iban, domicilio, ecc. "
                      "Ritorna i campi SOLO se sei il titolare, un admin, o hai ricevuto il grant "
                      "(ACL per-profilo). Usalo quando ti serve un dato personale di qualcuno."),
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string", "description": "nome dell'agent/umano di cui leggere il profilo"}},
             "required": ["agent"]}),
    Tool(name="profile.set",
         description="Crea/aggiorna i campi del TUO profilo (o, se admin, di un altro). fields = oggetto chiave→valore; valore null rimuove la chiave.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"}, "fields": {"type": "object"}},
             "required": ["fields"]}),
    Tool(name="profile.list_files",
         description="Elenca i file allegati al profilo di un agent (se autorizzato): name, size, mtime.",
         inputSchema={"type": "object", "properties": {"agent": {"type": "string"}}, "required": ["agent"]}),
    Tool(name="profile.read_file",
         description="Legge un file allegato al profilo (se autorizzato). Ritorna testo, o base64 per i binari.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"}, "filename": {"type": "string"}}, "required": ["agent", "filename"]}),
    Tool(name="profile.grant",
         description="Concedi/revoca a un altro agent la lettura del TUO profilo (o, se admin, di un altro). granted=false per revocare.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"}, "grantee": {"type": "string"},
             "granted": {"type": "boolean"}},
             "required": ["grantee"]}),
]


_RUNTIME_TOOLS: list[Tool] = [
    Tool(name="runtime.agents",
         description="Introspezione runtime: gli agent dell'istanza (nome, tipo, provider effettivo, stato connessione, paused). Solo metadati.",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="runtime.jobs",
         description="Introspezione runtime: i job schedulati (cron/intervallo) e il loro stato.",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="runtime.skills",
         description="Introspezione runtime: le skill nel catalogo, per pack.",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="runtime.chats",
         description="Introspezione runtime: le chat aperte (id/kind/titolo/stato, non il contenuto).",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="runtime.topics",
         description="Introspezione runtime: i topic dell'istanza (metadati). I P3 (Restricted) sono esclusi salvo include_restricted=true.",
         inputSchema={"type": "object", "properties": {
             "include_restricted": {"type": "boolean", "description": "includi i topic P3 Restricted (default false)"}}}),
    Tool(name="runtime.mcp_servers",
         description="Introspezione runtime: i server MCP disponibili (backend montati via Add-MCP + namespace nativi).",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="runtime.providers",
         description="Introspezione runtime: i provider di inferenza (id/nome/meccanismo/stato di connessione). MAI segreti.",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="runtime.current_user",
         description="Chi è l'utente umano con cui stai parlando: l'owner/superadmin dell'istanza (+ gli altri principal umani). Usalo per sapere a chi ti stai rivolgendo.",
         inputSchema={"type": "object", "properties": {}}),
]

# settings.* — superficie conversazionale per i settings della piattaforma
# (oggi: backup). SOLO super-agent. MAI segreti (passphrase/credenziali si
# impostano dalla pagina Settings via paste-key).
_SETTINGS_TOOLS: list[Tool] = [
    Tool(name="settings.backup_get",
         description="Backup della piattaforma (ISO 27001 A.8.13): configurazione SENZA segreti, stato e ultimo snapshot.",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="settings.backup_set",
         description=("Aggiorna i campi NON-segreti del backup (backend, repository, "
                      "schedule cron, retention {daily,weekly,monthly}). Le credenziali e la "
                      "passphrase NON si impostano qui: vanno inserite dalla pagina Settings."),
         inputSchema={"type": "object", "properties": {
             "backend": {"type": "string"}, "repository": {"type": "string"},
             "schedule": {"type": "string"},
             "retention": {"type": "object"}}}),
    Tool(name="settings.backup_run",
         description="Esegue subito un backup completo (snapshot + retention + verifica integrità).",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="settings.backup_restore_test",
         description="Restore-test: ripristina l'ultimo snapshot in area temporanea e verifica (evidenza A.8.13).",
         inputSchema={"type": "object", "properties": {}}),
]

# gdrive.* — export/import file fra i topic e Drive, riusando le credenziali
# Workspace nel vault. Trasferimento via scratch (come topic.fetch/put).
_GDRIVE_TOOLS: list[Tool] = [
    Tool(name="gdrive.list",
         description=("Elenca file/cartelle di Google Drive. folder_id per il contenuto di "
                      "una cartella; query per una query Drive (es. \"name contains 'x'\")."),
         inputSchema={"type": "object", "properties": {
             "folder_id": {"type": "string"}, "query": {"type": "string"},
             "limit": {"type": "integer"}, "account": {"type": "string"}}}),
    Tool(name="gdrive.search",
         description="Cerca file/cartelle Drive per nome (match parziale).",
         inputSchema={"type": "object", "properties": {
             "name": {"type": "string"}, "limit": {"type": "integer"},
             "account": {"type": "string"}}, "required": ["name"]}),
    Tool(name="gdrive.mkdir",
         description="Crea una cartella Drive (riusa una omonima nello stesso parent se esiste).",
         inputSchema={"type": "object", "properties": {
             "name": {"type": "string"}, "parent_id": {"type": "string"},
             "account": {"type": "string"}}, "required": ["name"]}),
    Tool(name="gdrive.upload",
         description=("Carica un file su Drive. src = path di un file nello scratch dell'agent "
                      "(prepara con topic.fetch). name = nome su Drive; folder_id = cartella."),
         inputSchema={"type": "object", "properties": {
             "src": {"type": "string"}, "name": {"type": "string"},
             "folder_id": {"type": "string"}, "account": {"type": "string"}},
             "required": ["src"]}),
    Tool(name="gdrive.download",
         description=("Scarica un file Drive in dest (path scratch dell'agent; poi usa topic.put "
                      "per metterlo nel topic). I Google-doc nativi sono esportati (PDF/xlsx)."),
         inputSchema={"type": "object", "properties": {
             "file_id": {"type": "string"}, "dest": {"type": "string"},
             "account": {"type": "string"}}, "required": ["file_id", "dest"]}),
    Tool(name="gdrive.share",
         description="Condivide un file/cartella Drive con un'email. role: writer (editor, default)|reader|commenter.",
         inputSchema={"type": "object", "properties": {
             "file_id": {"type": "string"}, "email": {"type": "string"},
             "role": {"type": "string"}, "account": {"type": "string"}},
             "required": ["file_id", "email"]}),
]

# telegram.* — invio + inbound con lease per-chat. Un agente scrive solo a chat
# che hanno già scritto e di cui detiene il lease; chat diverse → lease
# indipendenti. Il bot token vive nel vault, mai nel modello.
_TELEGRAM_TOOLS: list[Tool] = [
    Tool(name="telegram.inbox",
         description=("Chat Telegram con messaggi in arrivo (metadati, NON consuma): "
                      "per ognuna chat_id, titolo, n. messaggi pendenti, anteprima e chi "
                      "detiene il lease. Punto di partenza prima di prendere un lease."),
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="telegram.lease_acquire",
         description=("Acquisisce il lease ESCLUSIVO su una chat per N minuti: finché è "
                      "valido sei l'unico a consumarne i messaggi e a poterle scrivere. "
                      "Fallisce se un altro agente la detiene. Solo chat che hanno scritto."),
         inputSchema={"type": "object", "properties": {
             "chat_id": {"type": "string", "description": "ID chat (da telegram.inbox)"},
             "minutes": {"type": "integer", "description": "Durata lease (default 10, max 120)"}},
             "required": ["chat_id"]}),
    Tool(name="telegram.poll",
         description=("Consuma (svuota) i messaggi in coda di una chat. Richiede un lease "
                      "attivo del chiamante su quella chat."),
         inputSchema={"type": "object", "properties": {
             "chat_id": {"type": "string"}}, "required": ["chat_id"]}),
    Tool(name="telegram.send",
         description=("Invia un messaggio a una chat. Consentito SOLO verso una chat che ha "
                      "già scritto al bot e di cui detieni il lease."),
         inputSchema={"type": "object", "properties": {
             "chat_id": {"type": "string"}, "text": {"type": "string"}},
             "required": ["chat_id", "text"]}),
    Tool(name="telegram.lease_release",
         description="Rilascia anticipatamente il lease su una chat (no-op se non lo detieni).",
         inputSchema={"type": "object", "properties": {
             "chat_id": {"type": "string"}}, "required": ["chat_id"]}),
]


def _dispatch_trello(name: str, a: dict):
    from .tools import trello as tr
    verb = name.split(NS_SEP_DOT, 1)[1]
    if verb == "boards":
        return tr.boards()
    if verb == "lists":
        return tr.lists(a["board_id"])
    if verb == "cards":
        return tr.cards(a["list_id"])
    if verb == "create_card":
        return tr.create_card(a["list_id"], a["name"], a.get("desc"))
    if verb == "move_card":
        return tr.move_card(a["card_id"], a["to"])
    if verb == "comment":
        return tr.comment(a["card_id"], a["text"])
    raise ValueError(f"unknown trello verb: {name}")


def _dispatch_profile(name: str, a: dict, caller: str | None):
    from . import profile as prof
    sub = name.split(NS_SEP_DOT, 1)[1]
    target = a.get("agent") or caller
    if sub == "get":
        return prof.get(caller, target)
    if sub == "set":
        return prof.set_fields(caller, target, a.get("fields") or {})
    if sub == "list_files":
        return {"files": prof.list_files(caller, target)}
    if sub == "read_file":
        import base64 as _b64
        raw = prof.read_file(caller, target, a["filename"])
        try:
            return {"filename": a["filename"], "text": raw.decode("utf-8")}
        except UnicodeDecodeError:
            return {"filename": a["filename"], "encoding": "base64", "data": _b64.b64encode(raw).decode()}
    if sub == "grant":
        return prof.grant(caller, target, a["grantee"], bool(a.get("granted", True)))
    raise ValueError(f"unknown profile tool: {name}")


def _dispatch_settings(name: str, arguments: dict, agent: str | None):
    # SOLO super-agent: settings.* tocca la configurazione di piattaforma.
    if not _is_super(agent):
        raise PermissionError("settings.* riservato ai super-agent")
    from . import backup
    sub = name.split(NS_SEP_DOT, 1)[1]
    if sub == "backup_get":
        return backup.config_redacted()
    if sub == "backup_set":
        return backup.set_config(arguments or {})
    if sub == "backup_run":
        return backup.run_backup()
    if sub == "backup_restore_test":
        return backup.restore_test()
    raise ValueError(f"unknown settings tool: {name}")


def _dispatch_gdrive(name: str, a: dict):
    from .tools import gdrive as gd
    verb = name.split(NS_SEP_DOT, 1)[1]
    if verb == "list":
        return gd.list_files(folder_id=a.get("folder_id"), query=a.get("query"),
                             limit=a.get("limit", 50), account=a.get("account"))
    if verb == "search":
        return gd.search(a["name"], limit=a.get("limit", 20), account=a.get("account"))
    if verb == "mkdir":
        return gd.mkdir(a["name"], parent_id=a.get("parent_id"), account=a.get("account"))
    if verb == "upload":
        src = _safe_scratch_path(a["src"])  # i byte vengono dallo scratch, mai dal modello
        return gd.upload(src, name=a.get("name"), folder_id=a.get("folder_id"),
                         account=a.get("account"))
    if verb == "download":
        dest = _safe_scratch_path(a["dest"])
        _os.makedirs(_os.path.dirname(dest), exist_ok=True)
        return gd.download(a["file_id"], dest, account=a.get("account"))
    if verb == "share":
        return gd.share(a["file_id"], a["email"], role=a.get("role", "writer"),
                        account=a.get("account"))
    raise ValueError(f"unknown gdrive verb: {name}")


def _dispatch_telegram(name: str, a: dict):
    from .tools import telegram as tg
    verb = name.split(NS_SEP_DOT, 1)[1]
    if verb == "inbox":
        return tg.inbox()
    if verb == "lease_acquire":
        return tg.lease_acquire(a["chat_id"], a.get("minutes", 10))
    if verb == "poll":
        return tg.poll(a["chat_id"])
    if verb == "send":
        return tg.send(a["chat_id"], a["text"])
    if verb == "lease_release":
        return tg.lease_release(a["chat_id"])
    raise ValueError(f"unknown telegram verb: {name}")


def _dispatch_runtime(name: str, arguments: dict):
    sub = name.split(NS_SEP_DOT, 1)[1]
    if sub == "agents":
        return runtime.agents()
    if sub == "jobs":
        return runtime.jobs()
    if sub == "skills":
        return runtime.skills()
    if sub == "chats":
        return runtime.chats()
    if sub == "topics":
        return runtime.topics(include_restricted=bool(arguments.get("include_restricted")))
    if sub == "mcp_servers":
        return runtime.mcp_servers()
    if sub == "providers":
        return runtime.providers()
    if sub == "current_user":
        return runtime.current_user()
    raise ValueError(f"unknown runtime tool: {name}")


# Super-agent nativi: hanno accesso a TUTTI i tool (inclusi i connettori/email
# delegati), bypassando la whitelist per-agent.
_SUPER_AGENTS = {"clodia", "ophelia"}


def _is_super(name: str | None) -> bool:
    return (name or "") in _SUPER_AGENTS


def _vault_grants(agent: str | None) -> set:
    if not agent:
        return set()
    try:
        from . import vault
        return set(vault.grants_for(agent).keys())
    except Exception:  # noqa: BLE001
        return set()


def _connector_allows(name: str, agent: str | None) -> bool:
    """Accesso a un tool di connettore derivato dai grant vault (persistente):
    - email.*   se l'agent ha un grant su un account gmail_<account>;
    - trello.*  se l'agent ha un grant sulla credenziale 'trello'.
    Così la delega non dipende da config.yaml (effimero al rebuild)."""
    grants = _vault_grants(agent)
    if name.startswith("email.") and any(
            c.startswith("gmail_") or c.startswith("mailbox_") for c in grants):
        return True
    if name.startswith("trello.") and "trello" in grants:
        return True
    if name.startswith("telegram.") and "telegram_bot_token" in grants:
        return True
    if name.startswith("gdrive.") and any(c.startswith("gworkspace_") for c in grants):
        return True
    return False


def _tool_allowed(name: str, allowed: set) -> bool:
    """True se il tool è in whitelist. Supporta il wildcard ``<backend>.*`` che
    concede TUTTI i tool di un backend MCP montato (usato dall'Add-MCP UI)."""
    if name in allowed:
        return True
    if NS_SEP_DOT in name and f"{name.split(NS_SEP_DOT, 1)[0]}.*" in allowed:
        return True
    return False


NS_SEP_DOT = "."


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Return only the tools allowed for the calling agent (native + proxied)."""
    try:
        allowed = set(agent_config().get("allowed_tools", []))
    except PermissionError:
        return []
    native = list(_FS_TOOLS + _AGENT_TOOLS + _EMAIL_TOOLS + _TRELLO_TOOLS + _TOPIC_TOOLS + _RUNTIME_TOOLS + _SETTINGS_TOOLS + _PROFILE_TOOLS + _TELEGRAM_TOOLS + _GDRIVE_TOOLS)
    # C1: tool dei backend MCP montati (namespaced), aggregati dal proxy.
    try:
        proxied = await proxy.list_proxied_tools()
    except Exception:
        proxied = []
    me = agent_name()
    if _is_super(me):
        return native + proxied  # super-agent: accesso a tutto
    return [t for t in (native + proxied)
            if _tool_allowed(t.name, allowed) or _connector_allows(t.name, me)]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        # Enforcement whitelist per-richiesta: in HTTP multi-agente non basta
        # il filtro di list_tools (un client può invocare un tool non elencato).
        # I super-agent (clodia/ophelia) bypassano: accesso a tutti i tool. I
        # tool dei connettori (email.*, trello.*) sono concessi anche a chi ha il
        # relativo grant nel vault (delega per-agent, persistente).
        _ag = agent_name()
        if not _is_super(_ag) and not _tool_allowed(
                name, set(agent_config().get("allowed_tools", []))) \
                and not _connector_allows(name, _ag):
            raise PermissionError(
                f"tool '{name}' non in whitelist per agent '{_ag}'")
        if name == "fs.list_dir":
            result = fs.list_dir(arguments["path"])
        elif name == "agent.spawn":
            result = agent.spawn(
                arguments["agent_type"],
                arguments["task"],
                wait_for_reply=arguments.get("wait_for_reply", False),
            )
        elif name == "email.send":
            result = email.send(
                arguments["to"],
                arguments["subject"],
                arguments["body"],
                account=arguments.get("account", "demo"),
                cc=arguments.get("cc"),
            )
        elif name == "email.folders":
            result = email.folders(account=arguments.get("account", "demo"))
        elif name == "email.list":
            result = email.list_messages(
                account=arguments.get("account", "demo"),
                folder=arguments.get("folder", "INBOX"),
                limit=arguments.get("limit", 10),
            )
        elif name == "email.read":
            result = email.read_message(
                arguments["email_id"],
                account=arguments.get("account", "demo"),
                folder=arguments.get("folder", "INBOX"),
            )
        elif name == "email.get_attachment":
            result = email.get_attachment(
                arguments["email_id"],
                arguments["filename"],
                account=arguments.get("account", "demo"),
                folder=arguments.get("folder", "INBOX"),
            )
        elif name == "email.search":
            result = email.search(
                arguments["query"],
                account=arguments.get("account", "demo"),
                folder=arguments.get("folder", "INBOX"),
                limit=arguments.get("limit", 20),
            )
        elif name == "email.reply":
            result = email.reply(
                arguments["email_id"],
                arguments["body"],
                account=arguments.get("account", "demo"),
                folder=arguments.get("folder", "INBOX"),
                cc=arguments.get("cc"),
            )
        elif name.startswith("trello."):
            result = _dispatch_trello(name, arguments)
        elif name.startswith("topic."):
            result = _dispatch_topic(name, arguments)
        elif name.startswith("profile."):
            result = _dispatch_profile(name, arguments, _ag)
        elif name.startswith("settings."):
            result = _dispatch_settings(name, arguments, _ag)
        elif name.startswith("telegram."):
            result = _dispatch_telegram(name, arguments)
        elif name.startswith("gdrive."):
            result = _dispatch_gdrive(name, arguments)
        elif name.startswith("runtime."):
            result = _dispatch_runtime(name, arguments)
        elif proxy.is_proxied(name):
            # C1: instrada al backend MCP montato (già passato il check whitelist).
            text = await proxy.call_proxied(name, arguments)
            return [TextContent(type="text", text=text)]
        else:
            raise ValueError(f"unknown tool: {name}")
        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except PermissionError as e:
        return [TextContent(type="text", text=f"DENIED: {e}")]
    except VersionConflict as e:
        return [TextContent(type="text", text=(
            "CONFLICT: il summary è cambiato durante il lavoro — rileggi con "
            f"topic.open e riapplica le tue modifiche, non sovrascrivere. {e}"))]
    except TopicError as e:
        return [TextContent(type="text", text=f"ERROR: {e}")]
    except Exception as e:
        return [TextContent(type="text", text=f"ERROR: {type(e).__name__}: {e}")]


# Estensioni che indicano contenuto BINARIO: un file con questo suffisso non può
# essere scritto come testo (es. un .xlsx scritto come testo = file corrotto che
# Excel non apre). Per questi forziamo la decodifica base64.
_BINARY_EXTS = {
    "xlsx", "xls", "xlsm", "docx", "doc", "pptx", "ppt", "pdf", "odt", "ods", "odp",
    "zip", "tar", "gz", "tgz", "7z", "rar",
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "tiff", "tif", "ico", "heic",
    "mp3", "wav", "ogg", "mp4", "mov", "avi", "mkv", "webm",
    "bin", "exe", "woff", "woff2", "ttf", "otf",
}


def _decode_b64_strict(content: str, filename: str) -> bytes:
    """Decodifica base64 in modo robusto: tollera whitespace/newline e padding
    mancante (errori comuni quando un LLM passa un blob lungo), ma su input non
    valido solleva un errore CHIARO — così l'agente rigenera il base64 invece di
    far scrivere spazzatura senza accorgersene."""
    import base64 as _b64
    import binascii
    t = "".join((content or "").split())          # togli spazi/newline
    t += "=" * ((-len(t)) % 4)                      # ripristina padding mancante
    try:
        return _b64.b64decode(t, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(
            f"Il content per '{filename}' non è base64 valido ({e}). I file binari "
            f"(xlsx/pdf/docx/zip/immagini) vanno passati come base64 con "
            f"encoding='base64'; rigenera il base64 COMPLETO del file e riprova."
        ) from e


_SPAWNS_ROOT = _os.environ.get("CLODIA_SPAWNS_ROOT", "/datadir/spawns")


def _safe_scratch_path(p: str) -> str:
    """Valida che `p` stia nello scratch di uno spawn (`/datadir/spawns/**`):
    il gateway scrive/legge SOLO lì, mai nel topic store o nei secrets, anche se
    l'agent passa un path arbitrario. Difesa contro path-traversal/abuso."""
    rp = _os.path.realpath(p or "")
    root = _os.path.realpath(_SPAWNS_ROOT)
    if not (rp == root or rp.startswith(root + "/")):
        raise ValueError(f"path non consentito (deve stare sotto {_SPAWNS_ROOT}): {p}")
    return rp


def _dispatch_topic(name: str, a: dict):
    svc = _topics()
    verb = name.split(".", 1)[1]
    if verb == "new":
        return svc.new(a.get("tier"), a["name"], a.get("meta"))
    if verb == "open":
        return svc.open(a["tier"], a["name"])
    if verb == "save_summary":
        return svc.save_summary(a["tier"], a["name"], a["text"], a.get("base_version"))
    if verb == "add_minute":
        return svc.add_minute(a["tier"], a["name"], a["text"])
    if verb == "archive":
        return svc.archive(a["tier"], a["name"])
    if verb == "list":
        return svc.list(a.get("tier"), a.get("include_archived", False))
    if verb == "search":
        return svc.search(a["query"], a.get("mode", "lexical"))
    if verb == "files":
        return svc.list_files(a["tier"], a["name"], a.get("subpath", ""))
    if verb == "read_file":
        data = svc.read_file(a["tier"], a["name"], a["path"])
        try:
            return {"path": a["path"], "encoding": "utf-8", "content": data.decode("utf-8")}
        except UnicodeDecodeError:
            import base64 as _b64
            return {"path": a["path"], "encoding": "base64",
                    "content": _b64.b64encode(data).decode("ascii"),
                    "note": "file binario (PDF/immagine/...): decodifica da base64"}
    if verb == "write_file":
        fn = a["filename"]
        enc = (a.get("encoding") or "text").lower()
        ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
        # Un file con estensione binaria NON può essere testo: lo decodifichiamo
        # sempre come base64 (anche se l'agente ha dimenticato encoding='base64'),
        # con errore chiaro se il base64 è malformato. Era questo il bug del
        # Travel_reimbursement.xlsx: base64 scritto come testo → file corrotto.
        if enc == "base64" or ext in _BINARY_EXTS:
            data = _decode_b64_strict(a["content"], fn)
        else:
            data = (a["content"] or "").encode("utf-8")
        return svc.put_file(a["tier"], a["name"], fn, data)
    if verb == "fetch":
        # Consegna una COPIA del file del topic nello SCRATCH dell'agent (path
        # locale), come un `git clone` ma di un singolo file e mediato dal gateway:
        # i byte NON transitano dal modello (niente base64 nel contesto → niente
        # troncamento sui file grandi). ACL: read_file rispetta la classe del topic.
        data = svc.read_file(a["tier"], a["name"], a["path"])
        dest = _safe_scratch_path(a["dest"])
        _os.makedirs(_os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data)
        return {"local_path": dest, "size": len(data)}
    if verb == "put":
        # Mette nel topic store un file preparato nello scratch dell'agent (come un
        # `push`): il gateway legge i byte dal path locale e li scrive nello store.
        src = _safe_scratch_path(a["src"])
        with open(src, "rb") as f:
            data = f.read()
        return svc.put_file(a["tier"], a["name"], a["filename"], data)
    if verb == "delete_file":
        return svc.delete_file(a["tier"], a["name"], a["path"])
    raise ValueError(f"unknown topic verb: {name}")


async def main():
    try:
        agent = agent_name()
        print(f"[mcp-tools-server v{__version__}] serving agent={agent}", file=sys.stderr)
    except PermissionError as e:
        print(f"[mcp-tools-server v{__version__}] {e}", file=sys.stderr)
        sys.exit(2)
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
