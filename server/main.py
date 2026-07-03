"""MCP stdio server entry point — Clodia tools gateway."""
import asyncio
import json
import sys

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from . import __version__
from . import proxy
from .tools import email, fs, runtime
from .tools import eu_corpus
from .whitelist import agent_config, agent_name, current_clearance

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
            "Send an email. Specify the sender mailbox via `account` (the account "
            "name, e.g. as shown by email.folders or your instructions). "
            "Plain-text body, optional CC and local file attachments."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "recipient email address"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "account": {
                    "type": "string",
                    "description": "sender mailbox account name (required if you have more than one)",
                },
                "cc": {"type": "string", "description": "optional CC address"},
                "attachments": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "optional local file paths to attach",
                },
            },
            "required": ["to", "subject", "body"],
        },
    ),
    Tool(
        name="email.folders",
        description="List the IMAP folders of an account (pass the account name in `account`).",
        inputSchema={
            "type": "object",
            "properties": {
                "account": {"type": "string",
                            "description": "account name to inspect"},
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
        description="Reply to a message keeping the thread (plain-text body, optional CC and local attachments).",
        inputSchema={
            "type": "object",
            "properties": {
                "email_id": {"type": "string", "description": "id of the message to reply to"},
                "body": {"type": "string"},
                "account": {"type": "string"},
                "folder": {"type": "string", "description": "IMAP folder, default INBOX"},
                "cc": {"type": "string", "description": "optional CC address"},
                "attachments": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "optional local file paths to attach",
                },
            },
            "required": ["email_id", "body"],
        },
    ),
]


# agent.spawn RIMOSSO (29 giu 2026): creava chat via POST /clodia/chats, endpoint
# eliminato nel passaggio al modello a canali/topic → il tool falliva a runtime
# (tool "fantasma" che illudeva l'agent di poter delegare in background). I
# subagent reali sono in-process (Task tool del Claude SDK), che girano dentro il
# turno (osservabili) e il cui esito rientra nel turno.
#
# agents.* (30 giu 2026): amministrazione delle capability degli ALTRI agent —
# dotare un agent editabile di skill/tool/rules dalla chat. Immutabili (super +
# flag immutable, es. Wainston) non toccabili. Scritture verificate anche dal
# backend (token inoltrato). Vedi tools/agents_admin.py.
_AGENT_TOOLS: list[Tool] = [
    Tool(name="agents.list",
         description=("Elenca gli agent dell'istanza con tipo e flag `immutable`. "
                      "Gli immutabili (super + protetti come Wainston) non sono "
                      "modificabili: si cambiano solo via codice/rebuild."),
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="agents.show",
         description="Capability correnti di un agent: skill (capabilities), rules, tool_permissions, immutabilità.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string", "description": "nome dell'agent"}},
             "required": ["agent"]}),
    Tool(name="agents.list_skills",
         description="Nomi delle skill disponibili nel catalogo (assegnabili come capabilities).",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="agents.list_rules",
         description="Nomi delle rule disponibili nel catalogo (assegnabili).",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="agents.list_tools",
         description="Namespace dei tool nativi del gateway concedibili a un agent (es. fs, email, topic, gdrive).",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="agents.grant_skill",
         description="Aggiunge una skill (capability) a un agent editabile.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"}, "skill": {"type": "string"}},
             "required": ["agent", "skill"]}),
    Tool(name="agents.revoke_skill",
         description="Rimuove una skill da un agent editabile.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"}, "skill": {"type": "string"}},
             "required": ["agent", "skill"]}),
    Tool(name="agents.grant_tool",
         description=("Concede un permesso tool a un agent editabile. Può essere un "
                      "tool puntuale (es. `email.send`) o un namespace (`fs.*`)."),
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"}, "tool": {"type": "string"}},
             "required": ["agent", "tool"]}),
    Tool(name="agents.revoke_tool",
         description="Revoca un permesso tool a un agent editabile.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"}, "tool": {"type": "string"}},
             "required": ["agent", "tool"]}),
    Tool(name="agents.grant_rule",
         description="Aggiunge una rule (regola di stile/comportamento) a un agent editabile.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"}, "rule": {"type": "string"}},
             "required": ["agent", "rule"]}),
    Tool(name="agents.revoke_rule",
         description="Rimuove una rule da un agent editabile.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"}, "rule": {"type": "string"}},
             "required": ["agent", "rule"]}),
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


_EU_CORPUS_TOOLS: list[Tool] = [
    Tool(
        name="eu_corpus.search",
        description=(
            "Retrieval semantico sul corpus normativo UE stabile (Horizon Europe): "
            "AGA (Annotated Grant Agreement), Programme Guide, General Annexes. "
            "Query in linguaggio naturale, IT o EN (l'embedding è multilingue). "
            "Ritorna i passaggi più pertinenti con CITAZIONE (documento, versione, "
            "sezione, pagina, score). Usalo per domande su eleggibilità costi, "
            "categorie di budget, funding rate, regole TRL, FSTP/cascade. "
            "IMPORTANTE: il retrieval trova i candidati, non è la verità — leggi il "
            "testo del passaggio per intero e cita sempre documento+versione+pagina."
        ),
        inputSchema={"type": "object", "properties": {
            "query": {"type": "string", "description": "domanda in linguaggio naturale (IT/EN)"},
            "k": {"type": "integer", "description": "n. passaggi (1-20, default 5)"},
            "doc": {"type": "string", "description": "filtro opzionale per documento: "
                    "AGA | HE-Programme-Guide | HE-General-Annexes"},
        }, "required": ["query"]},
    ),
    Tool(
        name="eu_corpus.ingest",
        description=(
            "Aggiunge un documento PDF alla knowledge base normativa (corpus RAG). "
            "Il file deve già stare nei files/ di un topic di cui sei participant "
            "(es. un PDF che l'utente ha allegato in chat → path 'files/xxx.pdf'). "
            "Lo estrae, chunka, embedda e lo indicizza su pgvector. "
            "USALO per materiale NORMATIVO/DI RIFERIMENTO stabile (guide, regolamenti, "
            "grant agreement), NON per dossier confidenziali specifici di un cliente "
            "(quelli restano nel topic e si leggono live con topic.read_file). "
            "doc_name+version identificano il documento: se stai caricando una NUOVA "
            "versione di un documento già presente, passa supersede=true (le versioni "
            "precedenti restano ma vengono marcate superseded). Ri-ingerire la stessa "
            "(doc_name, version) è idempotente (rimpiazza i chunk)."
        ),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"],
                     "description": "tier del topic da cui leggere il file"},
            "name": {"type": "string", "description": "nome del topic da cui leggere il file"},
            "path": {"type": "string", "description": "path del PDF nel topic, es. 'files/aga.pdf'"},
            "doc_name": {"type": "string", "description": "nome del documento nel corpus (es. 'AGA', 'HE-Programme-Guide')"},
            "version": {"type": "string", "description": "versione, es. '2.0 (2025-04-01)'"},
            "url": {"type": "string", "description": "URL fonte ufficiale (opzionale ma consigliato)"},
            "supersede": {"type": "boolean", "description": "true se è una nuova versione di un doc esistente"},
        }, "required": ["tier", "name", "path", "doc_name", "version"]},
    ),
    Tool(
        name="eu_corpus.list",
        description=("Elenca i documenti indicizzati nella knowledge base (corpus RAG): "
                     "nome, versione, status (active/superseded), n. chunk, fonte. "
                     "Usalo per mostrare all'utente cosa c'è nel corpus."),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="eu_corpus.remove",
        description=("Rimuove un documento dalla knowledge base (corpus RAG). "
                     "DISTRUTTIVO: cancella il documento e tutti i suoi chunk. "
                     "Se ometti `version` rimuove TUTTE le versioni di quel documento. "
                     "CONFERMA sempre con l'utente cosa stai per rimuovere prima di chiamarlo "
                     "(nome + versione). Usa eu_corpus.list per i nomi/versioni esatti."),
        inputSchema={"type": "object", "properties": {
            "doc_name": {"type": "string", "description": "nome del documento (come da eu_corpus.list)"},
            "version": {"type": "string", "description": "versione specifica; se omessa, tutte le versioni"},
        }, "required": ["doc_name"]},
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
        description=("Sposta nel CESTINO (.trash/) un file o una cartella DENTRO files/ del "
                     "topic — NON cancella mai davvero: è sempre recuperabile. Solo sotto "
                     "files/ (meta, summary, minutes sono protetti). path = path relativo alla "
                     "root del topic, come da topic.files (es. 'files/old/x.pdf' o 'files/files')."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "path": {"type": "string", "description": "path da eliminare, dentro files/"},
        }, "required": ["tier", "name", "path"]},
    ),
    Tool(
        name="topic.migrate_storage",
        description=("Migra i FILE del topic da uno storage all'altro (local↔Google Drive). "
                     "Copia NON distruttiva: il vecchio contenuto va nel cestino (recuperabile). "
                     "Guard SEAL: vietato migrare su uno storage con livello inferiore al tier "
                     "(es. SEAL-3 non va su Drive). target.type=local|drive; per drive folder "
                     "(link/id) opzionale (vuoto = crea cartella)."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "target": {"type": "object", "properties": {
                "type": {"type": "string", "enum": ["local", "drive"]},
                "folder": {"type": "string"}, "account": {"type": "string"}},
                "required": ["type"]},
        }, "required": ["tier", "name", "target"]},
    ),
    # ── Remote pluggable: lo storage è SEMPRE locale; un remote opzionale (git o
    # drive) sincronizza i FILE con verbi uniformi add/commit/push/pull. ──
    Tool(
        name="topic.remote_enable",
        description=("Attiva un remote di sync per i FILE del topic (storage resta locale). "
                     "type=git (config.url opzionale) | drive (config.folder link/id opzionale = "
                     "crea cartella, config.account). Poi usa remote_add/commit/push/pull."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "type": {"type": "string", "enum": ["git", "drive"]},
            "config": {"type": "object", "description": "git: {url,branch} · drive: {folder,account}"},
        }, "required": ["tier", "name", "type"]},
    ),
    Tool(
        name="topic.remote_disable",
        description="Disattiva il remote: torna a local pulito PRESERVANDO i file (git→rimuove .git, drive→cancella la sync-list).",
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}}, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.remote_add",
        description="Marca un file per il sync (git: git add · drive: aggiunge a sync-list e push-list). path relativo a files/.",
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}, "path": {"type": "string"}}, "required": ["tier", "name", "path"]},
    ),
    Tool(
        name="topic.remote_commit",
        description="Snapshot delle modifiche (git: commit · drive: no-op). message opzionale.",
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}, "message": {"type": "string"}}, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.remote_push",
        description="Invia le modifiche al remote (git: push · drive: carica la push-list, push-only, non cancella su Drive).",
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}}, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.remote_pull",
        description="Riceve dal remote (git: pull, conflitto→escala · drive: scarica; i nuovi entrano in sync-list, last-writer-wins per-file).",
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}}, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.remote_status",
        description="Stato del remote del topic (tipo, abilitato, e per drive: synced/pending).",
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}}, "required": ["tier", "name"]},
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


def _native_tool_namespaces() -> list[str]:
    """Namespace dei tool nativi del gateway (per agents.list_tools)."""
    tools = (_FS_TOOLS + _EMAIL_TOOLS + _TRELLO_TOOLS + _TOPIC_TOOLS + _RUNTIME_TOOLS
             + _PROFILE_TOOLS + _TELEGRAM_TOOLS + _GDRIVE_TOOLS + _AGENT_TOOLS
             + _EU_CORPUS_TOOLS)
    ns = sorted({t.name.split(NS_SEP_DOT, 1)[0] for t in tools})
    return ns


def _dispatch_agents(name: str, a: dict, caller: str | None):
    from .tools import agents_admin as adm
    verb = name.split(NS_SEP_DOT, 1)[1]
    if verb == "list":
        return adm.list_agents()
    if verb == "show":
        return adm.show(a["agent"])
    if verb == "list_skills":
        return adm.list_skills()
    if verb == "list_rules":
        return adm.list_rules()
    if verb == "list_tools":
        return {"namespaces": _native_tool_namespaces(),
                "note": "concedi un namespace intero con `<ns>.*` o un tool puntuale `<ns>.<verbo>`"}
    if verb == "grant_skill":
        return adm.grant_skill(a["agent"], a["skill"])
    if verb == "revoke_skill":
        return adm.revoke_skill(a["agent"], a["skill"])
    if verb == "grant_tool":
        return adm.grant_tool(a["agent"], a["tool"])
    if verb == "revoke_tool":
        return adm.revoke_tool(a["agent"], a["tool"])
    if verb == "grant_rule":
        return adm.grant_rule(a["agent"], a["rule"])
    if verb == "revoke_rule":
        return adm.revoke_rule(a["agent"], a["rule"])
    raise ValueError(f"unknown agents verb: {name}")


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


def _email_account(arguments: dict) -> str:
    """Account per una chiamata email.*: quello richiesto esplicitamente,
    altrimenti l'UNICO account su cui il chiamante ha un grant vault
    (gmail_*/mailbox_*). Se assente o ambiguo (più account) resta 'demo' → il
    tool solleva un errore chiaro con la lista disponibile, così l'agent sa che
    deve specificare `account`. Evita il default muto a 'demo' quando l'agent ha
    esattamente una casella delegata."""
    acct = (arguments.get("account") or "").strip()
    if acct:
        return acct
    grants = _vault_grants(agent_name())
    accts = sorted({c[len("gmail_"):] for c in grants if c.startswith("gmail_")}
                   | {c[len("mailbox_"):] for c in grants if c.startswith("mailbox_")})
    return accts[0] if len(accts) == 1 else "demo"


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
    native = list(_FS_TOOLS + _EMAIL_TOOLS + _TRELLO_TOOLS + _TOPIC_TOOLS + _RUNTIME_TOOLS + _SETTINGS_TOOLS + _PROFILE_TOOLS + _TELEGRAM_TOOLS + _GDRIVE_TOOLS + _AGENT_TOOLS + _EU_CORPUS_TOOLS)
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
        elif name == "email.send":
            result = email.send(
                arguments["to"],
                arguments["subject"],
                arguments["body"],
                account=_email_account(arguments),
                cc=arguments.get("cc"),
                attachments=arguments.get("attachments"),
            )
        elif name == "email.folders":
            result = email.folders(account=_email_account(arguments))
        elif name == "email.list":
            result = email.list_messages(
                account=_email_account(arguments),
                folder=arguments.get("folder", "INBOX"),
                limit=arguments.get("limit", 10),
            )
        elif name == "email.read":
            result = email.read_message(
                arguments["email_id"],
                account=_email_account(arguments),
                folder=arguments.get("folder", "INBOX"),
            )
        elif name == "email.get_attachment":
            result = email.get_attachment(
                arguments["email_id"],
                arguments["filename"],
                account=_email_account(arguments),
                folder=arguments.get("folder", "INBOX"),
            )
        elif name == "email.search":
            result = email.search(
                arguments["query"],
                account=_email_account(arguments),
                folder=arguments.get("folder", "INBOX"),
                limit=arguments.get("limit", 20),
            )
        elif name == "email.reply":
            result = email.reply(
                arguments["email_id"],
                arguments["body"],
                account=_email_account(arguments),
                folder=arguments.get("folder", "INBOX"),
                cc=arguments.get("cc"),
                attachments=arguments.get("attachments"),
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
        elif name.startswith("agents."):
            result = _dispatch_agents(name, arguments, _ag)
        elif name == "eu_corpus.search":
            result = eu_corpus.search(
                arguments["query"],
                k=arguments.get("k", 5),
                doc=arguments.get("doc"),
            )
        elif name == "eu_corpus.ingest":
            # Legge il PDF dal topic server-side (i byte NON passano dal modello),
            # con controllo participant+clearance, poi lo invia al micro-servizio.
            svc = _topics()
            tier, tname, path = arguments["tier"], arguments["name"], arguments["path"]
            _require_topic_member(svc, tier, tname)
            data = svc.read_file(tier, tname, path)
            filename = path.rsplit("/", 1)[-1]
            result = eu_corpus.ingest_bytes(
                data, filename,
                arguments["doc_name"], arguments["version"],
                url=arguments.get("url"),
                supersede=bool(arguments.get("supersede", False)),
            )
        elif name == "eu_corpus.list":
            result = eu_corpus.list_documents()
        elif name == "eu_corpus.remove":
            result = eu_corpus.remove(arguments["doc_name"], arguments.get("version"))
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


# Verbi topic.* che accedono ai dati di UN topic specifico → richiedono che il
# caller sia participant/owner (compartimento, need-to-know). `new`/`list`/`search`
# sono gestiti a parte (creazione / risultati filtrati per membership).
_TOPIC_SCOPED_VERBS = {
    "open", "save_summary", "add_minute", "archive", "files", "read_file",
    "write_file", "fetch", "put", "delete_file", "migrate_storage",
    "remote_enable", "remote_disable", "remote_add", "remote_commit",
    "remote_push", "remote_pull", "remote_status",
}


_SEAL_RANK = {"SEAL-0": 0, "SEAL-1": 1, "SEAL-2": 2, "SEAL-3": 3, "SEAL-4": 4}


def _rank(tier: str | None) -> int:
    return _SEAL_RANK.get(str(tier or "SEAL-0").strip().upper(), 0)


def _topic_is_member(meta: dict, caller: str) -> bool:
    return caller == meta.get("owner") or caller in (meta.get("participants") or [])


def _require_topic_member(svc, tier, name) -> None:
    """ACL compartimento: il caller dev'essere participant/owner del topic. I
    super-agent bypassano (accesso pieno). Enforcement per-(agent,topic): dà il
    confinamento reale, complementare alla clearance≥tier (vedi
    project_topic_access_two_axis)."""
    caller = agent_name()
    if _is_super(caller):
        return
    try:
        meta = svc.open(tier, name).get("meta", {})
    except Exception:  # noqa: BLE001 — topic inesistente/illeggibile → nega
        raise PermissionError(f"topic {tier}/{name}: accesso negato")
    if not _topic_is_member(meta, caller):
        raise PermissionError(
            f"agent '{caller}' non è participant del topic {tier}/{name} "
            f"(accesso negato: compartimento need-to-know)")
    # asse livello: clearance(caller) ≥ tier(topic). Clearance dal claim firmato
    # nel token (None → SEAL-0). Difesa in profondità oltre al compartimento.
    tier_t = meta.get("tier", tier)
    if _rank(current_clearance()) < _rank(tier_t):
        raise PermissionError(
            f"agent '{caller}': clearance insufficiente per il tier {tier_t} del "
            f"topic {tier}/{name} (accesso negato: livello)")


def _filter_member_rows(rows: list, caller: str) -> list:
    """Filtra righe-topic ai soli topic di cui il caller è participant/owner.
    Super → tutte. Righe senza participants/owner (shape diversa) lasciate."""
    if _is_super(caller):
        return rows
    out = []
    for r in rows:
        if not isinstance(r, dict) or ("participants" not in r and "owner" not in r):
            out.append(r)
        elif _topic_is_member(r, caller):
            out.append(r)
    return out


def _dispatch_topic(name: str, a: dict):
    svc = _topics()
    verb = name.split(".", 1)[1]
    if verb in _TOPIC_SCOPED_VERBS:
        _require_topic_member(svc, a.get("tier"), a.get("name"))
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
        return _filter_member_rows(svc.list(a.get("tier"), a.get("include_archived", False)),
                                   agent_name())
    if verb == "search":
        res = svc.search(a["query"], a.get("mode", "lexical"))
        return _filter_member_rows(res, agent_name()) if isinstance(res, list) else res
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
    if verb == "migrate_storage":
        return svc.migrate_storage(a["tier"], a["name"], a["target"])
    # Remote pluggable (git/drive): storage sempre local, sync opzionale/manuale.
    if verb == "remote_status":
        return svc.remote_status(a["tier"], a["name"])
    if verb == "remote_enable":
        return svc.remote_enable(a["tier"], a["name"], a["type"], a.get("config"))
    if verb == "remote_disable":
        return svc.remote_disable(a["tier"], a["name"])
    if verb == "remote_add":
        return svc.remote_add(a["tier"], a["name"], a["path"])
    if verb == "remote_commit":
        return svc.remote_commit(a["tier"], a["name"], a.get("message", ""))
    if verb == "remote_push":
        return svc.remote_push(a["tier"], a["name"])
    if verb == "remote_pull":
        return svc.remote_pull(a["tier"], a["name"])
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
