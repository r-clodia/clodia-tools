"""MCP stdio server entry point — Clodia tools gateway."""
import asyncio
import json
import sys

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from . import __version__
from . import instance_profile
from . import proxy
from . import transfer_channel
from .tools import email, fs, logs, runtime
from .tools import web_post
from .tools import eu_corpus
from .whitelist import (agent_config, agent_name, current_chat, current_clearance,
                        current_human_role, current_principal, current_scoped_tools,
                        is_on_behalf)

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
                     "SOLO per allegati piccoli/testuali: per PDF, immagini e binari usa "
                     "email.save_attachment (il base64 non passa dal modello). "
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
        name="email.save_attachment",
        description=("Scarica un allegato e lo SCRIVE su file nel tuo scratch (`dest` "
                     "assoluto): i byte NON passano dal contesto del modello — usa QUESTO "
                     "per PDF, immagini e binari. Flusso tipico: email.save_attachment → "
                     "topic.put per depositarlo nei file di un topic. "
                     "Usa email.read per scoprire i nomi degli allegati."),
        inputSchema={
            "type": "object",
            "properties": {
                "email_id": {"type": "string", "description": "IMAP message id"},
                "filename": {"type": "string", "description": "nome esatto dell'allegato (da email.read)"},
                "dest": {"type": "string", "description": "path assoluto di destinazione nel tuo scratch"},
                "account": {"type": "string"},
                "folder": {"type": "string", "description": "IMAP folder, default INBOX"},
            },
            "required": ["email_id", "filename", "dest"],
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
    Tool(name="agents.grant_scoped",
         description="Concede temporaneamente skill, regole, tool o runtime a un agent nello scope indicato.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"},
             "scope_kind": {"type": "string", "enum": ["topic", "chat", "run"], "default": "topic"},
             "scope_id": {"type": "string"},
             "ttl_minutes": {"type": "integer", "minimum": 1, "maximum": 120, "default": 15},
             "capabilities": {"type": "array", "items": {"type": "string"}},
             "rules": {"type": "array", "items": {"type": "string"}},
             "tools": {"type": "array", "items": {"type": "string"}},
             "model": {"type": "string"}, "provider": {"type": "string"},
             "reason": {"type": "string"}},
             "required": ["agent"]}),
    Tool(name="agents.list_scoped",
         description="Elenca gli override runtime attivi di un agent.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"}}, "required": ["agent"]}),
    Tool(name="agents.revoke_scoped",
         description="Revoca immediatamente un override runtime scoped.",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string"}, "override_id": {"type": "string"}},
             "required": ["agent", "override_id"]}),
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

_WEB_TOOLS: list[Tool] = [
    Tool(
        name="web.post",
        description=(
            "Invia una richiesta HTTP POST dopo approvazione umana per questa "
            "singola invocazione. Non segue redirect; payload e risposta sono limitati."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL http/https di destinazione"},
                "json": {"description": "payload JSON (alternativo a body)"},
                "body": {"type": "string", "description": "payload testuale (alternativo a json)"},
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "header opzionali; Host e hop-by-hop sono vietati",
                },
                "timeout_seconds": {
                    "type": "number", "minimum": 0.1, "maximum": 10,
                    "description": "timeout, massimo 10 secondi",
                },
            },
            "required": ["url"],
        },
    ),
]

_LOGS_TOOLS: list[Tool] = [
    Tool(
        name="logs.tail",
        description=(
            "Read-only: le ultime righe del log del server (agent-server) per la "
            "diagnosi. Segreti redatti. Solo log di piattaforma, MAI contenuti dei topic."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lines": {"type": "integer", "description": "Numero di righe (default 100, max 500)."},
                "level": {"type": "string", "description": "Filtro livello opzionale: INFO|WARNING|ERROR."},
            },
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


_RAG_TOOLS: list[Tool] = [
    Tool(
        name="rag.collections",
        description=("Elenca le knowledge base (collection) su cui hai accesso in "
                     "lettura, con tier e conteggi. Usalo per sapere quali corpora "
                     "puoi interrogare."),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="rag.create_collection",
        description=("Crea/provisiona una collection della knowledge base. Riservato "
                     "al provisioning dei pack: usa solo nomi e tier dichiarati nei "
                     "manifest curated. Dopo la creazione usa rag.ingest per le "
                     "risorse iniziali."),
        inputSchema={"type": "object", "properties": {
            "collection": {"type": "string"},
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "description": {"type": "string"},
        }, "required": ["collection"]},
    ),
    Tool(
        name="rag.search",
        description=("Retrieval semantico su una collection della knowledge base. "
                     "Query IT/EN. Ritorna passaggi con citazione (documento, "
                     "versione, sezione, pagina, score). Il retrieval trova i "
                     "candidati, non è la verità: leggi il passaggio per intero e "
                     "cita sempre documento+versione+pagina."),
        inputSchema={"type": "object", "properties": {
            "collection": {"type": "string", "description": "collection su cui cercare"},
            "query": {"type": "string", "description": "domanda in linguaggio naturale (IT/EN)"},
            "k": {"type": "integer", "description": "n. passaggi (1-20, default 5)"},
            "doc": {"type": "string", "description": "filtro opzionale per nome documento"},
        }, "required": ["collection", "query"]},
    ),
    Tool(
        name="rag.list",
        description="Elenca i documenti di una collection (nome, versione, status, n. chunk, fonte).",
        inputSchema={"type": "object", "properties": {
            "collection": {"type": "string"},
        }, "required": ["collection"]},
    ),
    Tool(
        name="rag.ingest",
        description=("Aggiunge un PDF (già nei files/ di un topic di cui sei "
                     "participant) a una collection della knowledge base. Il gateway "
                     "legge i byte server-side, li estrae/chunka/embedda/indicizza. "
                     "Richiede grant di SCRITTURA sulla collection. Solo materiale "
                     "stabile/di riferimento, non dossier confidenziali per-cliente. "
                     "supersede=true per una nuova versione di un doc già presente."),
        inputSchema={"type": "object", "properties": {
            "collection": {"type": "string"},
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"],
                     "description": "tier del topic da cui leggere il file"},
            "name": {"type": "string", "description": "nome del topic da cui leggere il file"},
            "path": {"type": "string", "description": "path del PDF nel topic, es. 'files/x.pdf'"},
            "doc_name": {"type": "string", "description": "nome del documento nella collection"},
            "version": {"type": "string"},
            "url": {"type": "string"},
            "supersede": {"type": "boolean"},
        }, "required": ["collection", "tier", "name", "path", "doc_name", "version"]},
    ),
    Tool(
        name="rag.remove",
        description=("Rimuove un documento da una collection (DISTRUTTIVO). Richiede "
                     "grant di SCRITTURA. Se ometti version rimuovi tutte le versioni. "
                     "Conferma sempre con l'utente cosa stai per rimuovere."),
        inputSchema={"type": "object", "properties": {
            "collection": {"type": "string"},
            "doc_name": {"type": "string"},
            "version": {"type": "string"},
        }, "required": ["collection", "doc_name"]},
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
            "hook_enabled": {
                "type": "boolean",
                "description": "crea il webhook del topic (default true)"},
        }, "required": ["name"]},
    ),
    Tool(
        name="topic.invoke_hook",
        description=(
            "Invoca localmente l'hook di un topic senza segreto. Il chiamante deve "
            "essere participant; messaggero può invocare qualunque topic. Il payload "
            "viene accodato come @caller e sveglia il caller."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "payload": {"type": "string"},
        }, "required": ["tier", "name", "payload"]},
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
        name="topic.read_document",
        description=("Estrae il TESTO di un documento del topic (PDF, DOCX, XLSX) — "
                     "l'estrazione avviene server-side nel gateway, quindi ricevi TESTO "
                     "leggibile, non base64. USA QUESTO per leggere un PDF/DOCX/XLSX "
                     "invece di topic.read_file (che restituisce base64 binario). "
                     "Ritorna {text, chars, pages, truncated}. Per PDF lunghi usa "
                     "max_chars per limitare il testo."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "path": {"type": "string", "description": "path relativo al topic, es. files/report.pdf"},
            "max_chars": {"type": "integer", "description": "max caratteri restituiti (default 60000)"},
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
        name="artifact.render",
        description=("Aggiorna il CANVAS LIVE del topic con un artefatto HTML. Scrive lo "
                     "snapshot in files/artifact.html (persistente e riapribile) e la "
                     "finestra di anteprima del topic lo mostra aggiornato. Passa l'INTERO "
                     "documento HTML in `html` a OGNI chiamata (snapshot completo, non un "
                     "frammento/patch). Usalo per mostrare all'utente un artefatto vivo "
                     "(cover, mockup, dashboard) che evolvi durante la conversazione."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "html": {"type": "string", "description": "documento HTML COMPLETO (snapshot del canvas)"},
        }, "required": ["tier", "name", "html"]},
    ),
    Tool(
        name="topic.fetch",
        description=("Scarica una COPIA di un file del topic nel TUO scratch (path "
                     "locale), per trattarlo con le skill standard (xlsx/pdf/docx/…). "
                     "USA QUESTO per i BINARI invece di topic.read_file (che passa "
                     "base64 nel contesto e si tronca sui file grandi). Il trasporto "
                     "usa envelope cifrati effimeri sul volume shared. `dest` = path "
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
                     "byte tramite un envelope cifrato effimero, niente base64 nel modello. `src` = path "
                     "assoluto nel tuo scratch; `filename` può includere sottocartelle."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "filename": {"type": "string", "description": "nome file (può includere sottocartelle)"},
            "src": {"type": "string", "description": "path assoluto del file nel tuo scratch"},
        }, "required": ["tier", "name", "filename", "src"]},
    ),
    Tool(
        name="topic.post_message",
        description=("Posta un MESSAGGIO nella chat del topic (una bolla nella "
                     "conversazione), come te. Serve a far comparire nel topic ciò che "
                     "arriva da fuori (es. una mail in arrivo) o un handoff a fine job. "
                     "Prerogativa di MESSAGGERO e dei super-agent. Se includi una "
                     "@menzione (es. `@messaggero …`), innesca l'agente taggato che "
                     "prende in carico il messaggio; senza menzione è solo una bolla. "
                     "Puoi postare solo in un topic di cui sei participant (cross-topic → gate)."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "text": {"type": "string", "description": "testo del messaggio"},
        }, "required": ["tier", "name", "text"]},
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
        description=("Migra i FILE del topic da locale a Google Drive o viceversa. "
                     "Su Drive la cartella remota diventa il filesystem live autoritativo; "
                     "tornando a locale, i file remoti vengono materializzati nel topic. "
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
    # ── Remote pluggable: git usa il ciclo di sync; Drive è un filesystem live. ──
    Tool(
        name="topic.remote_enable",
        description=("Attiva un remote per i FILE del topic. Git conserva il ciclo "
                     "add/commit/push/pull. Drive diventa il filesystem autoritativo live: "
                     "config.folder link/id opzionale (vuoto = crea cartella), config.account."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "type": {"type": "string", "enum": ["git", "drive"]},
            "config": {"type": "object", "description": "git: {url,branch} · drive: {folder,account}"},
        }, "required": ["tier", "name", "type"]},
    ),
    Tool(
        name="topic.remote_disable",
        description=("Disattiva il remote preservando i file. Per Drive materializza "
                     "prima la cartella remota nel filesystem locale."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}}, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.remote_add",
        description=("Marca un file per il sync Git. Su Drive è un no-op deprecato "
                     "perché topic.write_file/topic.put caricano immediatamente."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}, "path": {"type": "string"}}, "required": ["tier", "name", "path"]},
    ),
    Tool(
        name="topic.remote_commit",
        description="Snapshot delle modifiche Git. Su Drive live è un no-op deprecato.",
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}, "message": {"type": "string"}}, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.remote_push",
        description="Invia le modifiche Git. Su Drive live è un no-op deprecato.",
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}}, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.remote_pull",
        description=("Riceve dal remote Git (conflitto→escala). Su Drive live è un "
                     "no-op deprecato perché le letture vedono già il remoto."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}}, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.remote_status",
        description=("Stato del remote del topic. Per Drive include mode=live e "
                     "last_write_wins=true."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"}}, "required": ["tier", "name"]},
    ),
    Tool(
        name="topic.suggest_team",
        description=("Proponi la SQUADRA di agenti per un topic, data una breve "
                     "descrizione di cosa tratta. Ritorna gli agenti più "
                     "specializzati (rilevanza) e meno costosi fra quelli idonei "
                     "al tier (SEAL/clearance/provider): `candidates` ordinati con "
                     "score+costo+expertise, `suggested` (specialisti proposti) e "
                     "`coordinator` (super-agent, opzionale). Read-only: NON invita "
                     "nessuno (l'invito lo conferma l'owner). Usalo quando l'owner "
                     "descrive un nuovo topic per proporgli chi coinvolgere."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"],
                     "description": "tier del topic (default SEAL-0)"},
            "description": {"type": "string",
                            "description": "di cosa tratta il topic, in linguaggio naturale"},
        }, "required": ["description"]},
    ),
    Tool(
        name="topic.add_participant",
        description=("Aggiunge un agente ai partecipanti di un topic/chat esistente "
                     "(lo 'invita nella stanza'). Puoi usarlo se sei owner, "
                     "partecipante o super-agent del topic. Decidi TU chi coinvolgere "
                     "leggendo runtime.agents (expertise/skill/clearance/costo); "
                     "l'idoneità SEAL è comunque applicata alla risposta."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string", "description": "slug del topic"},
            "agent": {"type": "string", "description": "nome dell'agent/utente da aggiungere"},
        }, "required": ["tier", "name", "agent"]},
    ),
    Tool(
        name="topic.remove_participant",
        description=("Rimuove un agente dai partecipanti di un topic/chat. Come "
                     "add_participant: owner|partecipante|super."),
        inputSchema={"type": "object", "properties": {
            "tier": {"type": "string", "enum": ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]},
            "name": {"type": "string"},
            "agent": {"type": "string"},
        }, "required": ["tier", "name", "agent"]},
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
         description="Introspezione runtime: gli agent dell'istanza col quadro COMPLETO per decidere chi coinvolgere (dominio/expertise, skill, knowledge RAG, clearance SEAL, provider effettivo + suo SEAL, modello, ruolo, stato). Solo metadati, mai segreti — la decisione è tua, non del tool.",
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
    Tool(name="runtime.restart_agent",
         description="OPS: riavvia le sessioni vive di un agente — ferma i suoi subprocess/runtime; alla prossima interazione la chat rimaterializza il seed da zero. Da usare per sbloccare un agente col runtime impuntato (es. sessione opencode persa, loop). I dati/la history persistono. Capacità di ops (sysadmin).",
         inputSchema={"type": "object", "properties": {
             "agent": {"type": "string", "description": "nome del seed da riavviare (es. 'impiegato-tomato')"}},
             "required": ["agent"]}),
    Tool(name="runtime.inspect_topic",
         description=("OPS/STEWARD: ispeziona UN topic specifico (di norma quello da cui "
                      "l'utente ti sta chiamando nel widget). Ritorna metadati (titolo, "
                      "stato, owner), gli AGENTI del topic e gli ULTIMI messaggi. NB: "
                      "vincolato alla tua clearance — se la tua SEAL effettiva è < tier "
                      "del topic ricevi 403 (il topic è invisibile). Usalo per capire il "
                      "contesto in cui stai assistendo l'utente (chi c'è, cosa si sono detti)."),
         inputSchema={"type": "object", "properties": {
             "tier": {"type": "string", "description": "tier del topic (es. SEAL-1)"},
             "name": {"type": "string", "description": "nome del topic"}},
             "required": ["tier", "name"]}),
]

# jobs.* — gestione dei job schedulati. La CREAZIONE non è diretta: si PROPONE
# e l'owner approva via link firmato (un job è esecuzione autonoma ricorrente →
# superficie di privilegio, deve passare dall'umano).
_JOBS_TOOLS: list[Tool] = [
    Tool(name="jobs.list",
         description="Elenca i job schedulati dell'istanza (cron + stato). Sola lettura.",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="jobs.propose",
         description=("PROPONE un nuovo job schedulato: NON lo crea. Registra una "
                      "proposta; il job nasce solo se l'owner approva. Il risultato "
                      "include `render_marker`: presenta il job all'utente e includi "
                      "quel marker in fondo al messaggio → comparirà un popup "
                      "Approva/Annulla in chat (conferma sincrona, l'owner è presente). "
                      "Usalo quando l'utente chiede di schedulare un'attività ricorrente "
                      "(report settimanale, promemoria, backup, ...). Fornisci una "
                      "descrizione della cadenza in linguaggio naturale (schedule_text) "
                      "oppure un cron a 5 campi (cron_expr)."),
         inputSchema={"type": "object", "properties": {
             "name": {"type": "string", "description": "nome univoco del job"},
             "prompt": {"type": "string", "description": "cosa deve fare l'agente al fire del job"},
             "schedule_text": {"type": "string", "description": "cadenza in linguaggio naturale (es. 'ogni lunedì alle 9')"},
             "cron_expr": {"type": "string", "description": "in alternativa, cron a 5 campi"},
             "agent": {"type": "string", "description": "agent (kind) che esegue il job al fire. Default: l'agente chiamante (te stesso). Indicane un altro solo se il job deve girare per conto di qualcun altro."},
             "enabled": {"type": "boolean", "description": "attivo alla creazione (default true)"},
         }, "required": ["name", "prompt"]}),
]

# packs.* — import/rimozione dei pack e loro dipendenze. Riservati a sysadmin.
_PACKS_TOOLS: list[Tool] = [
    Tool(name="packs.list",
         description="Elenca i pack installati (nome, versione, plugin/seed contenuti).",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="packs.show",
         description="Dettaglio di un pack installato per nome.",
         inputSchema={"type": "object", "properties": {
             "name": {"type": "string"}}, "required": ["name"]}),
    Tool(name="packs.import_url",
         description=("Importa un pack da URL (repo pubblico / zip remoto). L'import da "
                      "file .zip caricato resta un'operazione della UI (upload)."),
         inputSchema={"type": "object", "properties": {
             "url": {"type": "string"}}, "required": ["url"]}),
    Tool(name="packs.remove",
         description="Rimuove un pack installato per nome.",
         inputSchema={"type": "object", "properties": {
             "name": {"type": "string"}}, "required": ["name"]}),
    Tool(name="packs.setup_done",
         description=("Marca il SETUP di un pack come COMPLETATO: smarca il flag "
                      "'setup_pending' (la UI toglie il bottone «Finish setup»). Chiamalo "
                      "SOLO al termine del task di setup del pack (deps installate, MCP "
                      "montati, RAG provisionato e verificato)."),
         inputSchema={"type": "object", "properties": {
             "name": {"type": "string"}}, "required": ["name"]}),
    Tool(name="packs.install_pip",
         description=("Installa package pip dichiarati da un pack nel venv persistente "
                      "$CLODIA_DATA/runtime/venv. Non è shell libera: accetta solo spec "
                      "package/versione validate. Usa solo valori provenienti da "
                      "`requires.pip` del manifest curated."),
         inputSchema={"type": "object", "properties": {
             "packages": {"type": "array", "items": {"type": "string"}}},
             "required": ["packages"]}),
    Tool(name="packs.install_npm",
         description=("Installa package npm dichiarati da un pack nel prefix persistente "
                      "$CLODIA_DATA/runtime/npm. Non è shell libera: accetta solo spec "
                      "package/versione validate. Usa solo valori provenienti da "
                      "`requires.npm` del manifest curated."),
         inputSchema={"type": "object", "properties": {
             "packages": {"type": "array", "items": {"type": "string"}}},
             "required": ["packages"]}),
    Tool(name="packs.check_command",
         description=("Verifica che un binario richiesto dal pack sia disponibile nel "
                      "PATH runtime (venv/bin + npm/bin + PATH di sistema). Usalo per "
                      "`requires.bin` e `requires.system`."),
         inputSchema={"type": "object", "properties": {
             "command": {"type": "string"}}, "required": ["command"]}),
]

# workflows.* — controllo delle run dei workflow (start/stop/terminate). Sysadmin.
_WORKFLOWS_TOOLS: list[Tool] = [
    Tool(name="workflows.list",
         description="Elenca i workflow disponibili (per plugin) e le run recenti.",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="workflows.status",
         description="Stato di una run di workflow per run_id.",
         inputSchema={"type": "object", "properties": {
             "run_id": {"type": "string"}}, "required": ["run_id"]}),
    Tool(name="workflows.start",
         description="Avvia una run di un workflow (plugin/name). params è una stringa opzionale.",
         inputSchema={"type": "object", "properties": {
             "plugin": {"type": "string"}, "name": {"type": "string"},
             "title": {"type": "string"}, "params": {"type": "string"}},
             "required": ["plugin", "name"]}),
    Tool(name="workflows.cancel",
         description="Ferma/termina una run in esecuzione per run_id (con nota opzionale).",
         inputSchema={"type": "object", "properties": {
             "run_id": {"type": "string"}, "note": {"type": "string"}},
             "required": ["run_id"]}),
    Tool(name="workflows.delete_run",
         description="Elimina il record di una run di workflow per run_id.",
         inputSchema={"type": "object", "properties": {
             "run_id": {"type": "string"}}, "required": ["run_id"]}),
]

# providers.* — pausa/riattiva i provider di inferenza. MAI segreti/chiavi. Sysadmin.
_PROVIDERS_TOOLS: list[Tool] = [
    Tool(name="providers.list",
         description="Elenca i provider di inferenza e il loro stato (id/nome/meccanismo/connesso/pausa). MAI segreti.",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="providers.pause",
         description="Mette in pausa un provider (escluso dalla selezione; gli agent ripiegano sul prossimo). Non tocca la chiave.",
         inputSchema={"type": "object", "properties": {
             "provider_id": {"type": "string"}}, "required": ["provider_id"]}),
    Tool(name="providers.resume",
         description="Riattiva un provider in pausa.",
         inputSchema={"type": "object", "properties": {
             "provider_id": {"type": "string"}}, "required": ["provider_id"]}),
]

# integrations.* — osservazione dei connettori/integration (stato di connessione).
_INTEGRATIONS_TOOLS: list[Tool] = [
    Tool(name="integrations.list",
         description=("Osserva le integration/connettori e il loro stato di connessione "
                      "(id/nome/provider/connected). NON legge i dati che veicolano."),
         inputSchema={"type": "object", "properties": {}}),
]

# mcp.* — registra/rimuove/elenca i server MCP montati (gateway-local). Sysadmin.
_MCP_TOOLS: list[Tool] = [
    Tool(name="mcp.list",
         description="Elenca i server MCP disponibili (backend montati + namespace nativi).",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="mcp.add",
         description=("Registra uno o più server MCP da un config in stile mcp.json "
                      "(oggetto con chiave `mcpServers`). I segreti (secrets: {NAME: val}) "
                      "sono depositati nel vault, mai nel config. Stessa diligenza "
                      "supply-chain dei pack."),
         inputSchema={"type": "object", "properties": {
             "config": {"type": "object", "description": "config con mcpServers"},
             "secrets": {"type": "object", "description": "segreti {NAME: valore} da mettere nel vault"}},
             "required": ["config"]}),
    Tool(name="mcp.remove",
         description="Smonta un server MCP montato per nome (slug).",
         inputSchema={"type": "object", "properties": {
             "name": {"type": "string"}}, "required": ["name"]}),
]

# settings.* — superficie conversazionale per i settings della piattaforma
# (oggi: backup). SOLO super-agent. MAI segreti (passphrase/credenziali si
# impostano dalla pagina Settings via paste-key).
_IMAGE_TOOLS: list[Tool] = [
    Tool(
        name="image.generate",
        description=("Genera un'immagine PNG (OpenAI gpt-image) dal prompt e la salva "
                     "nei file del topic (files/<filename>). Usa la API key OpenAI del "
                     "vault (server-side, mai esposta). Ritorna il path del file salvato; "
                     "scaricabile via /files/download per portarlo nella working copy."),
        inputSchema={
            "type": "object",
            "properties": {
                "tier": {"type": "string", "description": "tier del topic in cui salvare"},
                "name": {"type": "string", "description": "nome del topic in cui salvare"},
                "prompt": {"type": "string", "description": "prompt fully-baked dell'immagine"},
                "filename": {"type": "string",
                             "description": "nome file PNG di destinazione (es. cover.png)"},
                "size": {"type": "string", "enum": ["1024x1024", "1536x1024", "1024x1536"],
                         "description": "default 1024x1024"},
                "quality": {"type": "string", "enum": ["low", "medium", "high", "auto"],
                            "description": "default auto"},
                "background": {"type": "string", "enum": ["opaque", "transparent", "auto"],
                               "description": "default auto"},
            },
            "required": ["tier", "name", "prompt", "filename"],
        }),
]

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
    Tool(name="gdrive.rename",
         description="Rinomina un file/cartella Drive (anche sui Shared Drive).",
         inputSchema={"type": "object", "properties": {
             "file_id": {"type": "string"}, "new_name": {"type": "string"},
             "account": {"type": "string"}},
             "required": ["file_id", "new_name"]}),
    Tool(name="gdrive.move",
         description=("Sposta un file/cartella in un'altra cartella Drive "
                      "(folder_id di destinazione; anche sui Shared Drive)."),
         inputSchema={"type": "object", "properties": {
             "file_id": {"type": "string"}, "folder_id": {"type": "string"},
             "account": {"type": "string"}},
             "required": ["file_id", "folder_id"]}),
]

# gcalendar.* — Google Calendar sulla stessa credenziale Workspace (scope calendar
# già incluso). Orari ISO8601/RFC3339 (es. 2026-07-22T15:00:00+02:00).
_GCALENDAR_TOOLS: list[Tool] = [
    Tool(name="gcalendar.list_calendars",
         description="Elenca i calendari accessibili con l'account Workspace.",
         inputSchema={"type": "object", "properties": {"account": {"type": "string"}}}),
    Tool(name="gcalendar.list_events",
         description=("Elenca eventi di un calendario in una finestra temporale. "
                      "time_min/time_max ISO8601; query = testo libero opzionale."),
         inputSchema={"type": "object", "properties": {
             "calendar_id": {"type": "string", "description": "default 'primary'"},
             "time_min": {"type": "string"}, "time_max": {"type": "string"},
             "query": {"type": "string"}, "limit": {"type": "integer"},
             "account": {"type": "string"}}}),
    Tool(name="gcalendar.create_event",
         description=("Crea un evento. start/end ISO8601 (dateTime) o date (YYYY-MM-DD "
                      "se all_day=true). attendees = lista di email."),
         inputSchema={"type": "object", "properties": {
             "summary": {"type": "string"}, "start": {"type": "string"},
             "end": {"type": "string"}, "calendar_id": {"type": "string"},
             "description": {"type": "string"}, "location": {"type": "string"},
             "attendees": {"type": "array", "items": {"type": "string"}},
             "all_day": {"type": "boolean"}, "account": {"type": "string"}},
             "required": ["summary", "start", "end"]}),
    Tool(name="gcalendar.update_event",
         description="Modifica un evento esistente (solo i campi passati).",
         inputSchema={"type": "object", "properties": {
             "event_id": {"type": "string"}, "calendar_id": {"type": "string"},
             "summary": {"type": "string"}, "start": {"type": "string"},
             "end": {"type": "string"}, "description": {"type": "string"},
             "location": {"type": "string"}, "account": {"type": "string"}},
             "required": ["event_id"]}),
    Tool(name="gcalendar.delete_event",
         description="Elimina un evento dal calendario.",
         inputSchema={"type": "object", "properties": {
             "event_id": {"type": "string"}, "calendar_id": {"type": "string"},
             "account": {"type": "string"}}, "required": ["event_id"]}),
    Tool(name="gcalendar.freebusy",
         description="Ritorna gli intervalli occupati (busy) in una finestra temporale.",
         inputSchema={"type": "object", "properties": {
             "time_min": {"type": "string"}, "time_max": {"type": "string"},
             "calendar_id": {"type": "string"}, "account": {"type": "string"}},
             "required": ["time_min", "time_max"]}),
]

# gdocs.* — Google Docs sulla stessa credenziale Workspace (scope documents).
_GDOCS_TOOLS: list[Tool] = [
    Tool(name="gdocs.create",
         description="Crea un Google Doc (opz. con testo iniziale). Ritorna id + url.",
         inputSchema={"type": "object", "properties": {
             "title": {"type": "string"}, "text": {"type": "string"},
             "account": {"type": "string"}}, "required": ["title"]}),
    Tool(name="gdocs.read",
         description="Legge il testo di un Google Doc (estratto plain-text).",
         inputSchema={"type": "object", "properties": {
             "document_id": {"type": "string"}, "account": {"type": "string"}},
             "required": ["document_id"]}),
    Tool(name="gdocs.append_text",
         description="Aggiunge testo in fondo a un Google Doc.",
         inputSchema={"type": "object", "properties": {
             "document_id": {"type": "string"}, "text": {"type": "string"},
             "account": {"type": "string"}}, "required": ["document_id", "text"]}),
    Tool(name="gdocs.replace_text",
         description="Sostituisce tutte le occorrenze di `find` con `replace` nel Doc.",
         inputSchema={"type": "object", "properties": {
             "document_id": {"type": "string"}, "find": {"type": "string"},
             "replace": {"type": "string"}, "match_case": {"type": "boolean"},
             "account": {"type": "string"}},
             "required": ["document_id", "find", "replace"]}),
]

# gsheets.* — Google Sheets on the same Workspace credential. The Sheets API
# accepts the `auth/drive` scope the connector already requests, so this needed
# no new consent (clodia-platform#118). Every verb is INCREMENTAL: before this,
# acting on a spreadsheet meant gdrive.download + gdrive.upload, which replaces
# the file and destroys the tabs the agent did not author.
_GSHEETS_TOOLS: list[Tool] = [
    Tool(name="gsheets.list_tabs",
         description=("Tab di un Google Sheet: titolo, id, posizione e dimensioni. "
                      "Da chiamare prima di leggere o scrivere, per sapere i nomi."),
         inputSchema={"type": "object", "properties": {
             "spreadsheet_id": {"type": "string"}, "account": {"type": "string"}},
             "required": ["spreadsheet_id"]}),
    Tool(name="gsheets.read",
         description=("Legge i valori di un range A1 (es. 'Foglio1!A1:D20') oppure di "
                      "un'intera tab. Senza range né tab legge la PRIMA tab. "
                      "formulas=true restituisce il TESTO delle formule invece del "
                      "valore calcolato: usalo se devi riprodurre il foglio, "
                      "altrimenti una formula ti torna come numero."),
         inputSchema={"type": "object", "properties": {
             "spreadsheet_id": {"type": "string"}, "range": {"type": "string"},
             "tab": {"type": "string"}, "formulas": {"type": "boolean"},
             "account": {"type": "string"}},
             "required": ["spreadsheet_id"]}),
    Tool(name="gsheets.add_tab",
         description=("Aggiunge una tab a un Google Sheet ESISTENTE lasciando intatte "
                      "le altre (mutazione, non riscrittura del file). Errore "
                      "azionabile se il titolo è già in uso."),
         inputSchema={"type": "object", "properties": {
             "spreadsheet_id": {"type": "string"}, "title": {"type": "string"},
             "index": {"type": "integer"}, "account": {"type": "string"}},
             "required": ["spreadsheet_id", "title"]}),
    Tool(name="gsheets.append_rows",
         description=("Aggiunge righe DOPO l'ultima riga popolata di una tab: non "
                      "sovrascrive nulla. È la scrittura da preferire. I valori "
                      "entrano come se digitati (le formule restano formule)."),
         inputSchema={"type": "object", "properties": {
             "spreadsheet_id": {"type": "string"}, "tab": {"type": "string"},
             "rows": {"type": "array", "items": {"type": "array"}},
             "account": {"type": "string"}},
             "required": ["spreadsheet_id", "tab", "rows"]}),
    Tool(name="gsheets.write_range",
         description=("Scrive in un range A1 esplicito SOVRASCRIVENDO le celle "
                      "esistenti. Nessun default e nessuna scorciatoia su tab intera: "
                      "per aggiungere dati usa append_rows."),
         inputSchema={"type": "object", "properties": {
             "spreadsheet_id": {"type": "string"}, "range": {"type": "string"},
             "values": {"type": "array", "items": {"type": "array"}},
             "account": {"type": "string"}},
             "required": ["spreadsheet_id", "range", "values"]}),
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
         description=("Invia un messaggio a una chat/gruppo (lease-free: sei l'unico "
                      "mittente). Vincolo Telegram: la chat deve aver già contattato il "
                      "bot, o il bot dev'essere membro del gruppo. `chat_id` accetta anche "
                      "il NOME del gruppo."),
         inputSchema={"type": "object", "properties": {
             "chat_id": {"type": "string"}, "text": {"type": "string"}},
             "required": ["chat_id", "text"]}),
    Tool(name="telegram.send_file",
         description=("Invia un FILE del topic a una chat/gruppo Telegram come allegato "
                      "(o come foto se è un'immagine). Solo tu (messaggero) puoi spedire. "
                      "Passa `chat_id` (id o NOME del gruppo) e `path` (il file dentro il "
                      "topic, es. `files/foo.png`): il TOPIC si ricava dal gruppo. `tier`/"
                      "`name` solo se il file è in un topic diverso da quello del gruppo."),
         inputSchema={"type": "object", "properties": {
             "chat_id": {"type": "string", "description": "chat_id o nome del gruppo"},
             "path": {"type": "string", "description": "path del file nel topic, es. files/foo.png"},
             "tier": {"type": "string", "description": "opzionale (override topic)"},
             "name": {"type": "string", "description": "opzionale: nome del topic (override)"},
             "caption": {"type": "string"}},
             "required": ["chat_id", "path"]}),
    Tool(name="telegram.lease_release",
         description="Rilascia anticipatamente il lease su una chat (no-op se non lo detieni).",
         inputSchema={"type": "object", "properties": {
             "chat_id": {"type": "string"}}, "required": ["chat_id"]}),
    Tool(name="telegram.listen",
         description=("Collega una chat Telegram a un topic: da ora il messaggero ne "
                      "riporta VERBATIM i messaggi nella chat del topic, con l'handle "
                      "autenticato del mittente. Il messaggero NON esegue né risponde "
                      "ai messaggi: riportano soltanto, decidono gli agenti del topic. "
                      "Richiede che tu sia partecipante del topic. Binding a livello di "
                      "istanza: puoi ascoltare più chat."),
         inputSchema={"type": "object", "properties": {
             "tier": {"type": "string"}, "name": {"type": "string"},
             "chat_id": {"type": "string"}},
             "required": ["tier", "name", "chat_id"]}),
    Tool(name="telegram.unlisten",
         description=("Scollega una chat Telegram da un topic: il messaggero smette di "
                      "riportarne i messaggi. Simmetrico a telegram.listen."),
         inputSchema={"type": "object", "properties": {
             "tier": {"type": "string"}, "name": {"type": "string"},
             "chat_id": {"type": "string"}},
             "required": ["tier", "name", "chat_id"]}),
]


# memory.* — seed memory scrivibile dell'agente (universale, non richiede grant).
_MEMORY_TOOLS: list[Tool] = [
    Tool(name="memory.read",
         description=("Legge un file della tua seed memory (default `MEMORY.md`, la tua "
                      "memoria di note/esperienza sempre disponibile). La memory è "
                      "condivisa fra le tue istanze."),
         inputSchema={"type": "object", "properties": {
             "filename": {"type": "string", "description": "default MEMORY.md"}}}),
    Tool(name="memory.write",
         description=("Scrive (sovrascrive) un file della tua seed memory. Usa per "
                      "aggiornare note durature o dati strutturati (es. una whitelist "
                      "JSON). Cap 64KB per file."),
         inputSchema={"type": "object", "properties": {
             "content": {"type": "string"},
             "filename": {"type": "string", "description": "default MEMORY.md"}},
             "required": ["content"]}),
    Tool(name="memory.append",
         description="Aggiunge una nota in coda a un file della seed memory (default MEMORY.md).",
         inputSchema={"type": "object", "properties": {
             "content": {"type": "string"},
             "filename": {"type": "string", "description": "default MEMORY.md"}},
             "required": ["content"]}),
    Tool(name="memory.list",
         description="Elenca i file di NOTE (testo) nella tua seed memory.",
         inputSchema={"type": "object", "properties": {}}),
    # Document store per-seed: DOCUMENTI (PDF/docx/dataset…) che sopravvivono agli
    # spawn, in agents/<seed>/files/. NON caricati in automatico: leggili su richiesta.
    Tool(name="memory.put_document",
         description=("Salva un DOCUMENTO (PDF, docx, xlsx, dataset, immagine…) nella tua "
                      "libreria personale del seed (persistente, sopravvive agli spawn). "
                      "content_b64 = contenuto in base64. Max 25MB. ⚠️ SOLO per file "
                      "PICCOLI: per binari o file grandi usa memory.put (byte dallo "
                      "scratch, niente base64 nel modello)."),
         inputSchema={"type": "object", "properties": {
             "filename": {"type": "string"}, "content_b64": {"type": "string"}},
             "required": ["filename", "content_b64"]}),
    Tool(name="memory.put",
         description=("Salva un file (anche BINARIO/GRANDE) nella tua libreria del seed "
                      "leggendo i BYTE dal tuo scratch — niente base64 nel modello (come "
                      "topic.put). USA QUESTO per PDF/immagini/file grandi. src = path "
                      "assoluto del file nel tuo scratch; filename = nome nella libreria."),
         inputSchema={"type": "object", "properties": {
             "filename": {"type": "string"}, "src": {"type": "string",
                 "description": "path assoluto del file nel tuo scratch"}},
             "required": ["filename", "src"]}),
    Tool(name="memory.fetch",
         description=("Scarica un DOCUMENTO della tua libreria nel TUO scratch (byte su "
                      "file, niente base64 nel modello — come topic.fetch). USA QUESTO al "
                      "posto di memory.get_document per binari/file grandi. filename = "
                      "nome nella libreria; dest = path assoluto nel tuo scratch."),
         inputSchema={"type": "object", "properties": {
             "filename": {"type": "string"}, "dest": {"type": "string",
                 "description": "path assoluto di destinazione nel tuo scratch"}},
             "required": ["filename", "dest"]}),
    Tool(name="memory.list_documents",
         description="Elenca i DOCUMENTI nella tua libreria del seed (nome + dimensione).",
         inputSchema={"type": "object", "properties": {}}),
    Tool(name="memory.read_document",
         description=("Legge un DOCUMENTO della tua libreria estraendone il TESTO "
                      "(PDF/docx/xlsx/txt/md → testo per l'uso). `max_chars` opzionale."),
         inputSchema={"type": "object", "properties": {
             "filename": {"type": "string"}, "max_chars": {"type": "integer"}},
             "required": ["filename"]}),
    Tool(name="memory.get_document",
         description=("Recupera un DOCUMENTO della libreria come base64 grezzo (per "
                      "ri-allegarlo o passarlo a un tool che accetta binari). ⚠️ SOLO "
                      "file PICCOLI: per binari/file grandi usa memory.fetch (byte nello "
                      "scratch)."),
         inputSchema={"type": "object", "properties": {
             "filename": {"type": "string"}}, "required": ["filename"]}),
    Tool(name="memory.delete_document",
         description="Rimuove un documento dalla tua libreria del seed.",
         inputSchema={"type": "object", "properties": {
             "filename": {"type": "string"}}, "required": ["filename"]}),
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
    # Autorizzazione GIÀ fatta a monte in call_tool: super-agent (bypass) OPPURE
    # verbo nella whitelist `tool_permissions` dell'agente (per-verbo) + M-gate.
    # NIENTE guard super-only qui: era ridondante e SBAGLIATO — ri-bloccava anche
    # chi ha il grant puntuale (es. sysadmin ha `settings.backup_run` per il
    # backup pre-flight delle migrazioni dati dei pack, ma non backup_set/get).
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
    if verb == "rename":
        return gd.rename(a["file_id"], a["new_name"], account=a.get("account"))
    if verb == "move":
        return gd.move(a["file_id"], a["folder_id"], account=a.get("account"))
    raise ValueError(f"unknown gdrive verb: {name}")


def _dispatch_gcalendar(name: str, a: dict):
    from .tools import gcalendar as gc
    verb = name.split(NS_SEP_DOT, 1)[1]
    if verb == "list_calendars":
        return gc.list_calendars(account=a.get("account"))
    if verb == "list_events":
        return gc.list_events(calendar_id=a.get("calendar_id", "primary"),
                              time_min=a.get("time_min"), time_max=a.get("time_max"),
                              query=a.get("query"), limit=a.get("limit", 25),
                              account=a.get("account"))
    if verb == "create_event":
        return gc.create_event(a["summary"], a["start"], a["end"],
                               calendar_id=a.get("calendar_id", "primary"),
                               description=a.get("description"), location=a.get("location"),
                               attendees=a.get("attendees"), all_day=a.get("all_day", False),
                               account=a.get("account"))
    if verb == "update_event":
        return gc.update_event(a["event_id"], calendar_id=a.get("calendar_id", "primary"),
                               summary=a.get("summary"), start=a.get("start"),
                               end=a.get("end"), description=a.get("description"),
                               location=a.get("location"), account=a.get("account"))
    if verb == "delete_event":
        return gc.delete_event(a["event_id"], calendar_id=a.get("calendar_id", "primary"),
                               account=a.get("account"))
    if verb == "freebusy":
        return gc.freebusy(a["time_min"], a["time_max"],
                           calendar_id=a.get("calendar_id", "primary"),
                           account=a.get("account"))
    raise ValueError(f"unknown gcalendar verb: {name}")


def _dispatch_gdocs(name: str, a: dict):
    from .tools import gdocs as gdo
    verb = name.split(NS_SEP_DOT, 1)[1]
    if verb == "create":
        return gdo.create(a["title"], text=a.get("text"), account=a.get("account"))
    if verb == "read":
        return gdo.read(a["document_id"], account=a.get("account"))
    if verb == "append_text":
        return gdo.append_text(a["document_id"], a["text"], account=a.get("account"))
    if verb == "replace_text":
        return gdo.replace_text(a["document_id"], a["find"], a["replace"],
                                match_case=a.get("match_case", True), account=a.get("account"))
    raise ValueError(f"unknown gdocs verb: {name}")


def _dispatch_gsheets(name: str, a: dict):
    from .tools import gsheets as gsh
    verb = name.split(NS_SEP_DOT, 1)[1]
    if verb == "list_tabs":
        return gsh.list_tabs(a["spreadsheet_id"], account=a.get("account"))
    if verb == "read":
        return gsh.read(a["spreadsheet_id"], range=a.get("range"), tab=a.get("tab"),
                        formulas=bool(a.get("formulas")), account=a.get("account"))
    if verb == "add_tab":
        return gsh.add_tab(a["spreadsheet_id"], a["title"], index=a.get("index"),
                           account=a.get("account"))
    if verb == "append_rows":
        return gsh.append_rows(a["spreadsheet_id"], a["tab"], a["rows"],
                               account=a.get("account"))
    if verb == "write_range":
        return gsh.write_range(a["spreadsheet_id"], a["range"], a["values"],
                               account=a.get("account"))
    raise ValueError(f"unknown gsheets verb: {name}")


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
    if verb == "send_file":
        # Legge il file dal topic (compartimento: dev'essere participant) e lo invia.
        # Il TOPIC si ricava dal gruppo (binding chat→topic), così basta chat + path;
        # `tier`/`name` sono override opzionali per topic diversi da quello del gruppo.
        import base64
        import os as _os
        from .tools import telegram_bindings as _tb
        cid = tg._resolve_chat(a["chat_id"])
        tier, tname = a.get("tier"), a.get("name")
        if not (tier and tname):
            b = _tb.get(cid)
            if not b:
                raise ValueError(f"chat {cid} non legata a un topic: passa tier+name del topic")
            tier, tname = b["tier"], b["topic"]
        _require_topic_member(_topics(), tier, tname)
        data = _topics().read_file(tier, tname, a["path"])
        return tg.send_file(cid, _os.path.basename(a["path"]),
                            base64.b64encode(data).decode("ascii"), a.get("caption", ""))
    if verb == "lease_release":
        return tg.lease_release(a["chat_id"])
    if verb in ("listen", "unlisten"):
        # Binding sull'ISTANZA del messaggero (telegram-bindings.json), NON nel
        # meta del topic. Il messaggero dev'essere partecipante del topic in cui
        # ripeterà. Enforcement compartimento come i topic.*.
        from .tools import telegram_bindings as tb
        from .topics.service import _check_channel_cap
        cid = str(a["chat_id"])
        tier, tname = a["tier"], a["name"]
        _require_topic_member(_topics(), tier, tname)
        if verb == "unlisten":
            return {"ok": True, "chat_id": cid, "removed": tb.remove(cid)}
        # listen: SEAL-cap (telegram cappa a SEAL-1) + una chat → un solo binding.
        meta = _topics().open(tier, tname).get("meta", {})
        _check_channel_cap({"type": "telegram"}, meta.get("tier", tier))
        ex = tb.get(cid)
        if ex and (ex.get("tier"), ex.get("topic")) != (tier, tname):
            raise ValueError(
                f"chat {cid} già collegata a {ex.get('tier')}/{ex.get('topic')}: "
                f"fai prima telegram.unlisten lì (una chat → un solo topic)")
        tb.set_binding(cid, agent_name(), tier, tname)
        return {"ok": True, "chat_id": cid, "instance": agent_name(),
                "topic": f"{tier}/{tname}"}
    raise ValueError(f"unknown telegram verb: {name}")


def _dispatch_memory(name: str, a: dict):
    from .tools import memory as mem
    verb = name.split(NS_SEP_DOT, 1)[1]
    if verb == "read":
        return mem.read(a.get("filename"))
    if verb == "write":
        return mem.write(a["content"], a.get("filename"))
    if verb == "append":
        return mem.append(a["content"], a.get("filename"))
    if verb == "list":
        return mem.list_files()
    # ── Document store per-seed ──────────────────────────────────────────────
    if verb == "put_document":
        return mem.put_document(a["filename"], a["content_b64"])
    if verb == "put":
        # Byte dallo scratch dell'agent → libreria del seed (niente base64 nel
        # modello). Il gateway legge il file locale; path validato sotto spawns/.
        src = _safe_scratch_path(a["src"])
        with open(src, "rb") as f:
            data = f.read()
        return mem.put_document_bytes(a["filename"], data)
    if verb == "fetch":
        # Documento del seed → file nello scratch dell'agent (niente base64).
        fn, data = mem.read_document_bytes(a["filename"])
        dest = _safe_scratch_path(a["dest"])
        _os.makedirs(_os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data)
        return {"file": fn, "bytes": len(data), "dest": dest, "ok": True}
    if verb == "list_documents":
        return mem.list_documents()
    if verb == "read_document":
        fn, data = mem.read_document_bytes(a["filename"])
        cap = int(a.get("max_chars") or 60000)
        try:
            text, pages = _extract_document_text(fn, data)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"estrazione fallita: {str(e)[:160]}"}
        return {"file": fn, "text": text[:cap], "chars": len(text),
                "pages": pages, "truncated": len(text) > cap}
    if verb == "get_document":
        import base64 as _b64
        fn, data = mem.read_document_bytes(a["filename"])
        return {"file": fn, "bytes": len(data), "encoding": "base64",
                "content_b64": _b64.b64encode(data).decode("ascii")}
    if verb == "delete_document":
        return mem.delete_document(a["filename"])
    raise ValueError(f"unknown memory verb: {name}")


def _native_tool_namespaces() -> list[str]:
    """Namespace dei tool nativi del gateway (per agents.list_tools)."""
    tools = (_FS_TOOLS + _WEB_TOOLS + _LOGS_TOOLS + _EMAIL_TOOLS + _TRELLO_TOOLS + _TOPIC_TOOLS + _IMAGE_TOOLS
             + _RUNTIME_TOOLS + _JOBS_TOOLS + _PROFILE_TOOLS + _TELEGRAM_TOOLS + _MEMORY_TOOLS + _GDRIVE_TOOLS
             + _GCALENDAR_TOOLS + _GDOCS_TOOLS + _GSHEETS_TOOLS + _AGENT_TOOLS
             + _PACKS_TOOLS + _WORKFLOWS_TOOLS + _PROVIDERS_TOOLS + _INTEGRATIONS_TOOLS + _MCP_TOOLS)
    if instance_profile.rag_enabled():
        tools = tools + _EU_CORPUS_TOOLS + _RAG_TOOLS
    ns = sorted({t.name.split(NS_SEP_DOT, 1)[0] for t in tools})
    return ns


def runtime_configuration_warnings() -> list[str]:
    """Coerenza fra whitelist, namespace montati e credenziali consumabili."""
    from .whitelist import CONFIG

    mounted = set(_native_tool_namespaces())
    mounted.update(
        str(backend.get("name") or "")
        for backend in (CONFIG.get("mcp_backends") or [])
    )
    warnings = []
    for agent, spec in (CONFIG.get("agents") or {}).items():
        for tool in spec.get("allowed_tools") or []:
            if tool == "*" or NS_SEP_DOT not in tool:
                continue
            namespace = tool.split(NS_SEP_DOT, 1)[0]
            if namespace not in mounted:
                warnings.append(
                    f"agent '{agent}': namespace '{namespace}' in whitelist "
                    "ma non esposto da tool nativi o backend MCP"
                )
    for row in email.credential_diagnostics():
        if row["operational"]:
            continue
        detail = (
            f"campi mancanti: {', '.join(row['missing'])}"
            if row["missing"] else f"errore: {row['error']}"
        )
        warnings.append(
            f"credenziale email '{row['credential']}' non materializzabile ({detail})"
        )
    return warnings


def _dispatch_agents(name: str, a: dict, caller: str | None,
                     gate_approval: dict | None = None):
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
    if verb == "grant_scoped":
        token = (gate_approval or {}).get("token")
        if not token:
            raise PermissionError("agents.grant_scoped richiede approvazione firmata one-shot")
        return adm.grant_scoped(a["agent"], a, token)
    if verb == "list_scoped":
        return adm.list_scoped(a["agent"])
    if verb == "revoke_scoped":
        token = (gate_approval or {}).get("token")
        if not token:
            raise PermissionError("agents.revoke_scoped richiede approvazione firmata one-shot")
        return adm.revoke_scoped(a["agent"], a["override_id"], token)
    raise ValueError(f"unknown agents verb: {name}")


def _dispatch_runtime(name: str, arguments: dict, caller: str | None = None):
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
    if sub == "restart_agent":
        return runtime.restart_agent(arguments.get("agent"))
    if sub == "inspect_topic":
        return runtime.inspect_topic(arguments.get("tier"), arguments.get("name"),
                                     by=caller or "")
    raise ValueError(f"unknown runtime tool: {name}")


def _dispatch_jobs(name: str, a: dict, caller: str | None):
    sub = name.split(NS_SEP_DOT, 1)[1]
    if sub == "list":
        return runtime.jobs()
    if sub == "propose":
        # l'agente PROPONE un job → l'owner approva via gate. `requested_by` è
        # l'identità del chiamante, impostata qui (non fidarsi dell'input).
        # NB: NESSUN create/delete diretto — anche gli agent di piattaforma
        # (sysadmin) passano dal gate owner. La creazione autonoma ricorrente è
        # superficie di privilegio: deve confermarla l'owner (Prima Legge).
        return runtime.propose_job(
            name=a.get("name"), prompt=a.get("prompt"),
            schedule_text=a.get("schedule_text"), cron_expr=a.get("cron_expr"),
            # default = l'agente CHIAMANTE (non clodia): chi propone un job
            # ricorrente di norma lo esegue lui stesso (es. messaggero/check-email).
            # Evita che l'executor "scivoli" a clodia quando l'agent è omesso.
            agent=a.get("agent") or caller or "clodia", enabled=a.get("enabled", True),
            requested_by=caller or "agente")
    raise ValueError(f"unknown jobs tool: {name}")


def _dispatch_packs(name: str, a: dict):
    from .tools import platform_ops as ops
    from .tools import pack_runtime
    sub = name.split(NS_SEP_DOT, 1)[1]
    if sub == "list":
        return ops.packs_list()
    if sub == "show":
        return ops.packs_show(a["name"])
    if sub == "import_url":
        return ops.packs_import_url(a["url"])
    if sub == "remove":
        return ops.packs_remove(a["name"])
    if sub == "setup_done":
        return ops.packs_setup_done(a["name"])
    if sub == "install_pip":
        return pack_runtime.install_pip(a["packages"])
    if sub == "install_npm":
        return pack_runtime.install_npm(a["packages"])
    if sub == "check_command":
        return pack_runtime.check_command(a["command"])
    raise ValueError(f"unknown packs tool: {name}")


def _dispatch_workflows(name: str, a: dict):
    from .tools import platform_ops as ops
    sub = name.split(NS_SEP_DOT, 1)[1]
    if sub == "list":
        return ops.workflows_list()
    if sub == "status":
        return ops.workflows_status(a["run_id"])
    if sub == "start":
        return ops.workflows_start(a["plugin"], a["name"],
                                   title=a.get("title", ""), params=a.get("params", ""))
    if sub == "cancel":
        return ops.workflows_cancel(a["run_id"], note=a.get("note", ""))
    if sub == "delete_run":
        return ops.workflows_delete_run(a["run_id"])
    raise ValueError(f"unknown workflows tool: {name}")


def _dispatch_providers(name: str, a: dict):
    from .tools import platform_ops as ops
    sub = name.split(NS_SEP_DOT, 1)[1]
    if sub == "list":
        return ops.providers_list()
    if sub == "pause":
        return ops.providers_pause(a["provider_id"])
    if sub == "resume":
        return ops.providers_resume(a["provider_id"])
    raise ValueError(f"unknown providers tool: {name}")


def _dispatch_integrations(name: str, a: dict):
    from .tools import platform_ops as ops
    sub = name.split(NS_SEP_DOT, 1)[1]
    if sub == "list":
        return ops.integrations_list()
    raise ValueError(f"unknown integrations tool: {name}")


def _dispatch_mcp(name: str, a: dict):
    """mcp.* — montaggio server MCP (gateway-local, via tools_api core)."""
    from . import tools_api
    sub = name.split(NS_SEP_DOT, 1)[1]
    if sub == "list":
        return runtime.mcp_servers()
    if sub == "add":
        try:
            return tools_api.register_mcp_core(a["config"], a.get("secrets") or {})
        except tools_api.McpRegisterError as e:
            raise PermissionError(str(e)) if getattr(e, "status", 400) == 403 else ValueError(str(e))
    if sub == "remove":
        return tools_api.unregister_mcp_core(a["name"])
    raise ValueError(f"unknown mcp tool: {name}")


# Super-agent nativi: hanno accesso a TUTTI i tool (inclusi i connettori/email
# delegati), bypassando la whitelist per-agent.
_SUPER_AGENTS = {"clodia", "ophelia"}


def _is_super(name: str | None) -> bool:
    return (name or "") in _SUPER_AGENTS


def _human_tool_allowed(name: str) -> bool:
    """RBAC UMANA (chiamata on-behalf): il gateway è il PDP unico anche per gli
    umani. Un tool `super-only` (packs/providers/mcp/agents/settings/pki/ca…,
    definita da M-gate) richiede ruolo **admin**; tutto il resto è concesso a
    qualunque umano autenticato. Il ruolo è un claim FIRMATO dall'agent-server →
    non forgiabile dal modello. Chiude la Broken Access Control del path REST."""
    from . import gate as _gate
    if _gate.is_gated(name):
        return (current_human_role() or "user") == "admin"
    return True


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
    - email.*      se l'agent ha un grant su un account gmail_<account>;
    - trello.*     se l'agent ha un grant sulla credenziale 'trello'.
    - gdrive.*     se l'agent ha un grant google_/gworkspace_;
    - gcalendar.*  idem (stessa credenziale Google Workspace);
    - gdocs.*      idem.
    - gsheets.*    idem (l'API Sheets accetta lo scope `drive`).
    Così la delega non dipende da config.yaml (effimero al rebuild)."""
    grants = _vault_grants(agent)
    # La credenziale Google UNIFICATA (google_<account>) abilita SIA email.* SIA
    # gdrive.* (ha entrambi gli scope); i legacy gmail_/gworkspace_ restano validi.
    if name.startswith("email.") and any(
            c.startswith("google_") or c.startswith("gmail_") or c.startswith("mailbox_")
            for c in grants):
        return True
    if name.startswith("trello.") and "trello" in grants:
        return True
    if name.startswith("telegram.") and "telegram_bot_token" in grants:
        return True
    _gws_grant = any(c.startswith("google_") or c.startswith("gworkspace_") for c in grants)
    if name.startswith(("gdrive.", "gcalendar.", "gdocs.", "gsheets.")) and _gws_grant:
        return True
    return False


def _email_account(arguments: dict) -> str:
    """Account per una chiamata email.*: quello richiesto esplicitamente,
    altrimenti l'UNICO account operativo con grant vault. Con zero o più account
    solleva un errore azionabile: nessun fallback verso mailbox inesistenti."""
    agent = agent_name()
    accounts = email.available_accounts(agent)
    acct = (arguments.get("account") or "").strip()
    if acct:
        if acct in accounts:
            return acct
        raise ValueError(
            f"email: account '{acct}' non disponibile per '{agent}'. "
            f"Passa il parametro 'account' con uno di questi valori: {accounts}"
        )
    if len(accounts) == 1:
        return accounts[0]
    if not accounts:
        raise ValueError(
            f"email: nessun account operativo con grant per '{agent}'. "
            "Configura una mailbox e assegna il relativo grant nel vault."
        )
    raise ValueError(
        "email: il parametro 'account' è obbligatorio quando sono disponibili "
        f"più mailbox. Valori accettati: {accounts}"
    )


# Namespace UNIVERSALI: disponibili a OGNI agente senza grant per-agente.
# `memory` = la seed memory dell'agente stesso (scoped alla sua sola cartella),
# accumulo di esperienza scrivibile da tutti (inclusi i nativi).
_UNIVERSAL_NS = {"memory"}


def _tool_allowed(name: str, allowed: set) -> bool:
    """True se il tool è in whitelist. Supporta il wildcard ``<backend>.*`` che
    concede TUTTI i tool di un backend MCP montato (usato dall'Add-MCP UI)."""
    if NS_SEP_DOT in name and name.split(NS_SEP_DOT, 1)[0] in _UNIVERSAL_NS:
        return True
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
        allowed = set(agent_config().get("allowed_tools", [])) | set(current_scoped_tools())
    except PermissionError:
        return []
    native = list(_FS_TOOLS + _WEB_TOOLS + _LOGS_TOOLS + _EMAIL_TOOLS + _TRELLO_TOOLS + _TOPIC_TOOLS + _IMAGE_TOOLS + _RUNTIME_TOOLS + _JOBS_TOOLS + _SETTINGS_TOOLS + _PROFILE_TOOLS + _TELEGRAM_TOOLS + _MEMORY_TOOLS + _GDRIVE_TOOLS + _GCALENDAR_TOOLS + _GDOCS_TOOLS + _GSHEETS_TOOLS + _AGENT_TOOLS
                  + _PACKS_TOOLS + _WORKFLOWS_TOOLS + _PROVIDERS_TOOLS + _INTEGRATIONS_TOOLS + _MCP_TOOLS)
    # Feature `rag` (profilo istanza): off → i verbi rag.*/eu_corpus.* non
    # esistono proprio (né in lista né al dispatch).
    if instance_profile.rag_enabled():
        native += list(_EU_CORPUS_TOOLS + _RAG_TOOLS)
    # C1: tool dei backend MCP montati (namespaced), aggregati dal proxy.
    try:
        proxied = await proxy.list_proxied_tools()
    except Exception:
        proxied = []
    me = agent_name()
    if is_on_behalf():
        # Umano: vede i tool consentiti dal suo RUOLO (admin = tutti; user = solo
        # non super-only). Stesso PDP del dispatch.
        return [t for t in (native + proxied) if _human_tool_allowed(t.name)]
    if _is_super(me):
        return native + proxied  # super-agent: accesso a tutto
    return [t for t in (native + proxied)
            if _tool_allowed(t.name, allowed) or _connector_allows(t.name, me)]


def _gate_notify_principal(agent: str, gate_key: str, principal: str | None) -> bool:
    """Notifica best-effort un gate in attesa al PRINCIPAL sui suoi canali di contatto
    (telegram/email dalla scheda agent). Se il principal non è umano/assente, ripiega
    sul superadmin umano dell'istanza. Non solleva mai (best-effort)."""
    try:
        import httpx as _hx
        from .tools.runtime import AGENT_SERVER_URL
        with _hx.Client(timeout=6.0) as c:
            data = c.get(f"{AGENT_SERVER_URL}/api/agents").json()
        rows = data.get("agents", data) if isinstance(data, dict) else data
        by_name = {a.get("name"): a for a in rows}
        target = by_name.get(principal) if principal else None
        if not target or target.get("type") != "human":
            target = next((a for a in rows if a.get("type") == "human"
                           and a.get("role") == "superadmin"),
                          next((a for a in rows if a.get("type") == "human"), None))
        if not target:
            return False
        ch = target.get("contact_channels") or {}
        tg_id = ch.get("telegram") or target.get("telegram")
        msg = (f"🔐 Gate in attesa: '{agent}' vuole usare `{gate_key}` (azione non "
               f"presidiata). Approva/nega dalla sezione gate della webui.")
        if tg_id:
            from .tools import telegram as _tg
            _tg.send(str(tg_id), msg)
            return True
    except Exception:  # noqa: BLE001 — notifica best-effort, mai bloccante
        pass
    return False


def _reply_recipient(arguments: dict) -> str:
    """Destinatario reale di un `email.reply`, letto dal messaggio originale.

    Stringa vuota se non risolvibile → `egress.check` la tratta come
    destinazione ignota e nega. È la direzione d'errore giusta: «l'attaccante
    scrive, l'agente risponde con i dati» è il percorso dell'injection, e non
    sapere a chi si sta rispondendo non è una buona ragione per procedere.
    """
    try:
        msg = email.read_message(
            str(arguments.get("email_id") or ""),
            account=_email_account(arguments),
            folder=arguments.get("folder") or "INBOX")
    except Exception as e:  # noqa: BLE001 — non risolvibile ≠ consentito
        LOG.warning("egress: destinatario di email.reply non risolvibile (%s)", e)
        return ""
    from . import egress as _eg
    src = msg.get("from") or (msg.get("message") or {}).get("from") or ""
    return _eg.address_of(str(src))


async def _require_gate_consent(
    agent: str, gate_key: str, *, consume: bool, reason: str = "",
    allow_delegation: bool = True,
) -> dict | None:
    """Block-and-wait sul consenso di gate per (agent, gate_key). Se assente crea
    la richiesta (popup) e ATTENDE la decisione umana (~180s), poi procede; solleva
    su diniego o timeout. `consume`=True → one-shot (verbi); False → time-boxed
    (cross-topic: l'intera operazione sul topic vale finché dura il consenso)."""
    from . import gate as _gate
    inst = "-"
    # DELEGA PERMANENTE (async·A): se esiste una delega firmata dall'utente il cui
    # scope copre questa azione (verb == gate_key), è già autorizzata → unlock senza
    # richiesta né blocco. Modello: delega → verifica firma (CA) → covers → unlock.
    if allow_delegation:
        try:
            from . import delegation as _deleg
            _d = _deleg.find_covering(agent, gate_key)
            if _d:
                import logging as _lg
                _lg.getLogger("clodia-tools").info(
                    "gate '%s' autorizzato da delega permanente di '%s'",
                    gate_key, _d.get("principal"))
                return {"delegated": True, "principal": _d.get("principal")}
        except Exception:  # noqa: BLE001 — la delega è additiva: su errore, gate normale
            pass
    if not _gate.active(agent, inst, gate_key):
        req = _gate.request(agent, inst, gate_key, context=current_chat(),
                            human=current_principal(), chat=current_chat(),
                            reason=reason)
        # UX inline: se l'azione parte da un CANALE (chat=chan:tier:name:...),
        # posta un marker nel canale → il webui rende la card Approva/Nega
        # NELLA conversazione (come job-proposal), non nel popup staccato. I gate
        # senza contesto-canale restano gestiti dal popup di fallback.
        _ch = current_chat() or ""
        if _ch.startswith("chan:"):
            try:
                _parts = _ch.split(":")
                _tier, _name = _parts[1], _parts[2]
                # kind=ai (non system): i system sono filtrati dal render del webui.
                _topics().post_message(_tier, _name, author="gate",
                                       text=f"<!-- gate={req.get('id')} -->", kind="ai")
            except Exception:  # noqa: BLE001 — il gate resta valido anche senza marker
                pass
        # Gate NON presidiato (nessun contesto-canale, es. turno di un job agentico):
        # oggi resterebbe silenzioso e scadrebbe → notifica best-effort al PRINCIPAL
        # (Davide) sui suoi CANALI DI CONTATTO (telegram/email dalla scheda agent),
        # così può approvarlo dalla webui. Finestra d'attesa più lunga per l'async.
        # (Additivo: try/except non tocca la decisione del gate.)
        import os as _os
        loops = int(_os.environ.get("GATE_WAIT_LOOPS", "90"))  # 90 = ~180s
        if not _ch.startswith("chan:"):
            loops = int(_os.environ.get("GATE_WAIT_LOOPS_ASYNC", "3600"))  # ~2 ore (loop 2s)
            _gate_notify_principal(agent, gate_key, current_principal())
        import asyncio as _aio
        approved = False
        for _ in range(loops):
            await _aio.sleep(2)
            if _gate.active(agent, inst, gate_key):
                approved = True
                break
            if not _gate.request_pending(agent, inst, gate_key):
                raise PermissionError(f"gate: '{gate_key}' negato dall'operatore")
        if not approved:
            _gate.resolve_request(agent, inst, gate_key)
            raise PermissionError(f"gate: '{gate_key}' non approvato entro il tempo limite")
    approval = _gate.details(agent, inst, gate_key)
    if not approval:
        raise PermissionError(f"gate: capability per '{gate_key}' non disponibile")
    if consume:
        _gate.consume(agent, inst, gate_key)
    return approval


def _cross_topic_gate_key(name: str, arguments: dict, agent: str) -> str | None:
    """Chiave di gate per l'accesso CROSS-TOPIC: se `name` è un verbo topic-scoped
    e l'agente NON è participant/owner del topic target → ritorna
    'topic-access:<tier>/<name>'. La membership del principal umano non concede
    accesso implicito all'agente: il consenso passa sempre dal gate esplicito."""
    if NS_SEP_DOT not in name:
        return None
    ns, verb = name.split(NS_SEP_DOT, 1)
    if ns != "topic" or verb not in _TOPIC_SCOPED_VERBS:
        return None
    tier, tname = arguments.get("tier"), arguments.get("name")
    if not (tier and tname):
        return None
    try:
        meta = _topics().open(tier, tname).get("meta", {})
    except Exception:  # noqa: BLE001 — topic inesistente → lascia decidere al dispatch
        return None
    return (None if _topic_is_member(meta, agent)
            else f"topic-access:{meta.get('tier', tier)}/{tname}")


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        # Enforcement whitelist per-richiesta: in HTTP multi-agente non basta
        # il filtro di list_tools (un client può invocare un tool non elencato).
        # I super-agent (clodia/ophelia) bypassano: accesso a tutti i tool. I
        # tool dei connettori (email.*, trello.*) sono concessi anche a chi ha il
        # relativo grant nel vault (delega per-agent, persistente).
        _ag = agent_name()
        if is_on_behalf():
            # Richiesta ON-BEHALF di un umano: autorizza sul RUOLO umano (PDP
            # unico), NON sul carrier-agent. Un umano non-admin non può invocare
            # i tool super-only anche se il carrier è clodia (super).
            if not _human_tool_allowed(name):
                raise PermissionError(
                    f"tool '{name}' riservato agli admin (umano '{current_principal()}' "
                    f"ruolo '{current_human_role() or 'user'}')")
        elif not _is_super(_ag) and not _tool_allowed(
                name, set(agent_config().get("allowed_tools", [])) | set(current_scoped_tools())) \
                and not _connector_allows(name, _ag):
            raise PermissionError(
                f"tool '{name}' non in whitelist per agent '{_ag}'")
        # M-gate: conferma umana su azioni sotto supervisione — UN SOLO meccanismo.
        # (a) VERBI gated (packs/mcp/agents/…): consenso one-shot per-verbo.
        # (b) CROSS-TOPIC: un agente che tocca un topic di cui NON è participant
        #     richiede un consenso per-topic (time-boxed, così l'intera operazione
        #     cross-topic procede). Sostituisce il vecchio sudo cross-topic.
        # Il gate non concede nuovi tool: per il cross-topic apre soltanto il
        # compartimento target, sempre entro clearance e whitelist già verificate.
        gate_approval = None
        if not is_on_behalf():
            from . import gate as _gate
            if _gate.is_gated(name):
                reason = web_post.gate_summary(arguments) if name == "web.post" else ""
                gate_approval = await _require_gate_consent(
                    _ag, name, consume=True, reason=reason,
                    allow_delegation=name not in {
                        "web.post", "agents.grant_scoped", "agents.revoke_scoped"},
                )
            _ck = _cross_topic_gate_key(name, arguments, _ag)
            if _ck:
                await _require_gate_consent(_ag, _ck, consume=False)
        # WHITELIST DI DESTINAZIONE (clodia-platform#104 §7, passo 5). Uscita da
        # capacità binaria a capacità circoscritta: «può inviare mail» diventa
        # «può inviare mail a queste destinazioni». Dopo il gate, non prima: se
        # il verbo è gated l'umano ha già visto la richiesta, e il verdetto sulla
        # destinazione è l'ultima cosa che deve poter fermare la chiamata.
        # Default `report`: decide e logga senza bloccare, perché la lista vera
        # delle destinazioni si impara dal traffico reale — è così che sono state
        # trovate le quattro lacune della whitelist di rete.
        # NON si applica alle richieste on-behalf: l'utente autenticato dall'UI
        # è trusted (§2), e una sua mail non è un'uscita dell'agente — è la sua.
        if not is_on_behalf():
            from . import egress as _egress
            try:
                _acfg = agent_config(_ag) if _ag else {}
            except KeyError:
                # Agent non in config (clone, connettore): nessuna regola
                # dichiarata → decide `egress.check`. Non si inventa un default
                # permissivo.
                _acfg = {}
            # `email.reply` non ha il destinatario negli argomenti: viene dal
            # messaggio a cui risponde, cioè da contenuto non fidato. Senza
            # risolverlo il verdetto sarebbe «destinazione ignota → nego», che
            # romperebbe il caso d'uso legittimo (un messaggero risponde alla
            # posta in arrivo: è il suo lavoro). Si risolve qui, al call-site,
            # con una lettura in più che avviene SOLO per questo verbo.
            _eargs = arguments
            if name == "email.reply" and not (arguments.get("to") or ""):
                _eargs = {**arguments, "to": _reply_recipient(arguments)}
            _ev = _egress.check(_ag or "", _acfg, name, _eargs)
            if _ev.get("action") == "deny":
                raise _egress.denied_error(_ag or "", _ev)
            if _ev.get("action") == "gate":
                # Destinazione non vagliata → si CHIEDE, non si rifiuta. La
                # whitelist nasce vuota e si popola con l'uso (decisione del
                # 3 ago 2026): approvando, l'invio procede e la destinazione
                # resta ammessa. Il gate è sulla DESTINAZIONE, non sul verbo:
                # «scrivi a mario@x.it» è la domanda che l'umano sa valutare,
                # «puoi mandare mail» no.
                await _require_gate_consent(
                    _ag, _ev["gate_key"], consume=True,
                    reason=_ev.get("gate_reason", ""),
                    # Nessuna delega prefirmata su una destinazione nuova: è
                    # l'atto che la rende silenziosa per sempre (§7 proprietà 2),
                    # e una delega la renderebbe silenziosa senza che nessuno la
                    # veda mai.
                    allow_delegation=False)
                _egress.remember(_ag or "", _ev["type"], _ev.get("remember") or [])
        if name == "fs.list_dir":
            result = fs.list_dir(arguments["path"])
        elif name == "web.post":
            result = await asyncio.to_thread(web_post.post, arguments, agent=_ag or "")
        elif name == "logs.tail":
            result = logs.tail(arguments.get("lines", 100), arguments.get("level", ""))
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
        elif name == "email.save_attachment":
            # I byte dell'allegato NON passano dal modello: decodifica server-side
            # e scrittura nello scratch validato (come topic.fetch).
            dest = _safe_scratch_path(arguments["dest"])
            raw, meta = email.get_attachment_bytes(
                arguments["email_id"],
                arguments["filename"],
                account=_email_account(arguments),
                folder=arguments.get("folder", "INBOX"),
            )
            _os.makedirs(_os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(raw)
            result = {"local_path": dest, "size": len(raw), **meta}
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
            # offload su thread: _dispatch_topic tocca lo storage e (suggest_team/
            # participants) fa httpx SINCRONO all'agent-server. Se girasse
            # nell'event loop lo bloccherebbe → deadlock bilaterale con
            # topics_client (agent-server → gateway, anch'esso sync). to_thread
            # propaga i contextvars → agent_name() resta valido.
            result = await asyncio.to_thread(_dispatch_topic, name, arguments)
        elif name.startswith("image."):
            result = await _dispatch_image(arguments)
        elif name.startswith("artifact."):
            result = _dispatch_artifact(arguments)
        elif name.startswith("profile."):
            result = _dispatch_profile(name, arguments, _ag)
        elif name.startswith("settings."):
            result = _dispatch_settings(name, arguments, _ag)
        elif name.startswith("telegram."):
            result = _dispatch_telegram(name, arguments)
        elif name.startswith("memory."):
            result = _dispatch_memory(name, arguments)
        elif name.startswith("gdrive."):
            result = _dispatch_gdrive(name, arguments)
        elif name.startswith("gcalendar."):
            result = _dispatch_gcalendar(name, arguments)
        elif name.startswith("gdocs."):
            result = _dispatch_gdocs(name, arguments)
        elif name.startswith("gsheets."):
            result = _dispatch_gsheets(name, arguments)
        elif name.startswith("runtime."):
            # proxy httpx SINCRONO all'agent-server → offload su thread (no blocco loop)
            result = await asyncio.to_thread(_dispatch_runtime, name, arguments, _ag)
        elif name.startswith("jobs."):
            result = await asyncio.to_thread(_dispatch_jobs, name, arguments, _ag)
        elif name.startswith("packs."):
            result = await asyncio.to_thread(_dispatch_packs, name, arguments)
        elif name.startswith("workflows."):
            result = await asyncio.to_thread(_dispatch_workflows, name, arguments)
        elif name.startswith("providers."):
            result = await asyncio.to_thread(_dispatch_providers, name, arguments)
        elif name.startswith("integrations."):
            result = await asyncio.to_thread(_dispatch_integrations, name, arguments)
        elif name.startswith("mcp."):
            result = await asyncio.to_thread(_dispatch_mcp, name, arguments)
        elif name.startswith("agents."):
            result = await asyncio.to_thread(
                _dispatch_agents, name, arguments, _ag, gate_approval)
        elif name == "eu_corpus.search":
            # alias morbido: eu_corpus.* == rag.* sulla collection eu-normativa.
            _rag_authorize("eu-normativa", write=False)
            result = eu_corpus.search(
                arguments["query"],
                k=arguments.get("k", 5),
                doc=arguments.get("doc"),
            )
        elif name == "eu_corpus.ingest":
            # Legge il PDF dal topic server-side (i byte NON passano dal modello),
            # con controllo participant+clearance, poi lo invia al micro-servizio.
            _rag_authorize("eu-normativa", write=True)
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
            _rag_authorize("eu-normativa", write=False)
            result = eu_corpus.list_documents()
        elif name == "eu_corpus.remove":
            _rag_authorize("eu-normativa", write=True)
            result = eu_corpus.remove(arguments["doc_name"], arguments.get("version"))
        elif name.startswith("rag."):
            result = _dispatch_rag(name, arguments)
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

# Soglia oltre la quale i byte NON devono viaggiare come base64 nei parametri di
# una tool-call (ARG_MAX, troncamento, token bruciati): sopra questo, read_file/
# write_file rifiutano e indirizzano a topic.fetch/topic.put (transfer via scratch,
# mediato dal gateway). ~128KB grezzi ≈ ~170KB di base64.
_B64_INLINE_CAP = 128 * 1024


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
    "read_document", "write_file", "fetch", "put", "delete_file", "migrate_storage",
    "post_message",
    "remote_enable", "remote_disable", "remote_add", "remote_commit",
    "remote_push", "remote_pull", "remote_status",
}


_SEAL_RANK = {"SEAL-0": 0, "SEAL-1": 1, "SEAL-2": 2, "SEAL-3": 3, "SEAL-4": 4}


def _rank(tier: str | None) -> int:
    return _SEAL_RANK.get(str(tier or "SEAL-0").strip().upper(), 0)


def _topic_is_member(meta: dict, caller: str) -> bool:
    return caller == meta.get("owner") or caller in (meta.get("participants") or [])


def _require_topic_member(svc, tier, name) -> None:
    """ACL compartimento (need-to-know).

    Consentito solo se l'AGENTE è participant/owner del target oppure esiste un
    consenso M-gate cross-topic attivo. La membership del principal umano non è
    un bypass: altrimenti un owner di molti topic annullerebbe il compartimento
    per qualunque agente che opera per suo conto.
    """
    caller = agent_name()
    try:
        meta = svc.open(tier, name).get("meta", {})
    except Exception:  # noqa: BLE001 — topic inesistente/illeggibile → nega
        raise PermissionError(f"topic {tier}/{name}: accesso negato")
    agent_ok = _topic_is_member(meta, caller)
    tier_t = meta.get("tier", tier)
    # cross-topic: consentito con un CONSENSO GATE attivo per questo topic
    # (topic-access:<tier>/<name>), concesso via popup (M-gate). Sostituisce sudo.
    from . import gate as _gate
    cross_ok = _gate.active(caller, "-", f"topic-access:{tier_t}/{name}")
    if not (agent_ok or cross_ok):
        raise PermissionError(
            f"accesso negato al topic {tier}/{name}: l'agente '{caller}' non è "
            "partecipante (compartimento need-to-know; "
            f"il cross-topic richiede un consenso gate)")
    # asse livello: clearance ≥ tier (difesa in profondità oltre al compartimento).
    if _rank(current_clearance()) < _rank(tier_t):
        raise PermissionError(
            f"agent '{caller}': clearance insufficiente per il tier {tier_t} del "
            f"topic {tier}/{name} (accesso negato: livello)")


def _require_local_hook_caller(svc, tier, name) -> str:
    """ACL stretta dell'hook locale: niente principal umano né gate cross-topic."""
    caller = agent_name()
    if not caller:
        raise PermissionError("invocazione hook locale riservata agli agenti")
    if caller == "messaggero":
        return caller
    try:
        meta = svc.open(tier, name).get("meta", {})
    except Exception:  # noqa: BLE001
        raise PermissionError(f"topic {tier}/{name}: accesso negato")
    if not _topic_is_member(meta, caller):
        raise PermissionError(
            f"agent '{caller}' non è participant di {tier}/{name}")
    if _rank(current_clearance()) < _rank(meta.get("tier", tier)):
        raise PermissionError(
            f"agent '{caller}': clearance insufficiente per {tier}/{name}")
    return caller


def _filter_member_rows(rows: list, caller: str) -> list:
    """Filtra allo scope need-to-know dell'AGENTE.

    La membership umana non amplia l'elenco: l'accesso aggiuntivo è per-topic e
    passa dal gate, non diventa un lasciapassare globale. Righe con shape diversa
    (senza participants/owner) restano invariate.
    """
    out = []
    for r in rows:
        if not isinstance(r, dict) or ("participants" not in r and "owner" not in r):
            out.append(r)
        elif _topic_is_member(r, caller):
            out.append(r)
    return out


def _rag_grants(agent: str) -> dict[str, set[str]]:
    """Grant live dal core; qualunque errore nega l'accesso (fail closed)."""
    try:
        return runtime.rag_grants(agent)
    except PermissionError:
        raise
    except Exception as e:  # noqa: BLE001 — backend irraggiungibile/malformato
        raise PermissionError(
            f"impossibile verificare i grant RAG dell'agent '{agent}'") from e


def _rag_readable(grants: dict[str, set[str]]) -> set[str]:
    """Collection su cui l'agent ha lettura (read grant OR write grant)."""
    return set(grants.get("rag_read") or []) | set(grants.get("rag_write") or [])


def _rag_provisioners() -> set[str]:
    return {
        x.strip() for x in _os.environ.get("CLODIA_RAG_PROVISIONERS", "sysadmin").split(",")
        if x.strip()
    }


def _rag_authorize(collection: str, write: bool) -> None:
    """Reference monitor per-collection: grant read/write (arg-aware, dal
    AgentSpec autorevole nel core) + tiering (clearance ≥ tier della collection).
    Super-agent → bypass dei grant, MA il vincolo del profilo (rag off/single)
    è strutturale e vale per tutti. Solleva PermissionError su violazione."""
    instance_profile.rag_check_collection(collection)
    ag = agent_name()
    if _is_super(ag):
        return
    if write and ag in _rag_provisioners():
        tier = eu_corpus.collection_tier(collection)
        if _rank(current_clearance()) < _rank(tier):
            raise PermissionError(
                f"agent '{ag}': clearance insufficiente per la collection '{collection}' "
                f"(tier {tier})")
        return
    grants = _rag_grants(ag)
    if write:
        if collection not in grants["rag_write"]:
            raise PermissionError(
                f"agent '{ag}' senza grant di SCRITTURA sulla collection '{collection}'")
    else:
        if collection not in _rag_readable(grants):
            raise PermissionError(
                f"agent '{ag}' senza grant di LETTURA sulla collection '{collection}'")
    # asse livello: clearance(agent) ≥ tier(collection). Difesa in profondità.
    tier = eu_corpus.collection_tier(collection)
    if _rank(current_clearance()) < _rank(tier):
        raise PermissionError(
            f"agent '{ag}': clearance insufficiente per la collection '{collection}' "
            f"(tier {tier})")


def _dispatch_rag(name: str, a: dict):
    verb = name.split(".", 1)[1]
    if not instance_profile.rag_enabled():
        raise PermissionError("feature 'rag' disabilitata dal profilo dell'istanza")
    if verb == "collections":
        res = eu_corpus.collections()
        # Profilo rag:single → la lista mostra solo la collection dell'edizione.
        if instance_profile.rag_mode() == "single":
            only = instance_profile.load()["rag"].get("collection") or ""
            res = {"collections": [c for c in res.get("collections", [])
                                   if c.get("collection") == only]}
        if not _is_super(agent_name()):
            if agent_name() in _rag_provisioners():
                res = {"collections": [
                    c for c in res.get("collections", [])
                    if _rank(current_clearance()) >= _rank(c.get("tier", "SEAL-0"))
                ]}
            else:
                allowed = _rag_readable(_rag_grants(agent_name()))
                res = {"collections": [c for c in res.get("collections", [])
                                       if c.get("collection") in allowed]}
        return res
    if verb == "create_collection":
        collection = a["collection"]
        _rag_authorize(collection, write=True)
        tier = a.get("tier", "SEAL-1")
        if _rank(current_clearance()) < _rank(tier):
            raise PermissionError(
                f"agent '{agent_name()}': clearance insufficiente per creare "
                f"collection tier {tier}")
        return eu_corpus.create_collection(
            collection,
            tier=tier,
            description=a.get("description"),
        )
    collection = a["collection"]
    if verb == "search":
        _rag_authorize(collection, write=False)
        return eu_corpus.search(a["query"], k=a.get("k", 5), doc=a.get("doc"),
                                collection=collection)
    if verb == "list":
        _rag_authorize(collection, write=False)
        return eu_corpus.list_documents(collection)
    if verb == "ingest":
        _rag_authorize(collection, write=True)
        svc = _topics()
        tier, tname, path = a["tier"], a["name"], a["path"]
        _require_topic_member(svc, tier, tname)
        data = svc.read_file(tier, tname, path)
        filename = path.rsplit("/", 1)[-1]
        return eu_corpus.ingest_bytes(
            data, filename, a["doc_name"], a["version"],
            url=a.get("url"), supersede=bool(a.get("supersede", False)),
            collection=collection)
    if verb == "remove":
        _rag_authorize(collection, write=True)
        return eu_corpus.remove(a["doc_name"], a.get("version"), collection)
    raise ValueError(f"unknown rag verb: {name}")


async def _dispatch_image(a: dict):
    """image.generate → genera un PNG e lo salva nei files/ del topic.
    La API key OpenAI è letta server-side dal vault, mai esposta all'agente."""
    from .tools import image as image_tool
    if not image_tool.has_key():
        return {"ok": False, "error": "nessuna API key OpenAI nel vault "
                "(Tools → Image generation)."}
    svc = _topics()
    tier, name = a.get("tier"), a.get("name")
    _require_topic_member(svc, tier, name)
    prompt = (a.get("prompt") or "").strip()
    if not prompt:
        return {"ok": False, "error": "serve un prompt"}
    filename = (a.get("filename") or "image.png").strip().lstrip("/")
    if not filename.lower().endswith(".png"):
        filename += ".png"
    png = await asyncio.to_thread(
        image_tool.generate, prompt,
        size=a.get("size") or "1024x1024",
        quality=a.get("quality") or "auto",
        background=a.get("background") or "auto")
    svc.put_file(tier, name, filename, png)
    return {"ok": True, "path": f"files/{filename}", "bytes": len(png)}


def _dispatch_artifact(a: dict):
    """artifact.render → snapshot del canvas live in files/artifact.html del topic
    (persistente; la finestra di anteprima lo mostra col suo polling)."""
    svc = _topics()
    tier, name = a.get("tier"), a.get("name")
    _require_topic_member(svc, tier, name)
    data = (a.get("html") or "").encode("utf-8")
    svc.put_file(tier, name, "artifact.html", data)
    return {"ok": True, "path": "files/artifact.html", "bytes": len(data)}


def _extract_document_text(filename: str, data: bytes) -> tuple[str, int | None]:
    """Estrae testo da PDF/DOCX/XLSX (server-side). Ritorna (testo, n_pagine|None).
    Fallback: prova a decodificare come testo UTF-8."""
    import io
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext == "pdf":
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        pages = [(p.extract_text() or "") for p in reader.pages]
        return "\n\n".join(pages), len(pages)
    if ext == "docx":
        from docx import Document
        doc = Document(io.BytesIO(data))
        parts = [p.text for p in doc.paragraphs]
        for tbl in doc.tables:
            for row in tbl.rows:
                parts.append("\t".join(c.text for c in row.cells))
        return "\n".join(parts), None
    if ext in ("xlsx", "xlsm"):
        from openpyxl import load_workbook
        wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        out = []
        for ws in wb.worksheets:
            out.append(f"# Foglio: {ws.title}")
            for row in ws.iter_rows(values_only=True):
                out.append("\t".join("" if v is None else str(v) for v in row))
        return "\n".join(out), None
    # fallback testo
    return data.decode("utf-8", errors="replace"), None


def _dispatch_topic(name: str, a: dict):
    svc = _topics()
    verb = name.split(".", 1)[1]
    if verb in _TOPIC_SCOPED_VERBS:
        _require_topic_member(svc, a.get("tier"), a.get("name"))
    if verb == "suggest_team":
        # proposta di squadra: proxy read-only all'agent-server (registry+rilevanza)
        return runtime.suggest_team(a.get("tier") or "SEAL-0", a.get("description") or "")
    if verb in ("add_participant", "remove_participant"):
        # topic.add_participant/remove_participant sono verbi GATED → il
        # gate di call_tool ha già richiesto la conferma umana (block-and-wait)
        # prima di arrivare qui. L'owner umano usa invece l'endpoint webui
        # dedicato, già autorizzato sul suo ruolo.
        return runtime.set_participant(a["tier"], a["name"], (a.get("agent") or "").strip(),
                                       by=agent_name() or "", add=(verb == "add_participant"))
    if verb == "new":
        # Profilo topics:single → solo il workspace unico (DM sempre permessi).
        instance_profile.topic_creation_check(a["name"])
        hook_enabled = bool(a.get("hook_enabled", True))
        meta = svc.new(
            a.get("tier"), a["name"],
            {**(a.get("meta") or {}), "hook_enabled": hook_enabled})
        if hook_enabled:
            runtime.ensure_topic_hook(
                meta["tier"], a["name"], by=agent_name() or "platform")
        return meta
    if verb == "invoke_hook":
        caller = _require_local_hook_caller(svc, a["tier"], a["name"])
        return runtime.invoke_topic_hook(
            a["tier"], a["name"], a.get("payload") or "", caller=caller)
    if verb == "open":
        return svc.open(a["tier"], a["name"])
    if verb == "post_message":
        # Prerogativa di messaggero e dei super: posta una bolla nella chat del
        # topic (es. mail in arrivo / handoff). Se il testo ha una @menzione,
        # innesca il risponditore → l'agente taggato prende in carico il messaggio.
        ag = agent_name()
        if not (_is_super(ag) or ag == "messaggero"):
            raise PermissionError(
                "topic.post_message riservato a messaggero e ai super-agent")
        text = a.get("text") or ""
        res = svc.post_message(a["tier"], a["name"], author=ag or "agente",
                               text=text, kind="ai")
        import re as _re
        if _re.search(r"@[a-z0-9][a-z0-9_-]{0,30}", text):
            try:
                runtime.channel_trigger(a["tier"], a["name"], text, by=ag or "")
                res["triggered"] = True
            except Exception as e:  # noqa: BLE001 — il post resta valido anche se il trigger fallisce
                res["trigger_error"] = str(e)[:120]
        return res
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
            # File binario: NON riversare base64 grossi nel contesto (si tronca, brucia
            # token, spesso fallisce). Sopra soglia → indirizza a topic.fetch (copia nello
            # scratch, byte fuori dal modello). Vedi anche topic.read_document per il testo.
            if len(data) > _B64_INLINE_CAP:
                return {"ok": False, "path": a["path"], "size": len(data),
                        "error": (f"file binario di {len(data)} byte: troppo grande per "
                                  "read_file (base64 nel contesto). USA topic.fetch(tier, name, "
                                  f"path='{a['path']}', dest=<path nel tuo scratch>) e lavora sul "
                                  "file locale; per il solo testo usa topic.read_document.")}
            import base64 as _b64
            return {"path": a["path"], "encoding": "base64",
                    "content": _b64.b64encode(data).decode("ascii"),
                    "note": "file binario (PDF/immagine/...): decodifica da base64"}
    if verb == "read_document":
        data = svc.read_file(a["tier"], a["name"], a["path"])
        cap = int(a.get("max_chars") or 60000)
        try:
            text, pages = _extract_document_text(a["path"].rsplit("/", 1)[-1], data)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"estrazione fallita: {str(e)[:160]}"}
        trunc = len(text) > cap
        return {"path": a["path"], "text": text[:cap], "chars": len(text),
                "pages": pages, "truncated": trunc}
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
            # Base64 grosso nei parametri = anti-pattern (ARG_MAX/troncamento): se hai
            # già il file nello scratch, caricalo con topic.put (il gateway legge i byte
            # dal path, niente base64 nel modello).
            if len(data) > _B64_INLINE_CAP:
                return {"ok": False, "filename": fn, "size": len(data),
                        "error": (f"payload di {len(data)} byte troppo grande per write_file. "
                                  "Scrivi il file nel tuo scratch e usa topic.put(tier, name, "
                                  f"filename='{fn}', src=<path nel tuo scratch>).")}
        else:
            data = (a["content"] or "").encode("utf-8")
        return svc.put_file(a["tier"], a["name"], fn, data)
    if verb == "fetch":
        # I byte attraversano il solo volume /shared come envelope cifrato per
        # lo spawn destinatario; agent-server decifra e materializza `dest`.
        data = svc.read_file(a["tier"], a["name"], a["path"])
        chat_id = current_chat()
        if not chat_id:
            raise ValueError("topic.fetch richiede una sessione agent con chat_id")
        return transfer_channel.fetch_to_agent(
            data, chat_id=chat_id, dest=a["dest"], sender=agent_name())
    if verb == "put":
        # agent-server legge lo scratch della sola sessione, cifra per il gateway
        # e deposita un envelope effimero su /shared; qui viene decifrato e consumato.
        chat_id = current_chat()
        if not chat_id:
            raise ValueError("topic.put richiede una sessione agent con chat_id")
        data = transfer_channel.put_from_agent(chat_id=chat_id, src=a["src"])
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
