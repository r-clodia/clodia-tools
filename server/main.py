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
from .tools import email, fs, logs, runtime
from .tools import eu_corpus
from .whitelist import (agent_config, agent_name, current_chat, current_clearance,
                        current_human_role, current_principal, is_on_behalf)

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

_SUDO_TOOLS: list[Tool] = [
    Tool(
        name="sudo.request",
        description=(
            "Richiedi l'ELEVAZIONE a sudo per un'operazione riservata (super-only: "
            "cross-topic, gestione partecipanti, install pack/provider/mcp, ...). "
            "NON attiva sudo da solo: crea una richiesta che l'OWNER approva o nega "
            "da un popup nella webUI. Spiega bene il MOTIVO. Riservato ai sudoer."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "reason": {"type": "string", "description": "Perché serve l'elevazione (mostrato all'owner)."},
                "minutes": {"type": "integer", "description": "Durata richiesta (default 15, max 120)."},
            },
            "required": ["reason"],
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
             "agent": {"type": "string", "description": "agent (kind) che esegue il job al fire (default clodia)"},
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
         description=("Legge un file della tua seed memory (default `memory.md`, la tua "
                      "memoria di note/esperienza sempre disponibile). La memory è "
                      "condivisa fra le tue istanze."),
         inputSchema={"type": "object", "properties": {
             "filename": {"type": "string", "description": "default memory.md"}}}),
    Tool(name="memory.write",
         description=("Scrive (sovrascrive) un file della tua seed memory. Usa per "
                      "aggiornare note durature o dati strutturati (es. una whitelist "
                      "JSON). Cap 64KB per file."),
         inputSchema={"type": "object", "properties": {
             "content": {"type": "string"},
             "filename": {"type": "string", "description": "default memory.md"}},
             "required": ["content"]}),
    Tool(name="memory.append",
         description="Aggiunge una nota in coda a un file della seed memory (default memory.md).",
         inputSchema={"type": "object", "properties": {
             "content": {"type": "string"},
             "filename": {"type": "string", "description": "default memory.md"}},
             "required": ["content"]}),
    Tool(name="memory.list",
         description="Elenca i file di NOTE (testo) nella tua seed memory.",
         inputSchema={"type": "object", "properties": {}}),
    # Document store per-seed: DOCUMENTI (PDF/docx/dataset…) che sopravvivono agli
    # spawn, in agents/<seed>/files/. NON caricati in automatico: leggili su richiesta.
    Tool(name="memory.put_document",
         description=("Salva un DOCUMENTO (PDF, docx, xlsx, dataset, immagine…) nella tua "
                      "libreria personale del seed (persistente, sopravvive agli spawn). "
                      "content_b64 = contenuto in base64. Max 25MB."),
         inputSchema={"type": "object", "properties": {
             "filename": {"type": "string"}, "content_b64": {"type": "string"}},
             "required": ["filename", "content_b64"]}),
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
                      "ri-allegarlo o passarlo a un tool che accetta binari)."),
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
    tools = (_FS_TOOLS + _LOGS_TOOLS + _SUDO_TOOLS + _EMAIL_TOOLS + _TRELLO_TOOLS + _TOPIC_TOOLS + _IMAGE_TOOLS
             + _RUNTIME_TOOLS + _JOBS_TOOLS + _PROFILE_TOOLS + _TELEGRAM_TOOLS + _MEMORY_TOOLS + _GDRIVE_TOOLS
             + _GCALENDAR_TOOLS + _GDOCS_TOOLS + _AGENT_TOOLS
             + _PACKS_TOOLS + _WORKFLOWS_TOOLS + _PROVIDERS_TOOLS + _INTEGRATIONS_TOOLS + _MCP_TOOLS)
    if instance_profile.rag_enabled():
        tools = tools + _EU_CORPUS_TOOLS + _RAG_TOOLS
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
            agent=a.get("agent") or "clodia", enabled=a.get("enabled", True),
            requested_by=caller or "agente")
    raise ValueError(f"unknown jobs tool: {name}")


def _dispatch_packs(name: str, a: dict):
    from .tools import platform_ops as ops
    sub = name.split(NS_SEP_DOT, 1)[1]
    if sub == "list":
        return ops.packs_list()
    if sub == "show":
        return ops.packs_show(a["name"])
    if sub == "import_url":
        return ops.packs_import_url(a["url"])
    if sub == "remove":
        return ops.packs_remove(a["name"])
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
    stessa lista di M-sudo) richiede ruolo **admin**; tutto il resto è concesso a
    qualunque umano autenticato. Il ruolo è un claim FIRMATO dall'agent-server →
    non forgiabile dal modello. Chiude la Broken Access Control del path REST."""
    from . import sudo as _sudo
    if _sudo.is_super_only(name):
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
    if name.startswith(("gdrive.", "gcalendar.", "gdocs.")) and _gws_grant:
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
    accts = sorted({c[len("google_"):] for c in grants if c.startswith("google_")}
                   | {c[len("gmail_"):] for c in grants if c.startswith("gmail_")}
                   | {c[len("mailbox_"):] for c in grants if c.startswith("mailbox_")})
    return accts[0] if len(accts) == 1 else "demo"


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
        allowed = set(agent_config().get("allowed_tools", []))
    except PermissionError:
        return []
    native = list(_FS_TOOLS + _LOGS_TOOLS + _SUDO_TOOLS + _EMAIL_TOOLS + _TRELLO_TOOLS + _TOPIC_TOOLS + _IMAGE_TOOLS + _RUNTIME_TOOLS + _JOBS_TOOLS + _SETTINGS_TOOLS + _PROFILE_TOOLS + _TELEGRAM_TOOLS + _MEMORY_TOOLS + _GDRIVE_TOOLS + _GCALENDAR_TOOLS + _GDOCS_TOOLS + _AGENT_TOOLS
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
                name, set(agent_config().get("allowed_tools", []))) \
                and not _connector_allows(name, _ag):
            raise PermissionError(
                f"tool '{name}' non in whitelist per agent '{_ag}'")
        # M-gate: un verbo GATED richiede conferma umana AD OGNI uso — anche per i
        # super-agent (niente più bypass) e anche on-behalf di un umano. Il gate
        # NON concede nulla: il richiedente è già autorizzato sopra. Per gli AGENTI
        # serve un consenso ccap1 (one-shot, consumato all'uso); assente → si crea
        # una richiesta e si sospende. Per gli UMANI la conferma è il dialog lato UI
        # (sono già l'autorità autenticata): qui non blocchiamo oltre la RBAC.
        from . import gate as _gate
        if _gate.is_gated(name) and not is_on_behalf():
            _inst = "-"
            if not _gate.active(_ag, _inst, name):
                _gate.request(_ag, _inst, name, context=current_chat(),
                              human=current_principal(), chat=current_chat())
                raise PermissionError(
                    f"gate: '{name}' richiede conferma umana — richiesta creata "
                    "nel contesto; riprova dopo l'approvazione")
            _gate.consume(_ag, _inst, name)  # one-shot: il consenso vale per questa azione
        if name == "fs.list_dir":
            result = fs.list_dir(arguments["path"])
        elif name == "logs.tail":
            result = logs.tail(arguments.get("lines", 100), arguments.get("level", ""))
        elif name == "sudo.request":
            from . import sudo as _sudo
            result = _sudo.request_sudo(
                agent_name(), "-", arguments.get("reason", ""),
                arguments.get("minutes", 15), human=current_principal(),
                chat=current_chat())
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
        elif name.startswith("runtime."):
            # proxy httpx SINCRONO all'agent-server → offload su thread (no blocco loop)
            result = await asyncio.to_thread(_dispatch_runtime, name, arguments)
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
            result = await asyncio.to_thread(_dispatch_agents, name, arguments, _ag)
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
    "remote_enable", "remote_disable", "remote_add", "remote_commit",
    "remote_push", "remote_pull", "remote_status",
}


_SEAL_RANK = {"SEAL-0": 0, "SEAL-1": 1, "SEAL-2": 2, "SEAL-3": 3, "SEAL-4": 4}


def _rank(tier: str | None) -> int:
    return _SEAL_RANK.get(str(tier or "SEAL-0").strip().upper(), 0)


def _topic_is_member(meta: dict, caller: str) -> bool:
    return caller == meta.get("owner") or caller in (meta.get("participants") or [])


def _sudo_cross_topic(caller: str) -> bool:
    """Un SUDOER (clodia/ophelia/sysadmin) può andare cross-topic / fare azioni
    super-only SOLO con un grant sudo attivo (approvato da un admin). Non-sudoer
    o sudoer senza grant → False. Fix confused-deputy: nessun bypass permanente.
    (instance-boxing per-sessione: il plumbing dell'id-istanza arriva dopo; per
    ora chiave istanza '-'.)"""
    try:
        from . import sudo
        return sudo.is_sudoer(caller) and sudo.active(caller, "-")
    except Exception:  # noqa: BLE001
        return False


def _require_topic_member(svc, tier, name) -> None:
    """ACL compartimento (need-to-know). Consentito SSE:
      - l'UMANO del turno (current_principal) è participant/owner del target, OPPURE
      - l'AGENTE è participant/owner del target (autonomo/legittimo), OPPURE
      - l'agente è super CON un grant SUDO attivo (cross-topic autorizzato).
    Il super NON bypassa più incondizionatamente (fix confused-deputy: un agente
    non deve leggere/copiare un topic di cui né il richiedente umano né l'agente
    sono partecipanti). Vedi project_topic_access_two_axis."""
    caller = agent_name()
    principal = current_principal()
    try:
        meta = svc.open(tier, name).get("meta", {})
    except Exception:  # noqa: BLE001 — topic inesistente/illeggibile → nega
        raise PermissionError(f"topic {tier}/{name}: accesso negato")
    human_ok = bool(principal) and _topic_is_member(meta, principal)
    agent_ok = _topic_is_member(meta, caller)
    if not (human_ok or agent_ok or _sudo_cross_topic(caller)):
        raise PermissionError(
            f"accesso negato al topic {tier}/{name}: né l'umano '{principal}' né "
            f"l'agente '{caller}' sono partecipanti (compartimento need-to-know; "
            f"cross-topic richiede sudo)")
    # asse livello: clearance ≥ tier (difesa in profondità oltre al compartimento).
    tier_t = meta.get("tier", tier)
    if _rank(current_clearance()) < _rank(tier_t):
        raise PermissionError(
            f"agent '{caller}': clearance insufficiente per il tier {tier_t} del "
            f"topic {tier}/{name} (accesso negato: livello)")


def _filter_member_rows(rows: list, caller: str) -> list:
    """Filtra righe-topic allo scope need-to-know: topic di cui l'UMANO del turno
    o l'AGENTE è participant/owner. Super con sudo attivo → tutte. Righe senza
    participants/owner (shape diversa) lasciate."""
    if _sudo_cross_topic(caller):
        return rows
    principal = current_principal()
    out = []
    for r in rows:
        if not isinstance(r, dict) or ("participants" not in r and "owner" not in r):
            out.append(r)
        elif (bool(principal) and _topic_is_member(r, principal)) or _topic_is_member(r, caller):
            out.append(r)
    return out


def _rag_readable(cfg: dict) -> set:
    """Collection su cui l'agent ha lettura (read grant OR write grant)."""
    return set(cfg.get("rag_read") or []) | set(cfg.get("rag_write") or [])


def _rag_authorize(collection: str, write: bool) -> None:
    """Reference monitor per-collection: grant read/write (arg-aware, dal
    config.yaml del gateway) + tiering (clearance ≥ tier della collection).
    Super-agent → bypass dei grant, MA il vincolo del profilo (rag off/single)
    è strutturale e vale per tutti. Solleva PermissionError su violazione."""
    instance_profile.rag_check_collection(collection)
    ag = agent_name()
    if _is_super(ag):
        return
    cfg = agent_config()
    if write:
        if collection not in set(cfg.get("rag_write") or []):
            raise PermissionError(
                f"agent '{ag}' senza grant di SCRITTURA sulla collection '{collection}'")
    else:
        if collection not in _rag_readable(cfg):
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
            allowed = _rag_readable(agent_config())
            res = {"collections": [c for c in res.get("collections", [])
                                   if c.get("collection") in allowed]}
        return res
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
        # Gestione partecipanti = azione SUDO (admin), come agents.*: un agente
        # può farlo SOLO se super CON grant sudo attivo. Una clodia non-sudoer
        # NON può aggiungere/togliere partecipanti → chiude l'auto-invito
        # (giovanni non può chiedere a clodia di aggiungersi a un topic).
        # L'owner UMANO gestisce i partecipanti dalla webui (endpoint dedicato,
        # non questo tool), quindi i flussi legittimi non si rompono.
        if not _sudo_cross_topic(agent_name()):
            raise PermissionError(
                "gestione partecipanti: azione riservata (super con sudo attivo). "
                "L'owner invita/rimuove i partecipanti dalla webui.")
        return runtime.set_participant(a["tier"], a["name"], (a.get("agent") or "").strip(),
                                       by=agent_name() or "", add=(verb == "add_participant"))
    if verb == "new":
        # Profilo topics:single → solo il workspace unico (DM sempre permessi).
        instance_profile.topic_creation_check(a["name"])
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
