# Connector manifest — schema v1

A connector is everything the platform needs to know about one way in or out:
which URI schemes it speaks, which providers implement them, which verbs write
where, how the owner connects it, which button it adds to a topic, and which
long-running process it needs. Today all of that is hardcoded in the gateway and
in the webui. This document is the grammar that lets a **pack** declare it
instead.

Parser and validation: `manifest.py` next to this file. Issue:
`r-clodia/clodia-platform#516`, part of the *Pack connectors* epic #527.

> **This schema is read-only authority.** A manifest *declares*; it never
> *grants*. The author of a pack says what the connector is, the owner who
> installs decides what it may reach — the same line `pack_import.declared_flows`
> already draws for `ingress:`/`egress:`. Nothing a pack writes here puts a
> destination in a whitelist.

Every fenced `yaml` block below is a complete, valid example, and
`test_manifest.py` loads all of them into one registry. An example that stops
being valid, or that collides with another, fails the suite.

---

## Where it goes

A `connectors:` list at the top level of `pack.yaml`, alongside `agents:`,
`plugins:` and `datastores:`.

```
pack.yaml
  name: comms-pack
  connectors:
    - id: …
```

## Two kinds of connector

| Kind | Declares | Example |
|---|---|---|
| **Vocabulary owner** | `schemes:`, and may declare `verbs:`, `taint:`, `topic_actions:` | `comms-pack` owns the mail vocabulary `mailto:`/`mailfrom:`/`inbox:`/`outbox:` |
| **Contributor** | `extends: <id>` plus `providers:` only | `google-pack` adds Gmail as a provider of that same vocabulary |

The split is the whole of the multi-provider decision of 2026-10-08. Gmail lives
in `google-pack` and IMAP in `comms-pack`, but `mailto:` has to mean one thing on
the instance. So the vocabulary has exactly one owner, and a contributor adds an
*implementation*, never a *meaning*: an entry with `extends:` that also carries
`schemes:`, `verbs:`, `taint:` or `topic_actions:` is refused. Otherwise the pack
installed second would quietly redefine the first one's vocabulary.

A third shape is legal and useful: **no schemes, no `extends`, just a provider**.
That is a connector which only needs a credential — image generation is one.

## Fields

### Connector

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | unique on the instance, `[a-z][a-z0-9-]*` |
| `manifest_version` | yes | `1`. A higher number is refused by name, not parsed with the wrong rules |
| `namespace` | yes | the verb namespace the pack owns, `[a-z][a-z0-9_]*` |
| `label` | no | shown in the UI; defaults to `id` |
| `extends` | no | id of the vocabulary this entry contributes a provider to |
| `schemes` | – | see below; mutually exclusive with `extends` |
| `providers` | no | implementations, each with its credential |
| `verbs` | no | verb → destination and read → source; a verb may appear more than once |
| `danger_uris` | no | warnings for URIs of a shared scheme (`match` + `text`) |
| `taint` | no | MCP prefixes of this pack whose answers do not taint a channel |
| `topic_actions` | no | buttons the connector adds to a topic |
| `tools_card` | no | what the Tools page shows: `setup_label`, `status_verb`, `test_verb`, `docs_url`, `blurb`, `scope`, `icon` |
| `services` | no | long-running processes, see #515 |
| `storage_remote` | no | topic storage backend the pack provides, see #524 |
| `context` | no | arguments the GATEWAY fills on every verb of this namespace, see below |
| `files` | no | arguments that name a TOPIC FILE, which the gateway reads and delivers as bytes |
| `defaults` | no | arguments the gateway fills **only when omitted**, see below |

`blurb`, `scope` and `icon` (#520) are the card's COPY and its glyph. The
drawing is a frontend asset — a logo is an SVG file, not gateway data — but the
CHOICE is the connector's: while the page decided it, it decided by NAME, which
is the per-connector knowledge the issue removes. A connector without a
`tools_card` is a vocabulary, not a card, and the Tools page does not draw it;
an `icon` the page does not know falls back to the generic glyph.

`docs_url` must be an absolute `https://` URL: the Tools page puts it in an
`href`, and anything else (`javascript:`, `data:`, `http:`, relative) is refused
when the manifest is parsed.

There is **no `seal_cap`**, and writing one is an error. The epic decided there
is no SEAL ceiling on a binding: the owner decides per binding at the gate, and
the gate shows the topic's tier. Today's `_CHANNEL_SEAL_CAP` and
`_DRIVE_SEAL_CAP` disappear with #518 and must not come back as a field.

### `context`

```
context:
  channel: channel      # argument name: what the gateway puts in it
  agent: agent
```

A mapping `<argument>: channel|agent`. The gateway fills those arguments on
**every** call to a verb of this namespace, with the values it reads from the
session's signed claim — the room the call comes from and the agent making it —
and it **overwrites** whatever arrived with the call.

Why it exists: a native connector knows where it is and who is calling because
it reads the claim; a pack's process does not have the claim, and a context
passed as an ordinary argument would be a context the caller can choose.
`telegram.send` without `chat_id` sends to the chat bound to the calling topic,
so a caller-declared channel would mean «write into another topic's group».

Consequences worth knowing before declaring one:

- the value is overwritten **always**, with the empty string when there is no
  channel: there is no «the caller already set it, so I keep it», because that
  case is the attack;
- it applies to every verb of the namespace, so every tool of your MCP server
  must accept those arguments. One list per verb would be one more list to keep
  in step with the server's tools, and the day a new verb arrives without an
  entry it would receive the caller's value instead;
- `channel` and `agent` are the whole list. A manifest may not invent a context
  name: that is not adding a field, it is asking the gateway to certify
  something it does not know;
- a **builtin** manifest declaring `context` is refused: the gateway's own
  connectors have the claim, and the argument would overwrite a parameter of
  code we own.

### `defaults`

```
defaults:
  - verb: telegram.send
    arg: chat_id
    value: binding      # the chat bound to the calling topic
```

The gateway fills these arguments **only when the caller left them out**, and
that rule is the whole difference from `context:`. A context is an *identity*
and is always overwritten, because «the caller already set it» is the attack. A
default is a convenience — «send it to this topic's chat» — and an explicit
value from the caller has to win, or you could no longer write to any chat other
than the bound one.

Per **verb**, not per namespace: `telegram.inbox` has no chat to fill, and
filling it anyway would hand the backend an argument its schema does not
declare.

`binding` is the whole list of values. It resolves through the gateway's
bindings registry — the one the topic's button writes, which holds every
connector's bindings — and that is the point: a pack process reading it itself
would also be reading everybody else's, with the gateway's uid.

A declared default that cannot be resolved is an **explained error**, not an
argument left empty: empty, the PDP would compute a destination that does not
exist and refuse the send talking about «unknown destination», which is the
wrong symptom for «this topic has no chat connected».

### `files`

```
files:
  - verb: telegram.send_file
    path_arg: path            # what the caller names
    bytes_arg: content_b64    # where the gateway puts the bytes
    name_arg: filename        # where it puts the basename
    tier_arg: tier            # optional: explicit topic
    topic_arg: name
    chat_arg: chat_id         # optional: the topic bound to this chat
```

Some verbs act on a file that lives in a topic. **Reading it is platform work,
not connector work**: the compartment (the caller must be a participant of that
topic) and the audit of what crosses the boundary hang off that read. A pack
backend reading the topics' filesystem itself would walk past both, and the path
is chosen by the caller.

So the pack says *which arguments* are the path, the bytes and the name; the
gateway resolves the topic, checks the membership, reads, records the crossing
and fills in the two arguments. The backend receives bytes and never sees a
path — the arguments that said *where to read* are removed once they have done
their job.

The topic is resolved in the order the native code used: `tier_arg`+`topic_arg`
when the caller passes both, else the topic bound to the chat in `chat_arg`
(the bindings registry belongs to the gateway, not to the pack), else the
channel the call comes from.

`verb` must be inside the connector's namespace — the same rule as `verbs:`, for
the same reason: a pack does not get somebody else's topic files delivered. A
**builtin** manifest declaring `files` is refused: the gateway reads a topic
file from the inside.

### `schemes[]`

| Field | Required | Meaning |
|---|---|---|
| `scheme` | yes | the URI scheme, without the colon |
| `direction` | yes | `source`, `egress` or `both` — today's `SOURCE_SCHEMES` / `EGRESS_SCHEMES` |
| `forms[]` | no | accepted shapes: `label`, `pattern`, optional `example` |
| `hierarchical` | no | a rule covers what is below it |
| `lowercase` | no | the whole URI is case-insensitive and is stored lowercased (the mail family) |
| `wildcard` | no | default `true`; `false` where `<scheme>:*` would be the whole thing and not a perimeter (`gcal:`) |
| `label`, `icon` | no | presentation |
| `danger` | no | the warning shown at the gate — today's `_DANGER` |
| `canonicalise[]` | no | `from` (regex) → `to` (template over `{1}`, `{2}`…) — today's `_CANON` |

Every pattern — `forms`, `canonicalise.from`, `danger_uris.match` — matches
with **`fullmatch`**: `^-?\d+` accepts `-100123`, not `-100123garbage`.

A PACK pattern must stay inside a **safe subset**, checked on its parse tree at
load: at most two quantified atoms with a maximum above one (`*`, `+`, `{m,n}`,
bounded or not), at most two `?`; a quantifier applies to a single character
or character class, never to a group (`(?:x)?`, `(a+)+` are refused); at most
one alternation, of at most four alternatives, with no quantifier inside it;
no back-references, lookarounds or conditionals; at most 200 characters. And a
pack pattern is never applied to a value longer than **256** characters — such a
value is refused for that scheme. `re` has no timeout, so the bound is in the
grammar and in the input, not on the clock. (The gateway's own manifests are
checked by a structural analysis instead, and matched on up to 2048
characters.)

A **canonicalisation** rewrites a URI of its own scheme into its own scheme:
`to` must start with `<scheme>:` and use at least one capture group. A pack's
rules — and its `danger_uris` — are applied only to URIs of the schemes that
pack owns, never to a shared scheme like `https:`; only the gateway's own
manifests may read a shared scheme (that is how a Drive URL becomes
`gdrive:folder/<id>`).

An `example` that does not match its own `pattern` is an error: it is the
cheapest available proof that the regex says what the author meant. A
canonicalisation template that refers to a capture group the pattern does not
have is an error too.

`http`, `https`, `topic` and `mcp` are **platform-intrinsic**: a pack may point a
verb at them, but declaring them in `schemes:` is refused — they are declared in
the gateway's own core manifest (see below). GitHub works that way
— its destinations are ordinary `https://github.com/<owner>/<repo>` URLs, checked
by the ordinary http rules.

### `providers[]`

Used by `POST /internal/tools/connectors/{id}/connect` (#519) for `kind: form`:
the declared fields go into the declared vault entry, as an infrastructure
credential with no per-agent grant, and the answer says that something is there
— never what. `kind: oauth` keeps its provider routes: a consent has application
credentials, state to keep between the two legs and a callback, and making that
generic without a manifest that describes it would be rewriting it.

`id`, `label`, optional `status_verb` / `test_verb`, and a `credential`:

- `kind: form` — `vault_entry` (under the connector's own namespace:
  `<namespace>` or `<namespace>_<name>`, never a core credential such as
  `mailbox_…`, `provider_…`, `mcp_…`, `google_…`, `telegram_…`. The stems of
  those prefixes — google, gmail, telegram, github, mailbox, openai, … — are
  reserved NAMESPACES for every pack until the migration issue of that core
  connector lands) plus the `fields` the owner fills in (`secret:
  true` for the ones that must never be echoed back);
- `kind: oauth` — `authorize_url`, `token_url`, `scopes`.

### `verbs[]`

| Field | Required | Meaning |
|---|---|---|
| `verb` | yes | **must start with the connector's `namespace.`** |
| `direction` | yes | `egress` (a destination) or `source` (a read) |
| `scheme` | yes | one the connector declares, or a platform scheme |
| `arg` | yes | the argument the destination is read from |
| `template` | no | how the URI is built; defaults to `<scheme>:{value}` |
| `multi` | no | the argument may carry a list (several recipients) |
| `dtype` | no | the destination type shown at the gate |
| `prefix` | no | `verb` is a prefix, for the verbs of a proxied backend that change upstream (`github.create_`) |
| `normalise` | no | one of the gateway's transforms: `url_origin`, `repo_url`, `repo_pair`, `email_from`. With it, `arg` may be omitted |
| `reads` | no | `arguments` (default) or `result` — the sender of a mail is only in the answer |

**A verb may be mapped more than once.** `email.send` reads `to`, `cc` and
`bcc`; `gdrive.upload` writes into a folder *and* may share with a person, which
is a second scheme. The destinations of one call are the union, and all of them
have to be inside the perimeter. Two mappings of one verb may not disagree on
`dtype`: the gate would name the same call differently depending on which
argument it read.

**Using a vocabulary is not owning it.** A verb may point at any scheme declared
on the instance, not only at the ones its own connector declares: a courier pack
that sends mail is checked against the very same `mailto:` whitelist, which is
what makes it indistinguishable from the native verb (#517). What stays
forbidden is *declaring* someone else's scheme. Whether a scheme exists is
therefore checked when the registry is built, not when one entry is parsed.

**The namespace rule is not negotiable.** A pack maps only verbs it owns; a
manifest naming someone else's verb is refused *as a whole*, with the offending
verb in the message. Without it a pack could declare `email.send` as a read, or
map it to a harmless destination, and walk straight through the egress check.
`check_namespace()` is exported because #517 applies the same rule again when the
call actually happens — two implementations of it would be one too many.

### `topic_actions[]`

`id`, `label`, `fields[]`, `binding` (optional; only `channel`), `admin_only`
(optional, default `false`), and `adds:` with `ingress:` /
`egress:` templates over the action's own fields. A template naming a field the
action does not declare is an error, and so is a template that does not start
with one of the connector's OWN schemes written out (`tg:{chat}`, never `{url}`
or `https://{host}/`; an `extends` provider uses the vocabulary it joins). At
run time every resolved URI is checked against its scheme's forms and against
`egress.check_grantable` before anything is written. A pack's action may write
only into a scheme that declares `forms` (a scheme without forms would accept
`courier:*`). Only the topic's owner or an admin (on-behalf), or the
agent-server's own session, may run an action — never an agent token. What the action adds is a *proposal*: the
grant is still the owner's, at the gate.

`admin_only: true` means the action is **offered** only to an admin of the
instance, not to every topic owner: what it authorises may not belong to whoever
owns the room (a system mailbox is the instance's mail). It is a rule about the
SURFACE — the route's check stays `_authorize_topic_owner` — and it lives here
rather than in an `if` on the connector's name, which is what rendering the row
generically would otherwise delete (#520).

A free-text value is passed through `egress.canonical()` before the template is
rendered, and a value that is already an address of the scheme the template
writes stands for itself: a Drive folder URL copied from the browser bar becomes
`gdrive:folder/<id>`. Anything else goes through the template and then through
the same form check as before, so this widens what a person may TYPE, not what
the action may WRITE.

Since #519 the action is **executed** from this declaration, by the generic
route `POST /internal/topics/{tier}/{name}/connectors/{id}/{action}`: the owner
fills the fields in, the gateway renders the templates and writes those entries
into that topic's lists — and `binding: channel` also creates the binding, which
is the second half nothing works without.

A field is free text, or a **choice among values the gateway supplies**:

| field | meaning |
|---|---|
| `name`, `label`, `required`, `placeholder` | the form |
| `options` | one of `manifest.OPTION_SETS` (today: `mailboxes`) |

The difference is not convenience, it is trust. A chosen option is **resolved by
the gateway**: picking a mailbox yields the address the gateway knows for it, and
the template interpolates that (`inbox:{address}`) — the names an option set
resolves are declared in `OPTION_SET_VALUES`, so the grammar can validate them.
Free text is the client's, and is then checked against the scheme's forms.
Without the distinction, the mailbox action would take the address to authorise
from the request body, and a whitelist written by whoever is subject to it is not
a whitelist. A pack may *point at* an option set, never define one.

### `services[]`

The shape #515 fixed, parsed here so the supervisor consumes one format instead
of inventing a second: `name`, `command` (a **list**, never a string — a string
would mean a shell, and a shell is a way to hide a second process inside a
manifest that declares one), `workdir`, `credentials` (vault entry names),
`health: {kind: http|tcp|command, target, interval_seconds}`,
`restart: {policy: always|on-failure|never, backoff_seconds}`.

State lives under `<datadir>/services/<pack>/<service>/` — `Service.state_dir`
computes it, so the path is not written down twice.

**At load** a service is refused, and with it the whole pack, when:

- a `credentials` entry is outside the connector's own namespace (`<namespace>`
  or `<namespace>_<name>`) or carries a core prefix (`github_`, `google_`,
  `telegram_`, `provider_`, `app_`, …) — the same `vault_entry_problem` rule as a
  provider credential — or when the entry falls under a LONGER installed
  namespace (`foo` may not declare `foo_bar_token` while `foo_bar` is
  installed: an entry belongs to the longest namespace that prefixes it);
- the pack's namespace is a `_`-prefix of a builtin or core-reserved namespace
  (`foo` when the gateway owns `foo_bar`);
- `workdir` is absolute, starts with `~`, or contains `..`. A `workdir` is
  relative to the pack directory (`<datadir>/packs/<pack>/`); empty means the
  service state dir.

**At run time** (`server/services/`, #515), and this is the contract a pack
author writes against:

- the process is started by the gateway's supervisor, which reconciles what the
  packs declare with what is alive: declaring a service is enough to have it
  started at boot and at install, and removing the pack stops it;
- it runs under a **dedicated OS user** of its own, and its environment is built
  from scratch — `PATH`/`PYTHONPATH` of the pack runtime, `HOME` and
  `CLODIA_SERVICE_STATE_DIR` (the directory above, the only writable one it
  gets), `CLODIA_SERVICE_PACK`, `CLODIA_SERVICE_NAME`, and one
  `CLODIA_CREDENTIAL_<NAME>` per declared credential, holding that vault entry
  as JSON. Nothing of the gateway's own environment reaches it;
- a declared credential that is not in the vault keeps the service **stopped**:
  a process that is up and fails every call is worse than one that says why;
- the `health.target` must be on **loopback**: a service is reachable by the
  gateway only, and a health check pointing outside declares the opposite;
- `stdout`/`stderr` go to `service.log` inside the state dir, rotated past
  5 MB into `service.log.1` (one kept);
- before the first isolated start the gateway checks that the service uid
  **cannot** read a 0600 file of the gateway (`services/.isolation-probe/`). If
  it can — storage that ignores permission bits, as OrbStack virtiofs on terra
  (clodia-platform#544) — no service starts: each is `blocked` with
  `isolation unavailable: …`, `isolation: unavailable` on the Tools page, and
  one CRITICAL log line;
- the credentials and the `workdir` are checked again at launch, the
  `workdir` after resolving symlinks: it must stay inside the pack directory
  or the state dir;
- a service must listen on loopback only: a TCP socket of its uid in LISTEN
  outside loopback stops it (`blocked`, with backoff). UDP is not checked;
- a transient registry error keeps the running services as they are;
- status, last error and restart count appear on the Tools page
  (`GET /tools`, `GET /internal/connectors`).

## The gateway's own manifests

`connectors/builtin_manifests/*.yaml` are manifests the gateway ships with
itself (#518). They are read with the same grammar and land in the same
registry; they are what the PDP reads while a connector is still implemented in
gateway code rather than in a pack:

| file | holds | leaves with |
|---|---|---|
| `core.yaml` | `http:`, `https:`, `topic:`, `mcp:` | never: this is the core manifest |
| `mail.yaml` | the mail vocabulary and `email.*` | #522 |
| `telegram.yaml` | `tg:` and `telegram.*` | #522 |
| `google.yaml` | `gdrive:`, `gsheets:`, `gcal:` and their verbs | #523 |
| `github.yaml` | the GitHub verbs on `https:`, and its warning | #525 |
| `datastore.yaml` | `datastore:` and `datastore.read` | — |

They are code, not input: they live in the image, next to the modules that
implement them. Three privileges follow, and nothing on disk can obtain them:
they may declare the intrinsic schemes, they are not checked against the
reserved namespaces (they *are* the gateway's namespaces, and one file may span
several), and they **win** a collision — a pack declaring the same connector id
or the same scheme is refused on its own, without taking the registry down with
it. Letting the pack win would mean an installed manifest redefining what
`mailto:` means while the native implementation is still the thing doing the
sending. Each migration deletes its file in the change that adds the pack.

---

## Examples

They describe the **end state** of the epic, the one the migrations #522–#525
lead to: `telegram.`, `mail.` and `github.` are namespaces of packs there, not of
the gateway. Validated today against the core namespaces they would of course
collide with the native verbs that still exist — which is exactly what
`check_namespace` is for, and what each migration removes on its way out.

### comms-pack — Telegram, and the mail vocabulary with its IMAP provider

```yaml
name: comms-pack
connectors:
  - id: telegram
    manifest_version: 1
    namespace: telegram
    label: Telegram
    schemes:
      - scheme: tg
        direction: both
        label: Telegram chat
        # Verbatim from `egress._DANGER["tg"]`, in the language the owner reads
        # it at the gate: the example is the declaration, and a translated
        # sentence here would be a different thing to consent to.
        danger: "una chat su Telegram, cioè su un'infrastruttura non tua."
        forms:
          - label: group
            pattern: '^-?\d+$'
            example: '-1001234567890'
          - label: person
            pattern: '^@[A-Za-z0-9_]{5,32}$'
            example: '@dadabit'
    providers:
      - id: bot
        label: Telegram bot
        status_verb: telegram.status
        credential:
          kind: form
          vault_entry: telegram_bot_token
          fields:
            - name: token
              label: Bot token
              secret: true
              placeholder: '123456:ABC-DEF…'
    verbs:
      - verb: telegram.send
        direction: egress
        scheme: tg
        arg: chat_id
        dtype: telegram
      - verb: telegram.send_file
        direction: egress
        scheme: tg
        arg: chat_id
        dtype: telegram
    # The two things the gateway knows and the pack's process cannot: which
    # room the call comes from (`telegram.send` without `chat_id` goes to the
    # chat bound to it) and who is calling (the per-chat lease is held by an
    # agent, by name). Filled by the gateway on every `telegram.*` call, over
    # whatever the caller sent.
    context:
      channel: channel
      agent: agent
    # `telegram.send_file` manda un file che sta in un topic. Il path lo nomina
    # l'agente, i byte li mette il gateway: leggere un file di topic è lavoro
    # suo — ci stanno attaccati il compartimento e l'audit di ciò che esce.
    # `chat_id` omesso = la chat legata al topic da cui si chiama. Lo risolve
    # il gateway, che è l'unico a tenere il registro dei binding; un esplicito
    # del chiamante vince, se no non si potrebbe più scrivere altrove.
    defaults:
      - verb: telegram.send
        arg: chat_id
        value: binding
      - verb: telegram.send_file
        arg: chat_id
        value: binding
    files:
      - verb: telegram.send_file
        path_arg: path
        bytes_arg: content_b64
        name_arg: filename
        tier_arg: tier
        topic_arg: name
        chat_arg: chat_id
    # No `telegram.read`: today no Telegram read goes through
    # `_RESOURCE_READ_VERBS`, so declaring one would add a check that does not
    # exist — inside a migration (#522) whose whole point is parity. What the
    # incoming side does have is the taint below.
    taint:
      - telegram.inbox
      - telegram.receive
      - telegram.pull
    topic_actions:
      - id: telegram-link
        label: Link a Telegram chat
        binding: channel
        fields:
          - name: chat_id
            label: Chat id or @handle
        adds:
          ingress:
            - 'tg:{chat_id}'
          egress:
            - 'tg:{chat_id}'
    tools_card:
      setup_label: Connect a bot
      status_verb: telegram.status

  - id: mail
    manifest_version: 1
    namespace: mail
    label: Email
    schemes:
      - scheme: mailto
        direction: egress
        label: Recipient
        danger: >-
          an email address. Once sent, the message cannot be recalled and a copy
          stays on the recipient's server.
        forms:
          - label: address
            pattern: '^[^@\s]+@[A-Za-z0-9.-]+$'
            example: 'someone@example.org'
      - scheme: mailfrom
        direction: source
        label: Vetted sender
        forms:
          - label: address
            pattern: '^[^@\s]+@[A-Za-z0-9.-]+$'
            example: 'someone@example.org'
      - scheme: outbox
        direction: egress
        label: Mailbox that sends
        forms:
          - label: address
            pattern: '^[^@\s]+@[A-Za-z0-9.-]+$'
            example: 'studio@example.org'
      - scheme: inbox
        direction: source
        label: Mailbox that is downloaded
        forms:
          - label: address
            pattern: '^[^@\s]+@[A-Za-z0-9.-]+$'
            example: 'studio@example.org'
    providers:
      - id: imap
        label: IMAP/SMTP mailbox
        credential:
          kind: form
          vault_entry: mail_imap
          fields:
            - name: address
              label: Email address
            - name: imap_host
              label: IMAP host
            - name: smtp_host
              label: SMTP host
            - name: password
              label: Password
              secret: true
    verbs:
      - verb: mail.send
        direction: egress
        scheme: mailto
        arg: to
        multi: true
        dtype: email
      - verb: mail.reply
        direction: egress
        scheme: mailto
        arg: to
        multi: true
        dtype: email
      - verb: mail.read
        direction: source
        scheme: inbox
        arg: account
    topic_actions:
      - id: mailbox-link
        label: Link a mailbox
        fields:
          - name: address
            label: Mailbox address
        adds:
          ingress:
            - 'inbox:{address}'
          egress:
            - 'outbox:{address}'
    tools_card:
      setup_label: Add a mailbox
```

### google-pack — Drive and Sheets, Gmail as a second provider of `mail`, topic storage

Note `mail-gmail`: a different pack, the same vocabulary, and not one line of it
redefines a scheme or a verb.

```yaml
name: google-pack
connectors:
  - id: google
    manifest_version: 1
    namespace: google
    label: Google Workspace
    schemes:
      - scheme: gdrive
        direction: both
        label: Drive folder or file
        hierarchical: true
        forms:
          - label: folder
            pattern: '^folder/[\w-]+$'
            example: 'folder/1AbCdEfGhIjKlMnOpQrStUv'
          - label: file
            pattern: '^file/[\w-]+$'
            example: 'file/1AbCdEfGhIjKlMnOpQrStUv'
        canonicalise:
          - from: '^gdrive://([\w-]+)/?$'
            to: 'gdrive:folder/{1}'
      - scheme: gsheets
        direction: both
        label: Google spreadsheet
        danger: 'a Google spreadsheet. If it is shared, anyone with the link sees it.'
        forms:
          - label: spreadsheet
            pattern: '^[\w-]+$'
            example: '1AbCdEfGhIjKlMnOpQrStUv'
        canonicalise:
          - from: '^gsheets://([\w-]+)/?$'
            to: 'gsheets:{1}'
      - scheme: gcal
        direction: egress
        label: Google calendar
        danger: >-
          a Google calendar: approving it grants reading the agenda — titles,
          places and guests — and writing events, which reach the guests as an
          invitation. It cannot be confined to a folder: the perimeter is the
          calendar itself.
        forms:
          - label: calendar
            pattern: '^[^\s/]+$'
            example: 'primary'
    providers:
      - id: workspace
        label: Google account
        credential:
          kind: oauth
          authorize_url: https://accounts.google.com/o/oauth2/v2/auth
          token_url: https://oauth2.googleapis.com/token
          scopes:
            - https://www.googleapis.com/auth/drive
            - https://www.googleapis.com/auth/spreadsheets
            - https://www.googleapis.com/auth/calendar
    verbs:
      - verb: google.drive_upload
        direction: egress
        scheme: gdrive
        arg: folder_id
        template: 'gdrive:folder/{value}'
        dtype: drive
      - verb: google.drive_share
        direction: egress
        scheme: gdrive
        arg: folder_id
        template: 'gdrive:folder/{value}'
        dtype: drive
      - verb: google.sheets_append_rows
        direction: egress
        scheme: gsheets
        arg: spreadsheet_id
        dtype: gsheets
      - verb: google.calendar_insert
        direction: egress
        scheme: gcal
        arg: calendar_id
        dtype: gcal
      - verb: google.drive_read
        direction: source
        scheme: gdrive
        arg: folder_id
        template: 'gdrive:folder/{value}'
    topic_actions:
      - id: drive-link
        label: Link a Drive folder
        fields:
          - name: folder
            label: Folder URL or id
        adds:
          ingress:
            - 'gdrive:folder/{folder}'
          egress:
            - 'gdrive:folder/{folder}'
    storage_remote:
      id: gdrive
      label: Google Drive
      versioning: true
    tools_card:
      setup_label: Connect Google
      docs_url: https://developers.google.com/workspace

  - id: mail-gmail
    manifest_version: 1
    namespace: google
    label: Gmail
    extends: mail
    providers:
      - id: gmail
        label: Gmail account
        credential:
          kind: oauth
          authorize_url: https://accounts.google.com/o/oauth2/v2/auth
          token_url: https://oauth2.googleapis.com/token
          scopes:
            - https://www.googleapis.com/auth/gmail.modify
```

### it-pack — GitHub on the platform `https` scheme, and a credential-only connector

```yaml
name: it-pack
connectors:
  - id: github
    manifest_version: 1
    namespace: github
    label: GitHub
    providers:
      - id: pat
        label: Personal access token
        credential:
          kind: form
          vault_entry: github_pat
          fields:
            - name: token
              label: Personal access token
              secret: true
    verbs:
      - verb: github.push
        direction: egress
        scheme: https
        arg: repo
        template: '{value}'
        dtype: github
      - verb: github.pull_request
        direction: egress
        scheme: https
        arg: repo
        template: '{value}'
        dtype: github
    taint:
      - github.
    tools_card:
      setup_label: Paste a token

  - id: openai-images
    manifest_version: 1
    namespace: imagegen
    label: Image generation (OpenAI)
    providers:
      - id: openai
        label: OpenAI API key
        credential:
          kind: form
          vault_entry: imagegen_openai
          fields:
            - name: api_key
              label: API key
              secret: true
    tools_card:
      setup_label: Paste an API key
```

---

## Known gaps of v1, deliberately left open

- **Shorthand normalisation for GitHub repositories.** Answered by #518, and the
  answer is `normalise: repo_url`: a verb mapping NAMES one of the gateway's own
  transforms instead of supplying it. `owner/repo` still becomes a full URL
  through `github_repo.normalize_repo` — letting a pack rewrite `https:` URLs
  would hand it the meaning of every URL on the instance — and the list of
  transforms is closed, in `manifest.NORMALISERS`.
- **Who reads this.** The PDP does: #517 applies the mappings at call time and
  #518 made the registry the only place the gateway knows a connector from.
  What is still missing is the generic HTTP endpoints (#519, which also refuses
  a malformed manifest at install time — until then `pack_import` drops the
  `connectors:` block and no PACK reaches the registry) and the webui rendered
  from it (#520).
- **Install-time refusal.** `pack_import` in `clodia-logic` will ask the gateway
  to validate a `connectors:` block the way it already asks `/flow-allow` for the
  flow declarations. That endpoint is #519.
