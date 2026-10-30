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

A fourth: **verbs or taint only**, no scheme and no provider. A connector owns
one namespace, so a vocabulary used by several verb namespaces is one owner
plus siblings that map their own verbs onto it — `google-sheets` maps
`gsheets.*` onto the `gsheets:` scheme `google` declares, and
`google-calendar` declares nothing but the taint of `gcalendar.list_events`
(#524). A connector declaring none of schemes, verbs, providers, taint, and
extending nothing, is empty and refused.

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
| `taint` | no | verb names or prefixes, inside the connector's namespace, whose answers DO taint the channel they land in — content nobody vouched for (`taint.taints`); e.g. comms-pack's `telegram.inbox`, google-pack's `gcalendar.list_events` |
| `unmapped` | no | verbs of the namespace that deliberately have NO egress/source mapping (#558); see below |
| `topic_actions` | no | buttons the connector adds to a topic |
| `tools_card` | no | what the Tools page shows: `setup_label`, `status_verb`, `test_verb`, `docs_url`, `blurb`, `scope`, `icon` |
| `services` | no | long-running processes, see #515 |
| `storage_remote` | no | topic storage backend the pack provides. No consumer: topic storage on Drive was repealed (decision record #40), see #524 |
| `context` | no | call facts the gateway fills in, see below |
| `files` | no | arguments that name a TOPIC FILE, which the gateway reads and delivers as bytes |
| `defaults` | no | arguments the gateway fills **only when omitted**, see below |
| `relay` | no | a chat transport on one of the connector's `services` (#638), see below |
| `pairing` | no | a device pairing step on one of the connector's `services` (#639), see below |

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

**`transport`** (optional, pack manifests only — refused in a builtin
manifest): `{backend: <mounted MCP backend>, tool: <tool name>}`. `backend`
follows the id rule, `tool` the argument rule; no other key is accepted.

Since #558 mail no longer uses it (comms-pack 2.0.0 is a gateway component);
it stays for it-pack's images (#525), and a comms-pack 1.4.0 manifest that
declares one remains valid. The original design, for reference — it existed
for a connector whose verbs the gateway keeps (#523, mail): before
any byte of a mailbox comes back the gateway takes decisions that belong to the
reference monitor — the mailbox whitelist (`inbox:`/`outbox:`), strict ingress
and its audit record (#503), topic attachments in and out with their taint, the
reply recipient — so the verbs `email.*` stay in the gateway and only the I/O
moves. The gateway, inside each verb and after every one of those checks, calls
`<backend>.<tool>` of the pack connector it holds for that id, with:

```
{"argv":   ["--account", "<account>", "<operation>", ...],
 "files":  {"secrets/<rel>": "<base64>", "att/<n>/<name>": "<base64>"},
 "timeout": <seconds>}
```

`files` carries only **that call's** credential (the files the gateway
materialised for one mailbox) and the attachments; `{dir}` in `argv` stands for
the directory where the transport writes them, and `secrets/` is the secrets
directory the client reads. The transport answers with the JSON text
`{"returncode": <int>, "stdout": "...", "stderr": "..."}`, which the gateway
parses and filters exactly as it filters its in-process client's output.

Three rules hold it in place. The transport is used only when the named backend
is **the pack's own mount** (the `pack:` stamp of the mount): a manifest naming
somebody else's backend would be a way to have a credential delivered there. In
`pack` position with no usable transport — pack missing, connector refused,
backend not the pack's — every `email.*` call is refused, never served by the
in-process client. And a transport backend is a socket of the gateway, not a
verb: its tools are not listed to anybody, and a call to `<backend>.<tool>`
from an agent or a person is `DENIED`.

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

### `unmapped[]`

A list of exact verb names of the connector's namespace that have no
destination and no source the PDP reads — `gdrive.list`, `gdocs.append_text`:
an id inside a perimeter the implementation enforces itself, a query, a
calendar the component checks against `gcal:`. It changes no PDP answer.
It exists because a **gateway component's** verb is served only when the
(pinned) manifest classifies it — an egress or source mapping, a taint prefix,
or this entry (`components.loader._classified`): an unclassified component
verb is denied, so «the PDP has nothing to read here» has to be written down in
the reviewed manifest rather than inferred from an absence. The namespace rule
applies, a verb may not be both mapped and `unmapped`, and a name is listed
once.

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

### `context[]`

Facts about the call in progress that the **gateway** fills in, one row per
argument (`arg` + `value`). `value` is one of a closed list — today `channel`
(the room the call comes from, `TIER/name`) and `agent` (who is calling).

```
context:
  - arg: channel
    value: channel
  - arg: agent
    value: agent
```

This is not a convenience. A native verb reads both from the process: the
channel is a **signed claim** and the agent an authenticated identity, so no
caller can lie about either. A pack's MCP server has neither, and if the agent
passed them they would be ordinary arguments — forgeable — and «send this to
this topic's chat» would become «send this to whichever chat I name», which is
the defect that produced the messages to the wrong group on 23 Sep 2026.

So the gateway fills them, and **overwrites** whatever the caller sent. It does
not prefer the caller's value, and it does not fall back to it: a fallback is
the same forgery with one more step, reachable by calling from wherever the
gateway has no answer. When the gateway genuinely has no answer — there is no
channel outside a room — the argument is **removed** rather than blanked, so
the connector can tell «I don't know» from «it is empty».

The rows apply to every verb of the connector's namespace, not only to the ones
listed in `verbs:`: an inbound verb declares no destination and still needs to
know who is asking. They belong to the pack that **owns the vocabulary**; a
contributor (`extends`) may not declare them.

An `arg` that a verb mapping reads its destination from is **refused**. A
destination is a property of the call — it is what the owner reads on the gate
card and what the whitelist compares — and letting the manifest write it would
mean the manifest decides where the call goes. It is also how the PDP would be
disarmed in silence: a fact the gateway has no answer for empties the argument,
and an extractor with no value is a verb with no declared destination.

### `defaults[]`

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

### `files[]`

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

### `relay` (clodia-platform#638)

A connector that brings a **chat channel** declares the transport. The
transport is one of the connector's own `services` (#515), reachable by the
gateway only, on loopback:

```
    relay:
      service: sms-relay            # one of THIS connector's services
      base: http://127.0.0.1:8731   # http, loopback host, a port; nothing else
      label: SMS                    # how the transport is named in the room
      attachments: false            # default false: no /download
      seal_cap: SEAL-1              # optional, SEAL-0 … SEAL-4; default SEAL-1
```

The service named by `relay.service` (and `pairing.service`) must declare an
`http` or `tcp` `health` check whose host and port are exactly those of
`base`: the health target is the address the supervisor verifies, and a base
pointing anywhere else would forward to whatever else listens on loopback.
Two connectors may not point a relay or pairing `base` at the same loopback
port (every loopback name is the same socket), and no two services of the
instance — any pack, relay or not — may declare the same `http`/`tcp` health
address; both packs are refused.

**SEAL cap.** Binding a room to a relay is capped like Telegram (#405): above
`seal_cap` — or SEAL-1 when the manifest names none, fail closed — the owner
must acknowledge the downgrade (`accept_seal_downgrade`) with the room's tier
shown, and the acknowledgement is dropped on disconnect. The cap is reported in
the topic action's `seal` state and in the listing's `relay.seal_cap`.
Acknowledgements are kept per connector (`channel_seal_ack: {<connector>:
{…}}`; the older single slot is read as Telegram's), and disconnecting a
channel withdraws only its own. Re-classifying a room carries every
connector's bindings to the new tier; climbing above a pack relay's cap is
refused unless the owner acknowledges it again (`accept_seal_downgrade` on the
retier), recorded at the new tier. This is
the one place a SEAL value appears in a manifest; a connector-level
`seal_cap` stays refused.

Also refused at load when: the connector `extends` another (a transport speaks the
vocabulary's URIs, and the vocabulary is its owner's); it is a gateway
manifest; `service` is not one of the connector's services; `base` is not
`http://<127.0.0.1|localhost|[::1]>:<port>` with no path, query, fragment or
userinfo; `label` is empty or longer than 32 characters; none of the
connector's schemes declares `forms` (the gateway vets every relayed URI
against them); an unknown key appears.

**Transport contract** — HTTP JSON on `base`, called by the gateway only.

**Authentication (MUST).** At every start the supervisor generates a random
secret for the service and passes it in the environment as
`CLODIA_SERVICE_TOKEN`; the gateway keeps it in memory and sends it as the
header `X-Clodia-Service-Token` on every call it forwards (relay and pairing).
A relay or pairing service **must refuse** (401) any request whose header does
not match, comparing in constant time (`hmac.compare_digest`): loopback is
reachable by every service uid, so «it came from 127.0.0.1» does not mean «it
came from the gateway». The token changes at every restart; never log it.


| Service endpoint | Body | Answer |
|---|---|---|
| `POST /poll` | `{timeout, ack?}` | `{messages: [row…], cursor?}`; each row carries `chat_id`, `chat_uri` (= `<scheme>:<chat_id>`) and `sender_uri` in the connector's own scheme. `ack` is the `cursor` of the previous poll: the service drops the rows it covers |
| `POST /send` | `{chat_id, text, thread_id?}` | `{ok, message_id}` |
| `POST /download` | `{file_id}` | `{content_b64, size, mime}` — only with `attachments: true` |

**Gateway side.** `POST /internal/channels/<connector>/{poll,send,download}`
(same authorisation as `/internal/telegram/*`: the agent-server's privileged
principal) forward to `<base>/<operation>` for a connector the live registry
accepted with `relay:`, and for no other path. Unknown connector, no `relay:`,
or `download` without `attachments` → 404; the service not running or not
answering → 503. On `poll` the gateway keeps a row only if its `chat_uri`
**and** its `sender_uri` (when present) parse in one of the connector's OWN
schemes and match one of that scheme's `forms`, and its `chat_uri` is exactly
`<scheme>:<chat_id>` with the row's own `chat_id` (the chat a reply goes to is
the chat that was vetted); any other row is dropped and logged, without its
values. Nothing else in a row is identity.

The gateway route takes `{timeout, ack?}` and answers `{messages, count,
cursor?}`: `ack` is passed through to the service, and the service's `cursor`
comes back **whatever rows were dropped** — a dropped row is acknowledged like
a kept one, and a lost cursor would make the service send the same rows
forever. `ack` and `cursor` are opaque printable strings of at most 512
characters; a cursor that is not is dropped and logged, an `ack` that is not is
a 400.

`GET /internal/connectors` shows `relay: {label, attachments, schemes,
seal_cap}` for such a connector — never `base` or the port. A topic action with `binding: channel`
writes its binding under its own connector id, and `channel.deliver` reaches
any scheme of a relay connector through the same `send` path, under the same
egress decision as a Telegram delivery (`channel.relay_send`, mapped in the
core manifest; its profile question is asked of `channel.deliver`). A
destination whose scheme belongs to any connector is never mailed: without a
usable relay the delivery is refused. A relayed message is posted with `kind: channel` and
`transport: <label>`; like `telegram`, it does not taint the room, because the
sender was vetted against the room's ingress before it was posted.

### `pairing` (clodia-platform#639)

A transport that needs a **device pairing** step after the credential is saved
(a linking code typed on a phone, a QR to scan) declares where its service
exposes it:

```
    pairing:
      service: sms-relay
      base: http://127.0.0.1:8731
      status: /status      # GET  → {state, code?, qr?, me?, error?}  (default /status)
      start: /pair         # POST → starts pairing                    (default /pair)
```

Same refusals as `relay` for `extends`, gateway manifests, `service` and
`base`; `status`/`start` must be plain paths. `GET` and `POST
/tools/connectors/<id>/pairing` are for a **human admin only** and forward to
`status` and `start`. Only `state`, `code`, `qr`, `me` and `error` come back,
each a length-capped string; the code and the QR are never logged or audited
by value. A connector without `pairing:` → 404; the service down → 503; a
4xx answer of the service comes back with its status, through the same field
filter (except 401/403, which mean the service refused the gateway → 502).
Starting a pairing is recorded in the audit trail (`control.connector`,
`pairing_start`: connector, admin, pack — never a code).
`GET /internal/connectors` shows `pairing: true`.

### `relay`/`pairing` through a mounted MCP backend (clodia-platform#641)

A transport built on third-party code may run in **its own container** and
expose itself as an MCP server, instead of a service the gateway supervises
(which needs a storage that enforces permission bits, #544). `relay:` and
`pairing:` then name a mounted backend instead of `service`/`base`:

```
    relay:
      backend: sms-transport   # a mounted MCP backend of THIS pack
      label: SMS
      attachments: true
      seal_cap: SEAL-1         # optional, as for the service form
    pairing:
      backend: sms-transport
```

- **Exclusive forms.** A block declares either `backend` or `service`/`base`,
  never both (refused at load). With `backend` the health/port checks of the
  service form do not apply, and `pairing` takes no `status`/`start` paths.
  `backend` follows the mount slug rules: lowercase letters, digits and `-`,
  at most 40. It may not be the connector's own `namespace` (that is the
  agent-facing backend), and two connectors may not name the same backend.
- **Ownership.** The backend must be mounted with the pack's stamp
  (`pack: <pack>`, `resolved.backend_owners`); otherwise the gateway does not
  call it and answers 503. The stamp is written only for a server the
  INSTALLED pack names (`resolved.declared_backends`): its `mcp_servers`, the
  servers of its plugins (`plugin.yaml` `mcp_servers`, `.mcp.json`
  `mcpServers`), a connector `namespace`, or a transport/relay/pairing
  `backend` — for every caller (`register_mcp_core`: the Tools route and
  `mcp.add`, whose gate card names the pack being granted ownership). An
  admin mounts a pack's server with that stamp through `POST /tools/mcp
  {config: {mcpServers: {<name>: {url: …}}}, pack: "<pack>"}` (human admin
  only; recorded as `control.mcp` `mount` with the pack and who), then
  provides its credential with «Connetti» (#565). Mounting WITHOUT `pack` a
  name that an installed pack claims as its relay/pairing backend or
  connector namespace is a 409 that names the pack: a transport is never
  mounted unhidden.
- **Transport, not a verb.** A backend named by a `relay:`/`pairing:` counts as
  a transport (`resolved.is_transport_backend`, like a provider transport of
  #523): its tools are never listed to agents and an agent's call to one is
  refused. Agent-facing verbs of the same container go in a SECOND backend,
  under the ordinary PDP.

**Tool contract** — JSON arguments in, one JSON object as the tool's text out:

| Tool | Arguments | Answer |
|---|---|---|
| `relay_poll` | `{timeout, ack?}` | `{messages: [row…], cursor?}` — rows as for `/poll` |
| `relay_send` | `{chat_id, text, thread_id?}` | `{ok, message_id}` |
| `relay_download` | `{file_id}` | `{content_b64, size, mime}` (only with `attachments: true`) |
| `pairing_status` | `{}` | `{state, code?, qr?, me?, error?}` |
| `pairing_start` | `{}` | the same shape |

The gateway calls them off its event loop, with the poll timeout plus a
5-second margin, and reads an http backend's answer with a byte cap ON THE
WIRE (a larger answer is cut and is a 502, never buffered whole). A tool answering `isError` is the equivalent of a service's error: with
a JSON object as its text it is a refusal (the pairing routes return it, with
status 400, through the same field filter), otherwise 502; the backend not
mounted, not the pack's, or not answering is 503; a backend that does not
serve the tool (JSON-RPC error) or whose session the vault rules refuse (#568)
is a 502 that says so. Row vetting, `ack`/`cursor`,
the SEAL cap, bindings, the `channel` kind and the pairing audit are exactly
those of the service form.

## Components (`components:`, clodia-platform#558)

Owner decision of 2026-10-16: a pack is a **distribution of components**, each
mounted in the container it belongs to. `connectors:` says what a connector *is*
(schemes, mappings, taint, cards); `components:` says where its *code* runs.

```yaml
name: weather-pack
first_party: true
connectors:
  - id: weather
    manifest_version: 1
    namespace: weather
    label: Weather
    verbs:
      - verb: weather.fetch_report
        direction: egress
        scheme: https
        arg: url
        template: '{value}'
    taint:
      - weather.
components:
  - id: gateway
    target: gateway
    source:
      repo: r-clodia/clodia-logic
      path: catalogs/packs/weather-pack/gateway
      ref: main
    entry: weather_component
    connectors: [weather]
    credentials: [weather_]
  - id: skills
    target: agent-server
  - id: card
    target: webui
```

Each entry has an `id` (unique in the pack) and a `target`: `gateway`,
`agent-server` or `webui`. The gateway parses only `target: gateway` entries,
strictly; the others are left to the container that mounts them. A pack has
**at most one** `target: gateway` component.

### `target: gateway`

| Field | Meaning |
|---|---|
| `source.repo` | `<owner>/<repository>` on GitHub; must EQUAL the pack's upstream in `FIRST_PARTY_SOURCES`. |
| `source.path` | Directory of the component; must lie under the pack's directory in that repository. |
| `source.ref` | Must be the repository's **default branch**. Pinned to its head; moves only on a refresh. |
| `entry` | Dotted Python module path inside the component; it defines `register(host)`. |
| `connectors` | Ids of connectors declared by **this** pack whose verbs the component implements. It may register verbs only in their namespaces. |
| `credentials` | Vault prefixes (ending in `_`) or exact entry names the component may use through `host.credentials(...)`. |

Any other key is refused, and so is the entry alone (never the pack, never the
other components).

### The security boundary is provenance

A gateway component runs **in the gateway's process, with the gateway's
privileges**. Neither the host API nor the import guard is a sandbox, and
nothing here pretends otherwise. What makes it acceptable is *where the code
comes from*:

1. **A table in gateway code**, `connectors.builtin.FIRST_PARTY_SOURCES`:
   `{pack: (repository, pack directory)}`. Only packs listed there have gateway
   components; `source.repo` must equal the repository and `source.path` must
   lie under the directory. The pack manifest must also say
   `first_party: true`, and the repository's organisation must be in the
   allowed list (gateway config `components.allowed_orgs`, else
   `CLODIA_COMPONENT_ORGS`, else `r-clodia`) — a secondary check that can only
   narrow the table. `trust.owner_approved` is a hook for a future SYSTEM gate
   for third-party components; it refuses today.
2. **Merged code only**: `source.ref` must be the default branch, and what is
   pinned is its head.
3. **The pinned manifest governs.** The datadir `pack.yaml` (written by the
   agent-server) only *triggers* the fetch. The gateway reads
   `<pack directory>/pack.yaml` from the same tarball at the same commit,
   stores and hashes it with the pin, and from then on
   `connectors.resolved.manifests()` serves THAT copy for the pack —
   connectors, mappings, taint, components, entry, credentials. A rewritten
   datadir manifest cannot drop the mapping the PDP uses to check a
   component's verb, nor change the code that runs.
4. **No downgrade.** `floors.json` keeps, per (pack, id), the highest commit
   ever pinned — it survives uninstalling the pack. A new commit must descend
   from it (`compare(floor...new)` is `ahead`/`identical`); a rewound upstream,
   a re-install or a repository change is refused unless the owner refreshes
   with `allow_downgrade`, which lowers the floor.
5. **Review upstream** is what the commit stands for.

Then the state dir must be isolated from the datadir (#80), and the fetch is
defensive: the tarball is streamed and cut at 64 MB; only `source.path` is
extracted (regular files only — no links, no `__pycache__`, `.pyc` or native
libraries — with size caps); a `.gitattributes` with `export-ignore` or
`export-subst` at the repository root or on the way to the pack refuses the
fetch, because the archive would differ from the reviewed tree. The tree and
the manifest are hashed into `pins.json` and re-hashed before every import.
A GitHub token is not needed for a public repository; for a private
first-party one the vault's `github_pat` is used, never on a redirect.

**Defence in depth at call time.** A component verb is served only while the
pack's connector for its namespace is held in the registry AND the (pinned)
manifest classifies the verb — an egress or source mapping, or a taint prefix
covering it. An unclassified component verb is DENIED.

**Load** (`loader.py`). At startup and whenever the installed manifests change,
the entry module is imported as `clodia_components.<pack>.<id>.<entry>` and
`register(host)` is called. Import your own modules relatively
(`from . import helper`): the component directory is not on `sys.path`. A
failing import or `register` disables **that component only** — logged
CRITICAL, shown by `GET /internal/components`, and every verb in its
connectors' namespaces answers `DENIED` with the reason (never a native or
mounted-backend verb).

**Import guard** (`guard.py`) — **advisory**. Before the import, every `.py`
file of the tree is parsed and the load is refused if one imports `server`,
`server.vault`, `server.state_paths`, `server.whitelist`, `server.gate`,
`server.egress` or `server.main` (also via `from server import …`, or
`importlib.import_module`/`__import__`, a non-literal target included). It
catches mistakes and makes review easier. It does not contain a component that
wants out: in-process Python can reach anything the gateway can. The boundary
is the provenance above.

### The host API (`server/components/host.py`)

The only thing a component gets:

```python
host.register_verb(tool: mcp.types.Tool, handler, *, offload=True)
host.register_route(path, methods, handler, *, auth="owner")   # or "admin"
host.register_service(name, handler)            # called by the GATEWAY, never an agent
host.credentials(prefix) -> ScopedCredentials   # list/has/read/read_internal/deposit/remove
host.perimeter.gdrive_roots() -> dict           # the gateway config's `gdrive_roots` (a copy)
host.perimeter.egress_uris(scope=None) -> list[str]        # global + room egress list
host.perimeter.approved_calendars(scope=None) -> list[str] # `gcal:` approvals
host.perimeter.calendar_allowed(calendar_id, scope=None) -> bool
host.perimeter.topic_drive_folders(tier, name) -> list[dict]   # topic `meta.drive_folders`
host.perimeter.in_channel() -> bool             # the call comes from a topic channel
host.perimeter.mailbox_allowed(direction, address, scope=None) -> bool  # inbox:/outbox: (#558, mail)
host.perimeter.strict_scope() -> str | None     # the room, if strict ingress (#503)
host.perimeter.address_of(header) -> str        # the PDP's `From:` parser
host.perimeter.source_vetted(uri, scope=None) -> bool   # e.g. `mailfrom:a@b.it`
host.perimeter.legacy_mail_accounts() -> dict   # {account: address|None}, names only
host.topics.read_file(tier, name, path, *, crossing="file") -> bytes   # crossing=None: caller notes it
host.topics.put_file(tier, name, path, data, *, provenance="untrusted")
host.note_crossing(data=None, *, path=None, kind="file")
host.scratch_path(path) -> str
host.config(key, default=None); host.set_config(key, value)   # owner routes only
host.agent(); host.channel(); host.principal(); host.log
host.current_topic() -> (tier, name) | (None, None)   # the room of the signed claim
host.tool_allowed(verb)                          # the whitelist's answer; raises PermissionError
host.audit_decision(verb, kind, result, *, reason_class=None)  # raises host.AuditUnavailable
host.service(pack, name) -> callable | None     # ANOTHER pack's service, granted pairs only
```

- **Verbs** join the catalogue next to the native ones and run through the same
  `call_tool` path: whitelist, deny, unattended block, gates, the egress PDP
  and taint from this pack's `connectors:` mappings, audit. The dispatcher
  calls the handler where it calls a native one. A verb is served only while
  the pack's connector for its namespace is held in the registry; a native verb
  name or a core namespace is refused at registration. Registration closes
  when `register` returns.
- **Routes** are mounted at `/tools/<pack>/<path>`, after every core route.
  Both `owner` and `admin` require a **human** admin (or the trusted core's UI
  token) — never a super-agent, never the agent-server's service role — and
  every call is audited (`control.component`). Only `owner` routes may write the
  component's config. There is no public route.
- **Credentials**: a prefix must be declared, and must be usable *now*: inside
  the namespace of one of the component's connectors; or a core prefix
  (`telegram_`, `github_`, …) released by the connectors of this very pack
  (`builtin.released_to`); or a gateway-custody entry listed in
  `builtin.CORE_CREDENTIALS_FOLLOW` (e.g. `google_`, `app_google_oauth`) whose
  connector is this pack's (`builtin.RELEASED_TO`). Checked again at every
  call. `read` enforces the calling agent's vault grant;
  `read_internal` is the component's own infrastructure read.
- **Topics**: membership/clearance checks (`_require_topic_member`), crossing
  notes on reads, `untrusted` writes taint the room; a component cannot label a
  file `trusted`.
- **Services** (#558, google-pack): named callables the gateway's OWN code
  calls where it needs the connector — `components.service(pack, name)`, None
  when the component is not serving (the caller then fails closed). The names
  are fixed by the gateway code that calls them; no agent reaches them. Same
  registration rules as verbs (closed after `register`, once per name). The
  service `pdp_arguments(verb, arguments) -> dict` is generic: the dispatcher
  calls it before the egress PDP of a component verb and takes from its answer
  ONLY the arguments a destination mapping of that verb reads (a failing
  service refuses the call: the destination would be unknown). A destination
  argument the verb's own schema does not offer (`gdrive.update`'s
  `folder_id`, `email.reply`'s `to`/`bcc`) is a fact the gateway establishes:
  the caller's value is dropped, never kept.
- **Another pack's services** (#558, mail): `host.service(pack, name)` looks up
  a service of ANOTHER pack's serving component, only for the pairs
  `builtin.COMPONENT_SERVICES` grants (code, closed by default; today
  comms-pack → google-pack's `mail_accounts` and `mail_exec`). Anything else
  is a `HostError`; a component not serving is None, and the caller fails
  closed. It lets each pack keep to its own credentials: comms-pack never
  reaches a Google refresh token, it asks google-pack to run the client.
- **Perimeter**: read-only facts the gateway holds and the agent-server cannot
  write — the config's `gdrive_roots`, the egress/source lists in force for the
  call, `gcal:` approvals, a topic's `drive_folders`, whether the call comes
  from a signed channel claim; for mail (#558) whether a mailbox is usable in a
  direction (`inbox:`/`outbox:`), the strict-ingress room of the call, the
  `From:` parser and the vetted-source answer, and the NAMES and addresses of
  the legacy accounts of `secrets/email_config.json` (never the file). Read
  live, per call; nothing in it writes.
- **Decisions on record** (#558, mail): `host.audit_decision` writes a
  `policy.decision` (e.g. the strict-ingress `filter`/`deny`, #503) and raises
  `host.AuditUnavailable` when the trail cannot be written, so a component
  whose decision must be recorded before it acts can refuse, as the native
  code did. `host.tool_allowed(verb)` answers the whitelist for a lookup made
  on the agent's behalf under another verb's authority (`email.reply` reads the
  message it answers as `email.read`). `host.current_topic()` is the room of
  the signed claim, for verbs whose topic defaults to the caller's.
- **Reserved namespaces.** A trusted, pinned component whose connectors'
  namespaces are ALL the gateway's own (`core_namespaces`) is not imported:
  status `refused`, no verb, route or service, nothing denied (the gateway's
  verbs serve). A component of several connectors registers only the ones
  that are free (`host.serves`). (Until #526 this was the `standby` of a
  connector switch on `native`; the switch is retired.)
- **No bytecode.** Modules under `clodia_components.*` are loaded by a finder
  that never writes `__pycache__`: a component importing its modules after
  `register` (or lazily) would otherwise change the pinned tree and fail its
  own integrity check at the next reconcile.

### Endpoints

- `GET /internal/components` (admin): status of every gateway component.
- `POST /internal/components/<pack>/refresh` (human admin or trusted core,
  audited): re-resolve the head of the pack's default branch and reload, after
  a pack Update. `{"allow_downgrade": true}` lowers the floor.

**After a pack Update.** The first time a gateway sees a `target: gateway`
component in an installed manifest it fetches and pins it by itself (next
reconcile, at most `CLODIA_COMPONENT_INTERVAL` seconds, default 60). It never
moves an existing pin by itself: after an Update the owner asks for it, because
moving code inside the reference monitor is a human decision and the
agent-server's service role is refused here. The agent-server's Update answer
names the call (`gateway_components.refresh`); until the webui makes it a
button, the owner runs it with their own session token:

```sh
curl -sS -X POST -H "Authorization: Bearer $OWNER_SESSION_TOKEN" \
     https://<gateway>/internal/components/google-pack/refresh
# then check: GET /internal/components  →  status "loaded"
```

## The gateway's own manifests

`connectors/builtin_manifests/*.yaml` are manifests the gateway ships with
itself (#518). They are read with the same grammar and land in the same
registry:

| file | holds |
|---|---|
| `core.yaml` | `http:`, `https:`, `topic:`, `mcp:` and `web.post`: the core manifest |
| `datastore.yaml` | `datastore:` and `datastore.read` |

Both are schema-only (no provider, no Tools card): the edition's
`integrations.connectors` never filters them (`instance_profile
.connector_allowed`), because every whitelist is written in their schemes.

They are code, not input: they live in the image. Three privileges follow, and
nothing on disk can obtain them: they may declare the intrinsic schemes, they
are not checked against the reserved namespaces (they *are* the gateway's
namespaces), and they **win** a collision — a pack declaring the same
connector id or the same scheme is refused on its own, without taking the
registry down with it.

### The first-party connectors (#522–#526)

Mail, Telegram, Google, GitHub and image generation used to be builtin files
here too. The migrations of the epic #527 moved each into a first-party pack —
comms-pack (`mail`, `telegram`), google-pack (`google`, `google-sheets`,
`google-docs`, `google-calendar`, and Gmail's `mail-gmail`), it-pack
(`github`, `openai-images`) — whose **gateway component** implements the
verbs inside the reference monitor (see «Components»). For a while an
instance switch (`profile.yaml`, `connectors: {<id>: native|pack}`) chose per
connector between the gateway's code and the pack's; the native code is gone
and #526 retired the switch. A profile that still carries `connectors:` keeps
loading; a `native` value is ignored with one boot warning.

What the gateway keeps about them is in `connectors/builtin.py`, as code:

- **Who owns them.** `RELEASED_TO` names the ONE pack each connector belongs
  to, and `RELEASED_NAMESPACES` its namespace (`email`, `telegram`, `github`,
  `openai`, `gdrive`, `gsheets`, `gdocs`, `gcalendar`). Any other pack that
  declares one of those connector ids or namespaces has that entry stripped
  before the registry is built (`resolved._strip_foreign_claims`), and the
  install preview reports it as `ignored`: a third-party pack can never answer
  `email.send` or receive `github_pat`.
- **The credentials stay in the gateway's custody.** `mailbox_<acct>`,
  `google_`/`gworkspace_`/`gmail_` and `app_google_oauth` remain reserved vault
  prefixes with the same names and shapes; the owning pack's component reaches
  them through `host.credentials(...)` (`CORE_CREDENTIALS_FOLLOW`). The adopted
  entries `telegram_bot_token`, `github_pat` and `openai_api_key`
  (`ADOPTED_VAULT_ENTRIES`) keep their legacy shapes; `github_pat` and
  `openai_api_key` are still written by their legacy handlers
  (`connectors_api._LEGACY_ADOPTED`). `google` stays a reserved NAMESPACE with
  its prefix, which is why `mail-gmail` lives in `gdrive`.
- **What a pack may not choose for itself.** The browser hosts google-pack may
  canonicalise into `gdrive:`/`gsheets:` (`ELECTED_URL_HOSTS`:
  `drive.google.com`, `docs.google.com`, read from the RAW prefix of the URL),
  and the `danger_uris` of the elected connectors on a shared scheme (GitHub's
  warning on `https:`), which are only ever ADDED to the scheme's own text.
- **Retired transports.** An Update does not unmount a transport a pack no
  longer declares (`mail-transport`, comms-pack 1.4.0):
  `RETIRED_TRANSPORTS` keeps such a stamped mount gateway-internal (never
  listed, DENIED) until an admin removes it.
- **The gateway's own code** that still needs mail or Google (the mailbox
  routes and topic button, the confinement API, whitelist labels, the token
  cache, the Tools card tests) asks the component's services
  (`server/tools/mail_switch.py`, `server/tools/google_switch.py`) and fails
  closed without them. `/tools/google/{app,auth,connect}` forward to
  google-pack's component routes with the component's own authentication and
  audit; the OAuth redirect URI the owner registered points there.

---

## Examples

They describe the shape of the first-party packs (abridged): `telegram.`,
`mail.` and `github.` are namespaces of packs, not of the gateway.

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
    # `telegram.send_file` manda un file che sta in un topic. Il path lo nomina
    # l'agente, i byte li mette il gateway: leggere un file di topic è lavoro
    # suo — ci stanno attaccati il compartimento e l'audit di ciò che esce.
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
    # Who is calling, and from which room. The native verbs read both from the
    # process — the signed channel claim and the authenticated agent — and a
    # pack's MCP server has neither. Declared here, filled by the gateway, and
    # overwritten even when the caller sent them: see `context[]`.
    context:
      - arg: channel
        value: channel
      - arg: agent
        value: agent

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
        # Since #558 the IMAP/SMTP code is the pack's gateway component
        # (`components:`), not a transport.
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

### google-pack — Drive, Sheets, Docs and Calendar, Gmail as a second provider of `mail`

The shape of #524/#558: four connectors, one per verb namespace of the 24
Google verbs, plus `mail-gmail` — a different pack, the same mail vocabulary,
and not one line of it redefines a scheme or a verb — and the gateway
component that implements them. `mail-gmail` sits in `gdrive`, not in
`google`: see «The first-party connectors» for why. (Abridged: the real manifest is
`catalogs/packs/google-pack/pack.yaml` in clodia-logic.)

```yaml
name: google-pack
first_party: true
components:
  - id: google
    target: gateway
    source: {repo: r-clodia/clodia-logic,
             path: catalogs/packs/google-pack/gateway, ref: main}
    entry: google_component
    connectors: [google, google-sheets, google-docs, google-calendar]
    credentials: [google_, gworkspace_, gmail_, app_google_oauth]
connectors:
  - id: google
    manifest_version: 1
    namespace: gdrive
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
          # Read from `https:` only because the gateway ELECTS this connector,
          # and only on the hosts it pins for it (drive.google.com,
          # docs.google.com): see «The first-party connectors».
          - from: '^https?://drive\.google\.com/drive/folders/([\w-]+)$'
            to: 'gdrive:folder/{1}'
          - from: '^https?://drive\.google\.com/drive/folders/([\w-]+)[/?#].*$'
            to: 'gdrive:folder/{1}'
      - scheme: gsheets
        direction: both
        label: Google spreadsheet
        danger: 'a Google spreadsheet. If it is shared, anyone with the link sees it.'
        canonicalise:
          - from: '^gsheets://([\w-]+)/?$'
            to: 'gsheets:{1}'
      - scheme: gcal
        direction: egress
        label: Google calendar
        wildcard: false
        danger: >-
          a Google calendar: approving it grants reading the agenda — titles,
          places and guests — and writing events, which reach the guests as an
          invitation. It cannot be confined to a folder: the perimeter is the
          calendar itself.
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
      - verb: gdrive.upload
        direction: egress
        scheme: mailto
        arg: email
        dtype: drive
      - verb: gdrive.upload
        direction: egress
        scheme: gdrive
        arg: folder_id
        template: 'gdrive:folder/{value}'
        dtype: drive
      - verb: gdrive.download
        direction: source
        scheme: gdrive
        arg: file_id
        template: 'gdrive:file/{value}'
    unmapped: [gdrive.list, gdrive.search, gdrive.rename]
    topic_actions:
      - id: drive-folder
        label: Link a Drive folder
        fields:
          - name: folder
            label: Folder URL or id
        adds:
          ingress:
            - 'gdrive:folder/{folder}'
          egress:
            - 'gdrive:folder/{folder}'
    tools_card:
      setup_label: Connect Google
      docs_url: https://developers.google.com/workspace

  # Verb-only: no scheme, no provider. Its verbs point at the owner's schemes.
  - id: google-sheets
    manifest_version: 1
    namespace: gsheets
    label: Google Sheets
    verbs:
      - verb: gsheets.append_rows
        direction: egress
        scheme: gsheets
        arg: spreadsheet_id
        dtype: gsheets
      - verb: gsheets.read
        direction: source
        scheme: gsheets
        arg: spreadsheet_id

  - id: google-docs
    manifest_version: 1
    namespace: gdocs
    label: Google Docs
    verbs:
      - verb: gdocs.read
        direction: source
        scheme: gdrive
        arg: document_id
        template: 'gdrive:doc/{value}'
    unmapped: [gdocs.create, gdocs.append_text, gdocs.replace_text]

  # Taint-only: what the PDP knows about the calendar verbs is that a list of
  # events mixes several authors.
  - id: google-calendar
    manifest_version: 1
    namespace: gcalendar
    label: Google Calendar
    taint:
      - gcalendar.list_events
    unmapped: [gcalendar.list_calendars, gcalendar.create_event,
               gcalendar.update_event, gcalendar.delete_event, gcalendar.freebusy]

  # No transport and no credential: the code is the component's (`mail_run`),
  # the credential the gateway vault's.
  - id: mail-gmail
    manifest_version: 1
    namespace: gdrive
    label: Gmail
    extends: mail
    providers:
      - id: gmail
        label: Gmail account
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
  `pack_import` in clodia-logic keeps the `connectors:` block in the installed
  `pack.yaml`, and the webui renders the Tools page from the registry (#520).
- **Install-time refusal.** Done (#519): `pack_import` asks the gateway to
  validate a `connectors:` block (`POST /internal/connectors/validate`) before
  installing, and refuses the pack when the gateway says no or cannot answer.
