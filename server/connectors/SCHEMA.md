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
| `verbs` | no | verb → destination and read → source |
| `taint` | no | MCP prefixes of this pack whose answers do not taint a channel |
| `topic_actions` | no | buttons the connector adds to a topic |
| `tools_card` | no | what the Tools page shows |
| `services` | no | long-running processes, see #515 |
| `storage_remote` | no | topic storage backend the pack provides, see #524 |

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
| `hierarchical` | no | a rule covers what is below it — today's `_HIERARCHICAL` |
| `label`, `icon` | no | presentation |
| `danger` | no | the warning shown at the gate — today's `_DANGER` |
| `canonicalise[]` | no | `from` (regex) → `to` (template over `{1}`, `{2}`…) — today's `_CANON` |

An `example` that does not match its own `pattern` is an error: it is the
cheapest available proof that the regex says what the author meant. A
canonicalisation template that refers to a capture group the pattern does not
have is an error too.

`http`, `https`, `topic` and `mcp` are **platform-intrinsic**: a pack may point a
verb at them, but declaring them in `schemes:` is refused. GitHub works that way
— its destinations are ordinary `https://github.com/<owner>/<repo>` URLs, checked
by the ordinary http rules.

### `providers[]`

`id`, `label`, optional `status_verb` / `test_verb`, and a `credential`:

- `kind: form` — `vault_entry` plus the `fields` the owner fills in (`secret:
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
| `dtype` | no | the destination type shown at the gate (today's first element of `_SPECS`) |

**The namespace rule is not negotiable.** A pack maps only verbs it owns; a
manifest naming someone else's verb is refused *as a whole*, with the offending
verb in the message. Without it a pack could declare `email.send` as a read, or
map it to a harmless destination, and walk straight through the egress check.
`check_namespace()` is exported because #517 applies the same rule again when the
call actually happens — two implementations of it would be one too many.

### `topic_actions[]`

`id`, `label`, `fields[]`, `binding` (optional), and `adds:` with `ingress:` /
`egress:` templates over the action's own fields. A template naming a field the
action does not declare is an error. What the action adds is a *proposal*: the
grant is still the owner's, at the gate.

### `services[]`

The shape #515 fixed, parsed here so the supervisor consumes one format instead
of inventing a second: `name`, `command` (a **list**, never a string — a string
would mean a shell, and a shell is a way to hide a second process inside a
manifest that declares one), `workdir`, `credentials` (vault entry names),
`health: {kind: http|tcp|command, target, interval_seconds}`,
`restart: {policy: always|on-failure|never, backoff_seconds}`.

State lives under `<datadir>/services/<pack>/<service>/` — `Service.state_dir`
computes it, so the path is not written down twice.

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
        danger: >-
          a chat on Telegram, that is on infrastructure that is not yours.
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
      - verb: telegram.read
        direction: source
        scheme: tg
        arg: chat_id
    topic_actions:
      - id: telegram-link
        label: Link a Telegram chat
        binding: channel
        fields:
          - name: chat
            label: Chat id or @handle
        adds:
          ingress:
            - 'tg:{chat}'
          egress:
            - 'tg:{chat}'
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
            pattern: '^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$'
            example: 'someone@example.org'
      - scheme: mailfrom
        direction: source
        label: Vetted sender
        forms:
          - label: address
            pattern: '^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$'
            example: 'someone@example.org'
      - scheme: outbox
        direction: egress
        label: Mailbox that sends
        forms:
          - label: address
            pattern: '^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$'
            example: 'studio@example.org'
      - scheme: inbox
        direction: source
        label: Mailbox that is downloaded
        forms:
          - label: address
            pattern: '^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$'
            example: 'studio@example.org'
    providers:
      - id: imap
        label: IMAP/SMTP mailbox
        credential:
          kind: form
          vault_entry: mailbox
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
          - from: '^https?://drive\.google\.com/drive/(?:u/\d+/)?folders/([\w-]+)'
            to: 'gdrive:folder/{1}'
          - from: '^https?://drive\.google\.com/file/d/([\w-]+)'
            to: 'gdrive:file/{1}'
      - scheme: gsheets
        direction: both
        label: Google spreadsheet
        danger: 'a Google spreadsheet. If it is shared, anyone with the link sees it.'
        forms:
          - label: spreadsheet
            pattern: '^[\w-]+$'
            example: '1AbCdEfGhIjKlMnOpQrStUv'
        canonicalise:
          - from: '^https?://docs\.google\.com/spreadsheets/d/([\w-]+)'
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
          vault_entry: openai_api_key
          fields:
            - name: api_key
              label: API key
              secret: true
    tools_card:
      setup_label: Paste an API key
```

---

## Known gaps of v1, deliberately left open

- **Shorthand normalisation for GitHub repositories.** `owner/repo` becomes a
  full URL through `github_repo.normalize_repo`, not through a `canonicalise`
  rule: letting a pack rewrite `https:` URLs would hand it the meaning of every
  URL on the instance. Whether this becomes a per-verb rule is a question for
  #518, with the tables in front of us.
- **Nothing reads this module yet.** Building the registry and deleting
  `egress.py`'s tables is #518; applying the mappings at call time is #517; the
  generic HTTP endpoints are #519; the webui rendered from the registry is #520.
- **Install-time refusal.** `pack_import` in `clodia-logic` will ask the gateway
  to validate a `connectors:` block the way it already asks `/flow-allow` for the
  flow declarations. That endpoint is #519.
