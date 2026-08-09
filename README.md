# clodia-tools

The **MCP HTTP gateway** of a Clodia colony: it offers agents a **controlled**
set of verbs in place of direct access to the filesystem, the shell and
credentials.

It is the colony's **reference monitor**. The vetoes live here, in a process — a
container, a repository — **separate from the runtime the agents run in**. An
agent holds no credential and no CLI: the only way it acts on the world is to
ask the gateway, which **authenticates (PKI `ckt1`) → resolves what that spawn
may do → executes or refuses**.

> ### 📍 This is not the entry repository
>
> This repository is a **component** of Clodia Platform, not something you
> install on its own. Installation, quickstart, architecture, licence and the
> **risk warnings** live in:
>
> ### 👉 **[r-clodia/clodia-platform](https://github.com/r-clodia/clodia-platform)**
>
> Do not deploy from here: `clodia-platform` clones the component repositories,
> builds the images and orchestrates the stack. Before installing, read the
> as-is disclaimer and the **known defects** in the platform tracker —
> [open `security` issues](https://github.com/r-clodia/clodia-platform/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity)
> and [`SECURITY.md`](https://github.com/r-clodia/clodia-platform/blob/main/SECURITY.md).
> The software is distributed **AS IS, without warranty**: you run it at your
> own risk.

## How a call is decided

```
agent (clodia-logic / clodia-web)  ──  Authorization: Bearer ckt1.<signed token>  ──▶  clodia-tools :7849
                                                                                       │ verify_session_token (PUBLIC certs)
                                                                                       │ seed matrix ∩ scope role ∩ profile
                                                                                       │ gate, if the action crosses a boundary
                                                                                       └ adapter (topic / email / drive / github / …)
```

- **Authentication.** A `ckt1` session token signed by the agent's private key,
  minted in clodia-logic and never written to disk. Here it is verified with
  **public** certificates only: signature → certificate against the CA →
  revocation → audience → expiry. The identity comes from the verified token,
  never from a spoofable header.
- **Authority** is the *intersection* of three terms — what the seed declares,
  what the caller's role in the scope allows, and what the instance profile
  enables. A refusal says which term blocked it, because the three have
  different remedies.
- **Which spawn**, not merely which seed: the token carries an `execution_id`,
  so one spawn cannot reach another's scratch directory.
- **Gates.** An action that crosses a boundary is held for a human. The class of
  the crossing (`system`, `walls`, `outward`) travels with the request, because
  whoever approves must not have to re-derive it — a duplicated rule diverges.

The rules themselves are not restated here. They are specified in
**[`docs/specification.md`](https://github.com/r-clodia/clodia-platform/blob/main/docs/specification.md)**,
and what this component currently enforces — with the gaps named — is measured in
**[`docs/gap-analysis.md`](https://github.com/r-clodia/clodia-platform/blob/main/docs/gap-analysis.md)**.

## Verb families

`topic.*` (scopes, their files, their messages) · `email.*` · `gdrive.*`,
`gdocs.*`, `gsheets.*`, `gcalendar.*` · `github.*` (clone, pull, push, pull
request — the credential never enters the agent's process) · `fs.*` · `memory.*`
· `agents.*`, `jobs.*`, `packs.*`, `providers.*`, `runtime.*` (control plane,
admin-held).

`cli.py --help` lists what a build actually exposes. That listing is the
authority: a README enumerating verbs goes stale the week it is written.

## Running it

```bash
pip install -r requirements.txt
python3 cli.py --http --port 7849      # HTTP gateway
python3 cli.py --version
```

Runtime environment: `CLODIA_CA_CRT`, `CLODIA_PKI_CERTS`, `CLODIA_PKI_REVOKED`,
`CLODIA_WORKSPACE_ROOT`. Secrets are **mounted**, never baked into the image.

## Origin

Split out of `r-clodia/clodia-logic` (`tools/system/mcp-tools-server`) on
2026-06-14 with history preserved, to separate the enforcement plane from the
runtime the agents live in.

## Licence

Copyright (C) 2026 Davide Carboni.

GNU AGPL v3, with a commercial option: see [LICENSING.md](LICENSING.md).
Releases up to the `apache2-final` tag remain Apache 2.0.
