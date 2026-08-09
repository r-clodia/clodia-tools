# Where this component's rules are written

This file used to restate the gateway's operating rules. It had drifted so far
that it was misleading on the one subject where being wrong costs most: it
described identification by an `MCP_AGENT_NAME` environment variable, a
`shell.exec` verb governed by a per-agent list of allowed commands, credentials
read from `secrets/`, and a set of Trello verbs. None of that exists. The header
claimed version 0.11.0 while the body's changelog had reached 1.31.0 and the
code was past 1.70.

A restatement of a rule is a **second copy of that rule**, and the copy that
drifts is always the one that only explains. That is the lesson this repository
has learned repeatedly, so the restatement is gone rather than refreshed.

## The rules

| what you want to know | where it is written |
|---|---|
| the model — scopes, authority, gates, tiers, the perimeter | [`docs/specification.md`](https://github.com/r-clodia/clodia-platform/blob/main/docs/specification.md) |
| what the code actually enforces today, and what it does not | [`docs/gap-analysis.md`](https://github.com/r-clodia/clodia-platform/blob/main/docs/gap-analysis.md) |
| the threats this design answers, and the ones it does not | [`docs/threat-model.md`](https://github.com/r-clodia/clodia-platform/blob/main/docs/threat-model.md) |
| the security posture, mapped to ISO/IEC 27001:2022 Annex A | [`SECURITY.md`](https://github.com/r-clodia/clodia-platform/blob/main/SECURITY.md) |
| which verbs a build exposes | `python3 cli.py --help` |
| which verbs are gated, and what each crossing is | `server/gate.py` — one matrix, with a test that fails if a gated verb has no class or a class has no verb |

## Why the code is the authority here

Every rule in this gateway is enforced in exactly one place and carries the
reason in its own docstring, next to the decision it governs. `server/gate.py`
holds the gate matrix; `server/whitelist.py` resolves what a seed may do;
`server/tools/gdrive_root.py` confines Google credentials to approved folders;
`server/tools/github_repo.py` keeps a git credential out of the agent's process
and then **checks the disk** to prove it. Reading those files answers a question
about behaviour more reliably than reading a document about them.
