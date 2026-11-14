"""The gateway's mail code (clodia-platform#683).

Back from comms-pack's gateway component (#558), without the agent verbs: the
courier reads mail, `email.send` exists only inside a `channel.deliver`, and
the mailboxes are managed from Tools.

    mail.py           accounts, the mailbox whitelist, the courier's reads, send
    mailboxes.py      list / add / remove / test — the Tools page
    verbs.py          `email.send`, the delivery-only verb
    _host.py          what the code asks of the gateway (perimeter, vault,
                      topics, audit), and google-pack's two Gmail services
    email_client.py   the IMAP/SMTP client, run in a child process

The rest of the gateway reaches it through `tools/mail_switch.py`.
"""
