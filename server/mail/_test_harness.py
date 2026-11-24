"""Test harness for `server/mail/` (clodia-platform#683).

The mail code reaches the gateway through `_host.get()` (perimeter, topics,
audit, scratch, crossings, google-pack's two services) and `server.vault`.
Here both are stood in for, recorded, so the security cases ported from
comms-pack's component suites (clodia-logic `test_558_mail_component`,
`test_523_mail_security_moved`, `test_585_586_comms_courier`) run against the
gateway's own code.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from .. import vault as gw_vault
from . import _host, mail

SECRET = "S3cr3t-Pa55w0rd-683-xyz"  # gitleaks:allow — fake test credential

STUDIO = {"email": "Studio@Example.it", "password": SECRET,
          "imap_server": "imap.example.it", "smtp_server": "smtp.example.it",
          "smtp_port": 587}


class FakePerimeter:
    def __init__(self):
        self.inbox: set[str] = set()
        self.outbox: set[str] = set()
        self.legacy: dict = {}
        #: Senders the CURRENT room itself declares (`mailfrom:`, #576).
        self.room_senders: set[str] = set()
        #: The message-box code of the courier call in progress (#583).
        self.tag = ""
        #: The colony mailbox's address (#583), "" = no colony.
        self.colony = ""
        #: Accounts that ALSO hold a Google mail credential (names only).
        self.google_named: set = set()

    def mailbox_allowed(self, direction, address, scope=None):
        return address in (self.inbox if direction == "inbox" else self.outbox)

    def address_of(self, header):
        m = re.search(r"[\w.+-]+@[\w.-]+", header or "")
        return m.group(0).lower() if m else ""

    def room_declares_sender(self, header):
        return self.address_of(header) in self.room_senders

    def courier_tag(self):
        return self.tag

    def colony_address(self):
        return self.colony

    def legacy_mail_accounts(self):
        return dict(self.legacy)

    def google_mail_account_exists(self, account):
        return account in self.google_named


class FakeTopics:
    def __init__(self, host):
        self.host = host
        self.files: dict = {}

    def read_file(self, tier, name, path, *, crossing="file"):
        if (tier, name) not in self.host.members:
            raise PermissionError(f"not a member of {tier}/{name}")
        data = self.files[(tier, name, path)]
        if crossing:
            self.host.crossings.append(("data", crossing))
        return data


class FakeGateway:
    """What `_host._Gateway` answers, recorded."""

    class AuditUnavailable(RuntimeError):
        pass

    def __init__(self, scratch: str):
        self.vault: dict[str, dict] = {}
        self.deposits: list = []
        self.crossings: list = []
        self.decisions: list = []
        self.members: set = set()
        self.topic = (None, None)
        self.perimeter = FakePerimeter()
        self.topics = FakeTopics(self)
        self.scratch = scratch
        self.google: dict = {}
        self.service_lookups: list = []
        self.log = logging.getLogger("fake-gateway")

    def agent(self):
        return "segretario"

    disabled: set = set()

    def mailbox_disabled(self, account):
        return str(account or "") in self.disabled

    def set_mailbox_enabled(self, account, enabled):
        self.disabled = (self.disabled - {account}) | (set() if enabled else {account})

    def current_topic(self):
        return self.topic

    def scratch_path(self, path):
        full = os.path.realpath(path)
        if not full.startswith(os.path.realpath(self.scratch) + os.sep):
            raise ValueError("outside the scratch")
        return full

    def note_crossing(self, data=None, *, path=None, kind="file"):
        self.crossings.append(("path" if path else "data", kind))

    def audit_decision(self, verb, kind, result, *, reason_class=None):
        self.decisions.append((verb, kind, result, reason_class))

    def service(self, pack, name):
        self.service_lookups.append((pack, name))
        if (pack, name) not in {("google-pack", "mail_accounts"),
                                ("google-pack", "mail_exec")}:
            raise PermissionError("not granted")
        return self.google.get(name)


#: A stand-in for email_client.py: reports what it sees.
PROBE = textwrap.dedent(r"""
    import json, os, stat, sys
    d = os.environ.get("CLODIA_SECRETS_DIR") or ""
    cfg = json.load(open(os.path.join(d, "email_config.json"))) if d else None
    print(json.dumps({"argv": sys.argv[1:], "config": cfg, "env": sorted(os.environ),
                      "dir_mode": oct(stat.S_IMODE(os.stat(d).st_mode)) if d else None,
                      "secrets_dir": d}))
""")


class OnFakeGateway(unittest.TestCase):
    """`server/mail/` on a fake gateway: one IMAP/SMTP mailbox `studio`,
    authorised in and out; the client replaced by a probe."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.host = FakeGateway(self.tmp)
        self.mail = mail
        v = self.host.vault

        def _deposit(name, bundle, *, cred_type="opaque", grant_agents=()):
            v[name] = dict(bundle)
            self.host.deposits.append((name, cred_type, list(grant_agents)))

        def _read(name):
            if name not in v:
                raise PermissionError(f"absent: {name}")
            return dict(v[name])

        probe = Path(self.tmp) / "probe.py"
        probe.write_text(PROBE, encoding="utf-8")
        for p in (patch.object(_host, "_GATEWAY", self.host),
                  patch.object(gw_vault, "has_credential", lambda n: n in v),
                  patch.object(gw_vault, "read_internal", _read),
                  patch.object(gw_vault, "store_names", lambda: sorted(v)),
                  patch.object(gw_vault, "deposit", _deposit),
                  patch.object(gw_vault, "remove", lambda n: v.pop(n, None) is not None),
                  patch.object(mail, "_EMAIL_SCRIPT", str(probe))):
            p.start()
            self.addCleanup(p.stop)
        v["mailbox_studio"] = dict(STUDIO)
        self.host.perimeter.inbox.add("studio@example.it")
        self.host.perimeter.outbox.add("studio@example.it")

    def svc(self, name, *args):
        from ..tools import mail_switch
        return mail_switch.call(name, *args)
