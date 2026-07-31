from unittest.mock import patch

import pytest

from . import pack_runtime


def test_install_pip_rejects_urls_and_shell_fragments():
    with pytest.raises(ValueError):
        pack_runtime.install_pip(["https://example.test/pkg.whl"])
    with pytest.raises(ValueError):
        pack_runtime.install_pip(["mcp;touch /tmp/nope"])


def test_install_npm_rejects_shell_fragments():
    with pytest.raises(ValueError):
        pack_runtime.install_npm(["@scope/pkg;whoami"])


def test_check_command_uses_runtime_path():
    with patch.object(pack_runtime.shutil, "which", return_value="/datadir/runtime/npm/bin/foo") as which:
        result = pack_runtime.check_command("foo")

    assert result["found"] is True
    assert result["path"] == "/datadir/runtime/npm/bin/foo"
    assert "/runtime/venv/bin" in which.call_args.kwargs["path"]
    assert "/runtime/npm/bin" in which.call_args.kwargs["path"]
