from unittest.mock import MagicMock, patch

from . import platform_ops


def _response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.content = b'{"ok":true}'
    response.json.return_value = payload
    return response


def test_req_forwards_current_caller_token():
    client = MagicMock()
    client.request.return_value = _response({"ok": True})
    client_context = MagicMock()
    client_context.__enter__.return_value = client

    with (
        patch.object(platform_ops.whitelist, "current_token", return_value="ckt1.signed"),
        patch.object(platform_ops.httpx, "Client", return_value=client_context),
    ):
        result = platform_ops.packs_import_url("https://example.test/pack.zip")

    assert result == {"ok": True}
    client.request.assert_called_once_with(
        "POST",
        f"{platform_ops.AGENT_SERVER_URL}/clodia/packs/import-url",
        json={"url": "https://example.test/pack.zip"},
        headers={"Authorization": "Bearer ckt1.signed"},
    )


def test_req_keeps_anonymous_reads_without_authorization_header():
    client = MagicMock()
    client.request.return_value = _response({"packs": []})
    client_context = MagicMock()
    client_context.__enter__.return_value = client

    with (
        patch.object(platform_ops.whitelist, "current_token", return_value=None),
        patch.object(platform_ops.httpx, "Client", return_value=client_context),
    ):
        result = platform_ops.packs_list()

    assert result == {"packs": []}
    client.request.assert_called_once_with(
        "GET",
        f"{platform_ops.AGENT_SERVER_URL}/clodia/packs",
        json=None,
        headers={},
    )
