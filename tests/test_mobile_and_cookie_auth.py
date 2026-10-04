"""
Auth modes this fork adds next to OAuth with PKCE and API tokens: a mobile app
OAuth token (ZENDESK_OAUTH_TOKEN, .zendesk_token or a browser sign-in) and a
browser session cookie.
"""
import pytest
import responses

from zendesk_mcp_server import mobile_auth, server
from zendesk_mcp_server.auth import SessionCookieAuthProvider
from zendesk_mcp_server.zendesk_client import ZendeskClient

SUBDOMAIN = "example"
TICKETS_URL = f"https://{SUBDOMAIN}.zendesk.com/api/v2/tickets.json"


@pytest.mark.parametrize(
    "env, saved_token, header, expected",
    [
        ({"ZENDESK_OAUTH_TOKEN": "env-token"}, None, "Authorization", "Bearer env-token"),
        ({"ZENDESK_SESSION_COOKIE": "cookie"}, None, "Cookie", "_zendesk_session=cookie"),
        # A token saved by zendesk-mobile-auth wins over an API token.
        (
            {"ZENDESK_EMAIL": "agent@example.com", "ZENDESK_API_KEY": "key"},
            "saved-token",
            "Authorization",
            "Bearer saved-token",
        ),
        # Nothing configured: sign in through the mobile app OAuth flow.
        ({}, None, "Authorization", "Bearer mobile-token"),
    ],
)
@responses.activate
def test_client_authenticates_with_the_configured_method(monkeypatch, env, saved_token, header, expected):
    monkeypatch.setenv("ZENDESK_SUBDOMAIN", SUBDOMAIN)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        mobile_auth, "load_token", lambda: {"access_token": saved_token} if saved_token else None
    )
    monkeypatch.setattr(mobile_auth, "ensure_auth", lambda subdomain: {"access_token": "mobile-token"})
    responses.add(responses.GET, TICKETS_URL, json={"tickets": [], "next_page": None})

    server._init_client().get_tickets()

    assert responses.calls[0].request.headers[header] == expected


@responses.activate
def test_session_cookie_is_not_forwarded_to_the_attachment_cdn():
    attachment_url = f"https://{SUBDOMAIN}.zendesk.com/attachments/token/abc/?name=x.png"
    cdn_url = f"https://{SUBDOMAIN}.zdusercontent.com/attachment/abc/x.png"
    responses.add(responses.GET, attachment_url, status=302, headers={"Location": cdn_url})
    responses.add(responses.GET, cdn_url, body=b"\x89PNG\r\n\x1a\npayload", content_type="image/png")
    client = ZendeskClient(subdomain=SUBDOMAIN, auth=SessionCookieAuthProvider("cookie"))

    client.get_ticket_attachment(attachment_url)

    assert responses.calls[0].request.headers["Cookie"] == "_zendesk_session=cookie"
    assert "Cookie" not in responses.calls[1].request.headers
