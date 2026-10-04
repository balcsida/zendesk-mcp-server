"""
Characterization tests for the authentication behaviour that shipped before
OAuth support was added.

These lock in the exact wire format of API-token (basic) authentication and the
attachment-fetch safety checks, so the refactor to pluggable auth providers can
be shown not to change observable behaviour.
"""
import base64

import pytest
import responses

from zendesk_mcp_server.zendesk_client import ZendeskClient

SUBDOMAIN = "example"
EMAIL = "agent@example.com"
API_TOKEN = "test-api-token"

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
ATTACHMENT_URL = "https://example.zendesk.com/attachments/token/abc/?name=x.png"


@pytest.fixture
def client():
    return ZendeskClient(subdomain=SUBDOMAIN, email=EMAIL, token=API_TOKEN)


def test_api_token_auth_header_is_basic_email_slash_token(client):
    expected_credentials = f"{EMAIL}/token:{API_TOKEN}"
    expected = "Basic " + base64.b64encode(expected_credentials.encode()).decode("ascii")

    assert client.auth_header == expected


@responses.activate
def test_get_tickets_sends_the_auth_header(client):
    responses.add(
        responses.GET,
        f"https://{SUBDOMAIN}.zendesk.com/api/v2/tickets.json",
        json={"tickets": [], "next_page": None},
    )

    client.get_tickets(page=2, per_page=10)

    assert responses.calls[0].request.headers["Authorization"] == client.auth_header


@responses.activate
def test_get_ticket_attachment_returns_base64_for_allowed_image(client):
    body = PNG_MAGIC + b"payload"
    responses.add(
        responses.GET,
        ATTACHMENT_URL,
        body=body,
        content_type="image/png",
        status=200,
    )

    result = client.get_ticket_attachment(ATTACHMENT_URL)

    assert result["content_type"] == "image/png"
    assert base64.b64decode(result["data"]) == body
    assert responses.calls[0].request.headers["Authorization"] == client.auth_header


@responses.activate
def test_get_ticket_attachment_rejects_disallowed_content_type(client):
    responses.add(
        responses.GET,
        ATTACHMENT_URL,
        body=b"<svg/>",
        content_type="image/svg+xml",
        status=200,
    )

    with pytest.raises(ValueError, match="is not allowed"):
        client.get_ticket_attachment(ATTACHMENT_URL)


@responses.activate
def test_get_ticket_attachment_rejects_spoofed_magic_bytes(client):
    responses.add(
        responses.GET,
        ATTACHMENT_URL,
        body=b"definitely-not-a-png",
        content_type="image/png",
        status=200,
    )

    with pytest.raises(ValueError, match="does not match declared content type"):
        client.get_ticket_attachment(ATTACHMENT_URL)


@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.example/x.png",
        "http://example.zendesk.com/attachments/token/abc/?name=x.png",
        "https://other-account.zendesk.com/attachments/token/abc/?name=x.png",
    ],
)
def test_get_ticket_attachment_rejects_untrusted_urls_before_any_request(client, url):
    with responses.RequestsMock() as mock:
        with pytest.raises(ValueError):
            client.get_ticket_attachment(url)
        assert len(mock.calls) == 0


@responses.activate
def test_get_ticket_attachment_sends_no_credentials_to_the_cdn(client):
    cdn_url = "https://example.zdusercontent.com/attachment/abc/x.png"
    responses.add(responses.GET, cdn_url, body=PNG_MAGIC + b"payload", content_type="image/png")

    client.get_ticket_attachment(cdn_url)

    assert "Authorization" not in responses.calls[0].request.headers
