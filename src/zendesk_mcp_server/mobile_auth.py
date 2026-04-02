"""
OAuth authentication for Zendesk using the mobile app's OAuth flow.

Supports two auth methods discovered via /api/mobile/account/lookup.json:
- Email/password: direct POST to /access/oauth_mobile (no browser needed)
- SSO (SAML/Google/Office365): opens system browser, user pastes callback URL

The access_token is saved to a token file for the MCP server to use.
"""

import getpass
import json
import os
import platform
import socket
import sys
import threading
import uuid
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs

import requests

CLIENT_ID = "zendesk_support_android"
OAUTH_SCHEME = "zendesk-support"
USER_AGENT = "Zendesk-SDK/1.0 Android/30 Variant/Core"
TOKEN_FILE = ".zendesk_token"

# HTML served by the local callback server after capturing the token
SUCCESS_HTML = """<!DOCTYPE html>
<html><head><title>Zendesk Auth</title></head>
<body style="font-family:sans-serif;text-align:center;padding:60px">
<h2>Authentication successful!</h2>
<p>You can close this tab and return to the terminal.</p>
</body></html>"""

# HTML page that intercepts the custom scheme redirect
INTERCEPT_HTML = """<!DOCTYPE html>
<html><head><title>Zendesk Auth</title>
<script>
// Listen for navigation to the custom scheme by polling the page location
// and by intercepting link clicks. The actual mechanism: after SSO completes,
// Zendesk redirects to zendesk-support://...?access_token=...
// The browser can't handle this scheme, so we catch it via a service worker
// or by having the user paste the URL.

// On page load, show instructions
document.addEventListener('DOMContentLoaded', function() {{
    document.getElementById('status').textContent = 'Redirecting to Zendesk login...';
    setTimeout(function() {{
        window.location.href = '{auth_url}';
    }}, 1000);
    // After redirect, show paste instructions (the redirect to custom scheme will fail)
    setTimeout(function() {{
        document.getElementById('paste-section').style.display = 'block';
        document.getElementById('status').textContent =
            'If you see an error about "zendesk-support://" not being recognized, ' +
            'copy the full URL from the address bar and paste it below.';
    }}, 5000);
}});

function submitUrl() {{
    var url = document.getElementById('callback-url').value.trim();
    if (url) {{
        fetch('/callback?url=' + encodeURIComponent(url))
            .then(function() {{
                document.body.innerHTML = '<h2 style="text-align:center;padding:60px;font-family:sans-serif">' +
                    'Authentication successful! You can close this tab.</h2>';
            }});
    }}
}}
</script>
</head>
<body style="font-family:sans-serif;max-width:600px;margin:40px auto;padding:20px">
<h2>Zendesk Authentication</h2>
<p id="status">Initializing...</p>
<div id="paste-section" style="display:none;margin-top:30px">
    <p><strong>Paste the callback URL here:</strong></p>
    <input type="text" id="callback-url" style="width:100%;padding:8px;font-size:14px"
           placeholder="zendesk-support://?access_token=...">
    <br><br>
    <button onclick="submitUrl()" style="padding:10px 20px;font-size:14px;cursor:pointer">
        Submit
    </button>
</div>
</body></html>"""


def get_token_path(project_dir: str = None) -> Path:
    """Get the path to the token file."""
    base = Path(project_dir) if project_dir else Path.cwd()
    return base / TOKEN_FILE


def load_token(project_dir: str = None) -> dict | None:
    """Load saved token from file. Returns dict with access_token, subdomain, etc."""
    path = get_token_path(project_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        if data.get("access_token") and data.get("subdomain"):
            return data
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def save_token(token_data: dict, project_dir: str = None) -> Path:
    """Save token data to file."""
    path = get_token_path(project_dir)
    path.write_text(json.dumps(token_data, indent=2))
    path.chmod(0o600)
    return path


def lookup_subdomain(subdomain: str) -> dict:
    """Call the mobile account lookup endpoint to discover auth methods."""
    url = f"https://{subdomain}.zendesk.com/api/mobile/account/lookup.json"
    resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=15)
    resp.raise_for_status()
    return resp.json()["lookup"]


def auth_email_password(subdomain: str, email: str, password: str) -> dict:
    """Authenticate with email/password via /access/oauth_mobile."""
    url = f"https://{subdomain}.zendesk.com/access/oauth_mobile"
    device_id = str(uuid.uuid4())
    device_name = platform.node() or "zendesk-mcp"
    payload = {
        "clientId": CLIENT_ID,
        "user": {"email": email, "password": password},
        "device": {"name": device_name, "identifier": device_id},
        "nativeMobile": True,
    }
    resp = requests.post(
        url,
        json=payload,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    auth = data.get("authentication", data)
    return {
        "subdomain": subdomain,
        "access_token": auth.get("accessToken") or auth.get("access_token"),
        "username": auth.get("username"),
        "user_id": auth.get("userId") or auth.get("user_id"),
        "account_id": auth.get("accountId") or auth.get("account_id"),
        "user_role": auth.get("userRole") or auth.get("user_role"),
    }


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def auth_sso_browser(subdomain: str, auth_url: str) -> dict:
    """
    Authenticate via SSO using the system browser.

    Opens a local HTTP server that:
    1. Serves a page that redirects to the Zendesk SSO URL
    2. After SSO, Zendesk redirects to zendesk-support://?access_token=...
    3. The browser can't handle the custom scheme, so the user pastes the URL
    4. The local server parses the token and shuts down
    """
    port = _find_free_port()
    result = {}
    server_ready = threading.Event()

    device_id = str(uuid.uuid4())
    device_name = platform.node() or "zendesk-mcp"
    full_auth_url = f"{auth_url}?{urlencode({'client_id': CLIENT_ID, 'device[name]': device_name, 'device[identifier]': device_id})}"

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/callback":
                params = parse_qs(parsed.query)
                callback_url = params.get("url", [""])[0]
                token_data = _parse_oauth_callback(callback_url, subdomain)
                if token_data:
                    result.update(token_data)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(SUCCESS_HTML.encode())
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                # Serve the intercept page
                html = INTERCEPT_HTML.format(auth_url=full_auth_url)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(html.encode())

        def log_message(self, format, *args):
            pass  # Suppress HTTP logs

    server = HTTPServer(("127.0.0.1", port), CallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    local_url = f"http://127.0.0.1:{port}/auth"
    print(f"\nOpening browser for Zendesk SSO login...")
    print(f"If the browser doesn't open, visit: {local_url}\n")
    webbrowser.open(local_url)

    print("Waiting for authentication...")
    print("After signing in, if the browser shows an error about 'zendesk-support://',")
    print("copy the full URL from the address bar and paste it into the browser page.\n")
    print("Or paste it here and press Enter:")
    print("(Press Ctrl+C to cancel)\n")

    # Also accept paste from stdin as fallback
    input_thread_result = {}

    def read_stdin():
        try:
            line = input("> ").strip()
            if line and not result:
                token_data = _parse_oauth_callback(line, subdomain)
                if token_data:
                    input_thread_result.update(token_data)
                    server.shutdown()
        except (EOFError, KeyboardInterrupt):
            server.shutdown()

    stdin_thread = threading.Thread(target=read_stdin, daemon=True)
    stdin_thread.start()

    server_thread.join(timeout=300)  # 5 min timeout
    server.server_close()

    if result:
        return result
    if input_thread_result:
        return input_thread_result
    raise RuntimeError("Authentication timed out or was cancelled.")


def _parse_oauth_callback(url: str, subdomain: str) -> dict | None:
    """Parse the OAuth callback URL to extract token data."""
    if not url:
        return None
    # Handle both zendesk-support://...?params and zendesk-support://?params
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    # Also try fragment (some OAuth flows put params in the fragment)
    if not params and parsed.fragment:
        params = parse_qs(parsed.fragment)

    access_token = (params.get("access_token") or [None])[0]
    if not access_token:
        return None

    return {
        "subdomain": subdomain,
        "access_token": access_token,
        "username": (params.get("username") or [None])[0],
        "user_id": (params.get("user_id") or [None])[0],
        "account_id": (params.get("account_id") or [None])[0],
        "user_role": (params.get("user_role") or [None])[0],
    }


def run_auth_cli():
    """Interactive CLI for authenticating with Zendesk."""
    print("=== Zendesk MCP Server - Authentication ===\n")

    subdomain = input("Enter your Zendesk subdomain (e.g., 'mycompany' for mycompany.zendesk.com): ").strip()
    if not subdomain:
        print("Error: subdomain is required.")
        sys.exit(1)

    # Remove .zendesk.com suffix if provided
    subdomain = subdomain.replace(".zendesk.com", "").replace("https://", "").replace("http://", "").strip("/")

    print(f"\nLooking up authentication options for {subdomain}.zendesk.com...")
    try:
        lookup = lookup_subdomain(subdomain)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            print(f"Error: subdomain '{subdomain}' not found.")
        elif e.response.status_code == 403:
            print(f"Error: access to '{subdomain}' is forbidden (IP restriction or mobile access disabled).")
        else:
            print(f"Error: {e}")
        sys.exit(1)

    agent_logins = lookup.get("agent_logins", [])
    if not agent_logins:
        print("Error: no login methods found for this subdomain.")
        sys.exit(1)

    # Display available auth methods
    print(f"\nAvailable login methods for {lookup.get('name', subdomain)}:")
    for i, login in enumerate(agent_logins):
        service = login.get("service", "unknown")
        label = {
            "zendesk": "Email & Password",
            "google": "Google",
            "office_365": "Office 365",
            "remote": "SSO (Corporate)",
        }.get(service, service)
        print(f"  [{i + 1}] {label}")

    # Choose method
    if len(agent_logins) == 1:
        choice = 0
    else:
        try:
            choice = int(input(f"\nSelect method [1-{len(agent_logins)}]: ").strip()) - 1
            if choice < 0 or choice >= len(agent_logins):
                raise ValueError()
        except (ValueError, EOFError):
            print("Invalid selection.")
            sys.exit(1)

    login = agent_logins[choice]
    service = login.get("service")

    try:
        if service == "zendesk":
            email = input("Email: ").strip()
            password = getpass.getpass("Password: ")
            print("\nAuthenticating...")
            token_data = auth_email_password(subdomain, email, password)
        else:
            # SSO/Google/Office365 - use browser flow
            # Prefer zendesk_url (the mobile SSO endpoint), fall back to url
            auth_url = login.get("zendesk_url") or login.get("url")
            if not auth_url:
                print("Error: no authentication URL found.")
                sys.exit(1)
            token_data = auth_sso_browser(subdomain, auth_url)
    except requests.HTTPError as e:
        print(f"\nAuthentication failed: {e}")
        if e.response is not None:
            try:
                detail = e.response.json()
                print(f"Detail: {json.dumps(detail, indent=2)}")
            except Exception:
                print(f"Response: {e.response.text[:500]}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"\n{e}")
        sys.exit(1)

    if not token_data.get("access_token"):
        print("\nError: no access token received.")
        sys.exit(1)

    # Save token
    path = save_token(token_data)
    print(f"\nAuthentication successful!")
    print(f"  User: {token_data.get('username', 'N/A')}")
    print(f"  Role: {token_data.get('user_role', 'N/A')}")
    print(f"  Token saved to: {path}")
    print(f"\nThe MCP server will use this token automatically on next start.")


def main():
    try:
        run_auth_cli()
    except KeyboardInterrupt:
        print("\n\nCancelled.")
        sys.exit(1)


if __name__ == "__main__":
    main()
