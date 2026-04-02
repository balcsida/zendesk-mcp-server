from typing import Dict, Any, List
import json
import urllib.request
import urllib.parse
import base64
import logging
import requests as _requests

logger = logging.getLogger("zendesk-mcp-server")


class ZendeskClient:
    def __init__(self, subdomain: str, email: str = None, token: str = None,
                 session_cookie: str = None):
        """
        Initialize the Zendesk client.

        Supports two auth modes:
        - Token auth: requires email + token (uses zenpy + Basic auth)
        - Cookie auth: requires session_cookie (uses direct HTTP with browser session)
        """
        self.subdomain = subdomain
        self.base_url = f"https://{subdomain}.zendesk.com/api/v2"
        self.email = email
        self.token = token
        self.session_cookie = session_cookie
        self._use_cookies = bool(session_cookie) and not (email and token)

        if self._use_cookies:
            logger.info("Using cookie-based authentication")
            self._session = _requests.Session()
            self._session.cookies.set(
                '_zendesk_session', session_cookie,
                domain=f'{subdomain}.zendesk.com'
            )
            self._session.headers.update({
                'Content-Type': 'application/json',
            })
            self.client = None
            self.auth_header = None
        else:
            logger.info("Using token-based authentication")
            from zenpy import Zenpy
            self.client = Zenpy(
                subdomain=subdomain,
                email=email,
                token=token
            )
            credentials = f"{email}/token:{token}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode('ascii')
            self.auth_header = f"Basic {encoded_credentials}"
            self._session = None

    def _api_get(self, path: str) -> Dict[str, Any]:
        """Make a GET request to the Zendesk API."""
        url = f"{self.base_url}/{path}"
        if self._use_cookies:
            resp = self._session.get(url, timeout=30)
            resp.raise_for_status()
            return resp.json()
        else:
            req = urllib.request.Request(url)
            req.add_header('Authorization', self.auth_header)
            req.add_header('Content-Type', 'application/json')
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode())

    def _api_put(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make a PUT request to the Zendesk API."""
        url = f"{self.base_url}/{path}"
        if self._use_cookies:
            resp = self._session.put(url, json=data, timeout=30)
            resp.raise_for_status()
            return resp.json()
        else:
            body = json.dumps(data).encode()
            req = urllib.request.Request(url, data=body, method='PUT')
            req.add_header('Authorization', self.auth_header)
            req.add_header('Content-Type', 'application/json')
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode())

    def _api_post(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make a POST request to the Zendesk API."""
        url = f"{self.base_url}/{path}"
        if self._use_cookies:
            resp = self._session.post(url, json=data, timeout=30)
            resp.raise_for_status()
            return resp.json()
        else:
            body = json.dumps(data).encode()
            req = urllib.request.Request(url, data=body, method='POST')
            req.add_header('Authorization', self.auth_header)
            req.add_header('Content-Type', 'application/json')
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode())

    def get_ticket(self, ticket_id: int) -> Dict[str, Any]:
        """
        Query a ticket by its ID
        """
        try:
            data = self._api_get(f"tickets/{ticket_id}.json")
            ticket = data['ticket']
            return {
                'id': ticket.get('id'),
                'subject': ticket.get('subject'),
                'description': ticket.get('description'),
                'status': ticket.get('status'),
                'priority': ticket.get('priority'),
                'created_at': ticket.get('created_at'),
                'updated_at': ticket.get('updated_at'),
                'requester_id': ticket.get('requester_id'),
                'assignee_id': ticket.get('assignee_id'),
                'organization_id': ticket.get('organization_id')
            }
        except Exception as e:
            raise Exception(f"Failed to get ticket {ticket_id}: {str(e)}")

    def get_ticket_comments(self, ticket_id: int) -> List[Dict[str, Any]]:
        """
        Get all comments for a specific ticket, including attachment metadata.
        """
        try:
            data = self._api_get(f"tickets/{ticket_id}/comments.json")
            result = []
            for comment in data.get('comments', []):
                attachments = []
                for a in comment.get('attachments', []):
                    attachments.append({
                        'id': a.get('id'),
                        'file_name': a.get('file_name'),
                        'content_url': a.get('content_url'),
                        'content_type': a.get('content_type'),
                        'size': a.get('size'),
                    })
                result.append({
                    'id': comment.get('id'),
                    'author_id': comment.get('author_id'),
                    'body': comment.get('body'),
                    'html_body': comment.get('html_body'),
                    'public': comment.get('public'),
                    'created_at': comment.get('created_at', ''),
                    'attachments': attachments,
                })
            return result
        except Exception as e:
            raise Exception(f"Failed to get comments for ticket {ticket_id}: {str(e)}")

    # Allowed image MIME types. SVG is excluded — it can contain active XML/JS content.
    _ALLOWED_IMAGE_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}

    # Magic bytes (file signatures) for each allowed type.
    _MAGIC_BYTES: Dict[str, List[bytes]] = {
        'image/jpeg': [b'\xff\xd8\xff'],
        'image/png':  [b'\x89PNG\r\n\x1a\n'],
        'image/gif':  [b'GIF87a', b'GIF89a'],
        'image/webp': [b'RIFF'],  # RIFF....WEBP — checked further below
    }

    # 10 MB hard cap to guard against image bombs and token budget blowout.
    _MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024

    def get_ticket_attachment(self, content_url: str) -> Dict[str, Any]:
        """
        Fetch an image attachment and return base64-encoded data.

        Security measures applied:
        - Allowlist of safe image MIME types (no SVG or arbitrary binary).
        - Magic byte validation so the file header must match the declared type.
        - 10 MB size cap to prevent image bombs and excessive token usage.

        Zendesk attachment URLs redirect to zdusercontent.com (Zendesk's CDN).
        requests strips the Authorization header on cross-origin redirects,
        which is required — the CDN returns 403 if it receives an auth header.
        """
        try:
            if self._use_cookies:
                response = self._session.get(
                    content_url,
                    timeout=30,
                    stream=True,
                )
            else:
                response = _requests.get(
                    content_url,
                    headers={'Authorization': self.auth_header},
                    timeout=30,
                    stream=True,
                )
            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '').split(';')[0].strip().lower()

            if content_type not in self._ALLOWED_IMAGE_TYPES:
                raise ValueError(
                    f"Attachment type '{content_type}' is not allowed. "
                    f"Supported types: {sorted(self._ALLOWED_IMAGE_TYPES)}"
                )

            # Read with size cap — stops download as soon as limit is exceeded.
            chunks = []
            total = 0
            for chunk in response.iter_content(chunk_size=65536):
                total += len(chunk)
                if total > self._MAX_ATTACHMENT_BYTES:
                    raise ValueError(
                        f"Attachment exceeds the {self._MAX_ATTACHMENT_BYTES // (1024*1024)} MB size limit."
                    )
                chunks.append(chunk)
            content = b''.join(chunks)

            # Validate magic bytes to catch MIME type spoofing.
            magic_signatures = self._MAGIC_BYTES.get(content_type, [])
            if magic_signatures and not any(content.startswith(sig) for sig in magic_signatures):
                raise ValueError(
                    f"File header does not match declared content type '{content_type}'. "
                    "The attachment may be spoofed."
                )
            # Extra check for WebP: bytes 8–12 must be b'WEBP'.
            if content_type == 'image/webp' and content[8:12] != b'WEBP':
                raise ValueError("File header does not match declared content type 'image/webp'.")

            return {
                'data': base64.b64encode(content).decode('ascii'),
                'content_type': content_type,
            }
        except (ValueError, _requests.HTTPError):
            raise
        except Exception as e:
            raise Exception(f"Failed to fetch attachment from {content_url}: {str(e)}")

    def post_comment(self, ticket_id: int, comment: str, public: bool = True) -> str:
        """
        Post a comment to an existing ticket.
        """
        try:
            data = {
                "ticket": {
                    "comment": {
                        "html_body": comment,
                        "public": public
                    }
                }
            }
            self._api_put(f"tickets/{ticket_id}.json", data)
            return comment
        except Exception as e:
            raise Exception(f"Failed to post comment on ticket {ticket_id}: {str(e)}")

    def get_tickets(self, page: int = 1, per_page: int = 25, sort_by: str = 'created_at', sort_order: str = 'desc') -> Dict[str, Any]:
        """
        Get the latest tickets with proper pagination support using direct API calls.

        Args:
            page: Page number (1-based)
            per_page: Number of tickets per page (max 100)
            sort_by: Field to sort by (created_at, updated_at, priority, status)
            sort_order: Sort order (asc or desc)

        Returns:
            Dict containing tickets and pagination info
        """
        try:
            # Cap at reasonable limit
            per_page = min(per_page, 100)

            params = urllib.parse.urlencode({
                'page': str(page),
                'per_page': str(per_page),
                'sort_by': sort_by,
                'sort_order': sort_order
            })
            data = self._api_get(f"tickets.json?{params}")
            tickets_data = data.get('tickets', [])

            # Process tickets to return only essential fields
            ticket_list = []
            for ticket in tickets_data:
                ticket_list.append({
                    'id': ticket.get('id'),
                    'subject': ticket.get('subject'),
                    'status': ticket.get('status'),
                    'priority': ticket.get('priority'),
                    'description': ticket.get('description'),
                    'created_at': ticket.get('created_at'),
                    'updated_at': ticket.get('updated_at'),
                    'requester_id': ticket.get('requester_id'),
                    'assignee_id': ticket.get('assignee_id')
                })

            return {
                'tickets': ticket_list,
                'page': page,
                'per_page': per_page,
                'count': len(ticket_list),
                'sort_by': sort_by,
                'sort_order': sort_order,
                'has_more': data.get('next_page') is not None,
                'next_page': page + 1 if data.get('next_page') else None,
                'previous_page': page - 1 if data.get('previous_page') and page > 1 else None
            }
        except Exception as e:
            raise Exception(f"Failed to get latest tickets: {str(e)}")

    def get_all_articles(self) -> Dict[str, Any]:
        """
        Fetch help center articles as knowledge base.
        Returns a Dict of section -> [article].
        """
        try:
            sections_url = f"https://{self.subdomain}.zendesk.com/api/v2/help_center/sections.json"
            if self._use_cookies:
                resp = self._session.get(sections_url, timeout=30)
                resp.raise_for_status()
                sections_data = resp.json()
            else:
                req = urllib.request.Request(sections_url)
                req.add_header('Authorization', self.auth_header)
                req.add_header('Content-Type', 'application/json')
                with urllib.request.urlopen(req) as response:
                    sections_data = json.loads(response.read().decode())

            kb = {}
            for section in sections_data.get('sections', []):
                articles_url = f"https://{self.subdomain}.zendesk.com/api/v2/help_center/sections/{section['id']}/articles.json"
                if self._use_cookies:
                    resp = self._session.get(articles_url, timeout=30)
                    resp.raise_for_status()
                    articles_data = resp.json()
                else:
                    req = urllib.request.Request(articles_url)
                    req.add_header('Authorization', self.auth_header)
                    req.add_header('Content-Type', 'application/json')
                    with urllib.request.urlopen(req) as response:
                        articles_data = json.loads(response.read().decode())

                kb[section.get('name', '')] = {
                    'section_id': section['id'],
                    'description': section.get('description', ''),
                    'articles': [{
                        'id': article['id'],
                        'title': article.get('title', ''),
                        'body': article.get('body', ''),
                        'updated_at': article.get('updated_at', ''),
                        'url': article.get('html_url', '')
                    } for article in articles_data.get('articles', [])]
                }

            return kb
        except Exception as e:
            raise Exception(f"Failed to fetch knowledge base: {str(e)}")

    def create_ticket(
        self,
        subject: str,
        description: str,
        requester_id: int | None = None,
        assignee_id: int | None = None,
        priority: str | None = None,
        type: str | None = None,
        tags: List[str] | None = None,
        custom_fields: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        """
        Create a new Zendesk ticket and return essential fields.
        """
        try:
            ticket_data: Dict[str, Any] = {
                "subject": subject,
                "description": description,
            }
            if requester_id is not None:
                ticket_data["requester_id"] = requester_id
            if assignee_id is not None:
                ticket_data["assignee_id"] = assignee_id
            if priority is not None:
                ticket_data["priority"] = priority
            if type is not None:
                ticket_data["type"] = type
            if tags is not None:
                ticket_data["tags"] = tags
            if custom_fields is not None:
                ticket_data["custom_fields"] = custom_fields

            result = self._api_post("tickets.json", {"ticket": ticket_data})
            ticket = result.get('ticket', {})

            return {
                'id': ticket.get('id'),
                'subject': ticket.get('subject', subject),
                'description': ticket.get('description', description),
                'status': ticket.get('status', 'new'),
                'priority': ticket.get('priority', priority),
                'type': ticket.get('type', type),
                'created_at': ticket.get('created_at', ''),
                'updated_at': ticket.get('updated_at', ''),
                'requester_id': ticket.get('requester_id', requester_id),
                'assignee_id': ticket.get('assignee_id', assignee_id),
                'organization_id': ticket.get('organization_id'),
                'tags': ticket.get('tags', tags or []),
            }
        except Exception as e:
            raise Exception(f"Failed to create ticket: {str(e)}")

    def update_ticket(self, ticket_id: int, **fields: Any) -> Dict[str, Any]:
        """
        Update a Zendesk ticket with provided fields.

        Supported fields include common ticket attributes like:
        subject, status, priority, type, assignee_id, requester_id,
        tags (list[str]), custom_fields (list[dict]), due_at, etc.
        """
        try:
            update_data = {k: v for k, v in fields.items() if v is not None}
            self._api_put(f"tickets/{ticket_id}.json", {"ticket": update_data})

            # Fetch the fresh ticket to return consistent data
            data = self._api_get(f"tickets/{ticket_id}.json")
            ticket = data['ticket']

            return {
                'id': ticket.get('id'),
                'subject': ticket.get('subject'),
                'description': ticket.get('description'),
                'status': ticket.get('status'),
                'priority': ticket.get('priority'),
                'type': ticket.get('type'),
                'created_at': ticket.get('created_at', ''),
                'updated_at': ticket.get('updated_at', ''),
                'requester_id': ticket.get('requester_id'),
                'assignee_id': ticket.get('assignee_id'),
                'organization_id': ticket.get('organization_id'),
                'tags': ticket.get('tags', []),
            }
        except Exception as e:
            raise Exception(f"Failed to update ticket {ticket_id}: {str(e)}")