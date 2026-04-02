from typing import Dict, Any, List
import urllib.parse
import base64
import requests as _requests

from markdown_it import MarkdownIt
from requests.adapters import HTTPAdapter
from zenpy import Zenpy
from zenpy.lib.api_objects import Comment
from zenpy.lib.api_objects import Ticket as ZenpyTicket

from zendesk_mcp_server.auth import ApiTokenAuthProvider, AuthProvider

# CommonMark renderer used for ticket comments.
#   breaks=True -> a single newline becomes <br>, so plain text and
#                  soft-wrapped prose keep their line breaks.
#   html=True   -> raw HTML embedded in the input is passed through rather
#                  than escaped, so a caller can still hand-write HTML.
#                  Zendesk sanitizes html_body server-side (stripping scripts,
#                  event handlers, etc.), which is the safety boundary.
# table/strikethrough are enabled because agents commonly use them.
_MD = MarkdownIt("commonmark", {"breaks": True, "html": True}).enable(["table", "strikethrough"])


def markdown_to_html(text: str) -> str:
    """
    Render Markdown (or plain text) to the HTML that Zendesk stores as html_body.

    Zendesk renders a comment's html_body as HTML, which collapses runs of
    whitespace, so plain text posted verbatim loses all its newlines and any
    Markdown appears as literal characters. Rendering here keeps both intact:
    newlines survive (breaks=True) and Markdown syntax (bold, lists, links,
    code, tables) becomes real HTML. Raw HTML in the input is preserved and
    left for Zendesk to sanitize.
    """
    return _MD.render(text or "")


class ZendeskClient:
    def __init__(
        self,
        subdomain: str,
        email: str | None = None,
        token: str | None = None,
        auth: AuthProvider | None = None,
    ):
        """
        Initialize the Zendesk client using zenpy lib and direct API.

        Authentication is supplied by an AuthProvider. Passing ``email`` and
        ``token`` instead selects deprecated API-token authentication and is
        retained for backwards compatibility.

        The provider is attached to a single requests Session that is shared
        with zenpy. Because requests invokes a session's auth callable on every
        request, credentials that expire (OAuth) are refreshed transparently for
        zenpy calls and direct calls alike.
        """
        if auth is None:
            auth = ApiTokenAuthProvider(email=email, token=token)
        self.auth = auth

        self.session = self._build_session(auth)
        # zenpy skips its own authentication when the session it is handed
        # reports being already authorized, which leaves our provider in charge.
        self.client = Zenpy(subdomain=subdomain, session=self.session)

        # For direct API calls
        self.subdomain = subdomain
        self.base_url = f"https://{subdomain}.zendesk.com/api/v2"
        # Retained for backwards compatibility. Both are None under OAuth, where
        # there is no email/token pair.
        self.email = email
        self.token = token

    @staticmethod
    def _build_session(auth: AuthProvider) -> _requests.Session:
        session = _requests.Session()
        # zenpy only mounts its retrying adapter on sessions it creates itself,
        # so mount it here to keep the same retry behaviour.
        session.mount("https://", HTTPAdapter(**Zenpy.http_adapter_kwargs()))
        session.auth = auth
        session.authorized = True
        # Providers holding expiring credentials opt into retrying a request once
        # after the credential is rejected mid-flight.
        response_hook = getattr(auth, "response_hook", None)
        if response_hook is not None:
            session.hooks["response"].append(response_hook)
        return session

    @property
    def auth_header(self) -> str:
        """
        Current Authorization header value.

        Read through the provider on every access rather than cached once, so a
        rotated OAuth token is picked up.
        """
        return self.auth.auth_header()

    def _api_get(self, path: str) -> Dict[str, Any]:
        """Make a GET request to the Zendesk API."""
        resp = self.session.get(f"{self.base_url}/{path}", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _api_post(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make a POST request to the Zendesk API."""
        resp = self.session.post(f"{self.base_url}/{path}", json=data, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _api_delete(self, path: str) -> None:
        """Make a DELETE request to the Zendesk API."""
        resp = self.session.delete(f"{self.base_url}/{path}", timeout=30)
        resp.raise_for_status()

    def get_ticket(self, ticket_id: int) -> Dict[str, Any]:
        """
        Query a ticket by its ID
        """
        try:
            ticket = self.client.tickets(id=ticket_id)
            return {
                'id': ticket.id,
                'subject': ticket.subject,
                'description': ticket.description,
                'status': ticket.status,
                'priority': ticket.priority,
                'created_at': str(ticket.created_at),
                'updated_at': str(ticket.updated_at),
                'requester_id': ticket.requester_id,
                'assignee_id': ticket.assignee_id,
                'organization_id': ticket.organization_id
            }
        except Exception as e:
            raise Exception(f"Failed to get ticket {ticket_id}: {str(e)}")

    def get_ticket_comments(self, ticket_id: int) -> List[Dict[str, Any]]:
        """
        Get all comments for a specific ticket, including attachment metadata.
        """
        try:
            comments = self.client.tickets.comments(ticket=ticket_id)
            result = []
            for comment in comments:
                attachments = []
                for a in getattr(comment, 'attachments', []) or []:
                    attachments.append({
                        'id': a.id,
                        'file_name': a.file_name,
                        'content_url': a.content_url,
                        'content_type': a.content_type,
                        'size': a.size,
                    })
                result.append({
                    'id': comment.id,
                    'author_id': comment.author_id,
                    'body': comment.body,
                    'html_body': comment.html_body,
                    'public': comment.public,
                    'created_at': str(comment.created_at),
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
        The session's auth callable is applied when the request is prepared and
        is not reapplied by requests on redirect, so this still holds.
        """
        try:
            response = self.session.get(
                content_url,
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

        The comment is treated as Markdown (plain text is valid Markdown) and
        rendered to HTML so newlines and formatting survive in Zendesk.
        """
        try:
            ticket = self.client.tickets(id=ticket_id)
            ticket.comment = Comment(
                html_body=markdown_to_html(comment),
                public=public
            )
            self.client.tickets.update(ticket)
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
            # Get all sections
            sections = self.client.help_center.sections()

            # Get articles for each section
            kb = {}
            for section in sections:
                articles = self.client.help_center.sections.articles(section.id)
                kb[section.name] = {
                    'section_id': section.id,
                    'description': section.description,
                    'articles': [{
                        'id': article.id,
                        'title': article.title,
                        'body': article.body,
                        'updated_at': str(article.updated_at),
                        'url': article.html_url
                    } for article in articles]
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
        Create a new Zendesk ticket using Zenpy and return essential fields.

        Args:
            subject: Ticket subject
            description: Ticket description (plain text). Will also be used as initial comment.
            requester_id: Optional requester user ID
            assignee_id: Optional assignee user ID
            priority: Optional priority (low, normal, high, urgent)
            type: Optional ticket type (problem, incident, question, task)
            tags: Optional list of tags
            custom_fields: Optional list of dicts: {id: int, value: Any}
        """
        try:
            ticket = ZenpyTicket(
                subject=subject,
                description=description,
                requester_id=requester_id,
                assignee_id=assignee_id,
                priority=priority,
                type=type,
                tags=tags,
                custom_fields=custom_fields,
            )
            created_audit = self.client.tickets.create(ticket)
            # Fetch created ticket id from audit
            created_ticket_id = getattr(getattr(created_audit, 'ticket', None), 'id', None)
            if created_ticket_id is None:
                # Fallback: try to read id from audit events
                created_ticket_id = getattr(created_audit, 'id', None)

            # Fetch full ticket to return consistent data
            created = self.client.tickets(id=created_ticket_id) if created_ticket_id else None

            return {
                'id': getattr(created, 'id', created_ticket_id),
                'subject': getattr(created, 'subject', subject),
                'description': getattr(created, 'description', description),
                'status': getattr(created, 'status', 'new'),
                'priority': getattr(created, 'priority', priority),
                'type': getattr(created, 'type', type),
                'created_at': str(getattr(created, 'created_at', '')),
                'updated_at': str(getattr(created, 'updated_at', '')),
                'requester_id': getattr(created, 'requester_id', requester_id),
                'assignee_id': getattr(created, 'assignee_id', assignee_id),
                'organization_id': getattr(created, 'organization_id', None),
                'tags': list(getattr(created, 'tags', tags or []) or []),
            }
        except Exception as e:
            raise Exception(f"Failed to create ticket: {str(e)}")

    def update_ticket(self, ticket_id: int, **fields: Any) -> Dict[str, Any]:
        """
        Update a Zendesk ticket with provided fields using Zenpy.

        Supported fields include common ticket attributes like:
        subject, status, priority, type, assignee_id, requester_id,
        tags (list[str]), custom_fields (list[dict]), due_at, etc.
        """
        try:
            # Load the ticket, mutate fields directly, and update
            ticket = self.client.tickets(id=ticket_id)
            for key, value in fields.items():
                if value is None:
                    continue
                setattr(ticket, key, value)

            # This call returns a TicketAudit (not a Ticket). Don't read attrs from it.
            self.client.tickets.update(ticket)

            # Fetch the fresh ticket to return consistent data
            refreshed = self.client.tickets(id=ticket_id)

            return {
                'id': refreshed.id,
                'subject': refreshed.subject,
                'description': refreshed.description,
                'status': refreshed.status,
                'priority': refreshed.priority,
                'type': getattr(refreshed, 'type', None),
                'created_at': str(refreshed.created_at),
                'updated_at': str(refreshed.updated_at),
                'requester_id': refreshed.requester_id,
                'assignee_id': refreshed.assignee_id,
                'organization_id': refreshed.organization_id,
                'tags': list(getattr(refreshed, 'tags', []) or []),
            }
        except Exception as e:
            raise Exception(f"Failed to update ticket {ticket_id}: {str(e)}")

    # ── P0: Search & Users ──────────────────────────────────────────────

    def search(self, query: str, page: int = 1, per_page: int = 25,
               sort_by: str = 'relevance', sort_order: str = 'desc') -> Dict[str, Any]:
        """Search tickets, users, orgs using Zendesk Query Language (ZQL)."""
        try:
            per_page = min(per_page, 100)
            params = urllib.parse.urlencode({
                'query': query, 'page': str(page),
                'per_page': str(per_page),
                'sort_by': sort_by, 'sort_order': sort_order,
            })
            data = self._api_get(f"search.json?{params}")
            return {
                'results': data.get('results', []),
                'count': data.get('count', 0),
                'page': page,
                'per_page': per_page,
                'has_more': data.get('next_page') is not None,
            }
        except Exception as e:
            raise Exception(f"Search failed: {str(e)}")

    def get_user(self, user_id: int) -> Dict[str, Any]:
        """Get a user by ID."""
        try:
            data = self._api_get(f"users/{user_id}.json")
            u = data['user']
            return {
                'id': u.get('id'), 'name': u.get('name'),
                'email': u.get('email'), 'role': u.get('role'),
                'phone': u.get('phone'), 'photo_url': (u.get('photo') or {}).get('content_url'),
                'organization_id': u.get('organization_id'),
                'time_zone': u.get('time_zone'),
                'active': u.get('active'), 'suspended': u.get('suspended'),
                'created_at': u.get('created_at'), 'updated_at': u.get('updated_at'),
                'tags': u.get('tags', []),
            }
        except Exception as e:
            raise Exception(f"Failed to get user {user_id}: {str(e)}")

    def get_current_user(self) -> Dict[str, Any]:
        """Get the currently authenticated user."""
        try:
            data = self._api_get("users/me.json")
            u = data['user']
            return {
                'id': u.get('id'), 'name': u.get('name'),
                'email': u.get('email'), 'role': u.get('role'),
                'organization_id': u.get('organization_id'),
                'time_zone': u.get('time_zone'),
                'default_group_id': u.get('default_group_id'),
            }
        except Exception as e:
            raise Exception(f"Failed to get current user: {str(e)}")

    def search_users(self, query: str) -> List[Dict[str, Any]]:
        """Search users by name, email, or external_id."""
        try:
            params = urllib.parse.urlencode({'query': query})
            data = self._api_get(f"users/search.json?{params}")
            return [{
                'id': u.get('id'), 'name': u.get('name'),
                'email': u.get('email'), 'role': u.get('role'),
                'organization_id': u.get('organization_id'),
                'active': u.get('active'),
            } for u in data.get('users', [])]
        except Exception as e:
            raise Exception(f"User search failed: {str(e)}")

    # ── P1: Views, Fields, Orgs, Bulk ───────────────────────────────────

    def list_views(self) -> List[Dict[str, Any]]:
        """List all available views."""
        try:
            data = self._api_get("views.json")
            return [{
                'id': v.get('id'), 'title': v.get('title'),
                'active': v.get('active'),
                'position': v.get('position'),
            } for v in data.get('views', [])]
        except Exception as e:
            raise Exception(f"Failed to list views: {str(e)}")

    def execute_view(self, view_id: int, page: int = 1, per_page: int = 25) -> Dict[str, Any]:
        """Execute a view and return its tickets."""
        try:
            per_page = min(per_page, 100)
            params = urllib.parse.urlencode({'page': str(page), 'per_page': str(per_page)})
            data = self._api_get(f"views/{view_id}/tickets.json?{params}")
            return {
                'tickets': [{
                    'id': t.get('id'), 'subject': t.get('subject'),
                    'status': t.get('status'), 'priority': t.get('priority'),
                    'requester_id': t.get('requester_id'),
                    'assignee_id': t.get('assignee_id'),
                    'group_id': t.get('group_id'),
                    'created_at': t.get('created_at'),
                    'updated_at': t.get('updated_at'),
                } for t in data.get('tickets', [])],
                'count': len(data.get('tickets', [])),
                'has_more': data.get('next_page') is not None,
            }
        except Exception as e:
            raise Exception(f"Failed to execute view {view_id}: {str(e)}")

    def list_ticket_fields(self) -> List[Dict[str, Any]]:
        """List all ticket fields (system + custom)."""
        try:
            data = self._api_get("ticket_fields.json")
            return [{
                'id': f.get('id'), 'title': f.get('title'),
                'type': f.get('type'), 'active': f.get('active'),
                'required': f.get('required'),
                'custom_field_options': [
                    {'name': o.get('name'), 'value': o.get('value')}
                    for o in f.get('custom_field_options', [])
                ] if f.get('custom_field_options') else None,
            } for f in data.get('ticket_fields', [])]
        except Exception as e:
            raise Exception(f"Failed to list ticket fields: {str(e)}")

    def get_organization(self, org_id: int) -> Dict[str, Any]:
        """Get an organization by ID."""
        try:
            data = self._api_get(f"organizations/{org_id}.json")
            o = data['organization']
            return {
                'id': o.get('id'), 'name': o.get('name'),
                'domain_names': o.get('domain_names', []),
                'details': o.get('details'), 'notes': o.get('notes'),
                'group_id': o.get('group_id'),
                'tags': o.get('tags', []),
                'created_at': o.get('created_at'),
                'updated_at': o.get('updated_at'),
            }
        except Exception as e:
            raise Exception(f"Failed to get organization {org_id}: {str(e)}")

    def search_organizations(self, query: str) -> List[Dict[str, Any]]:
        """Search organizations by name or external_id."""
        try:
            params = urllib.parse.urlencode({'name': query})
            data = self._api_get(f"organizations/autocomplete.json?{params}")
            return [{
                'id': o.get('id'), 'name': o.get('name'),
                'domain_names': o.get('domain_names', []),
            } for o in data.get('organizations', [])]
        except Exception as e:
            raise Exception(f"Organization search failed: {str(e)}")

    def get_tickets_bulk(self, ticket_ids: List[int]) -> List[Dict[str, Any]]:
        """Fetch multiple tickets by IDs in a single request (max 100)."""
        try:
            ids_str = ','.join(str(i) for i in ticket_ids[:100])
            data = self._api_get(f"tickets/show_many.json?ids={ids_str}")
            return [{
                'id': t.get('id'), 'subject': t.get('subject'),
                'status': t.get('status'), 'priority': t.get('priority'),
                'requester_id': t.get('requester_id'),
                'assignee_id': t.get('assignee_id'),
                'group_id': t.get('group_id'),
                'created_at': t.get('created_at'),
                'updated_at': t.get('updated_at'),
            } for t in data.get('tickets', [])]
        except Exception as e:
            raise Exception(f"Bulk ticket fetch failed: {str(e)}")

    # ── P2: Groups, Merge, Macros ───────────────────────────────────────

    def list_groups(self) -> List[Dict[str, Any]]:
        """List assignable groups."""
        try:
            data = self._api_get("groups/assignable.json")
            return [{
                'id': g.get('id'), 'name': g.get('name'),
                'description': g.get('description'),
            } for g in data.get('groups', [])]
        except Exception as e:
            raise Exception(f"Failed to list groups: {str(e)}")

    def merge_tickets(self, target_id: int, source_ids: List[int],
                      target_comment: str = "Merged from related tickets.",
                      source_comment: str = "This ticket has been merged.") -> Dict[str, Any]:
        """Merge source tickets into a target ticket."""
        try:
            data = {
                "ids": source_ids,
                "target_comment": target_comment,
                "source_comment": source_comment,
            }
            result = self._api_post(f"tickets/{target_id}/merge.json", data)
            return result
        except Exception as e:
            raise Exception(f"Failed to merge tickets into {target_id}: {str(e)}")

    def list_macros(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """List available macros."""
        try:
            path = "macros/active.json" if active_only else "macros.json"
            data = self._api_get(path)
            return [{
                'id': m.get('id'), 'title': m.get('title'),
                'description': m.get('description'),
                'active': m.get('active'),
            } for m in data.get('macros', [])]
        except Exception as e:
            raise Exception(f"Failed to list macros: {str(e)}")

    def apply_macro(self, ticket_id: int, macro_id: int) -> Dict[str, Any]:
        """Preview the result of applying a macro to a ticket."""
        try:
            data = self._api_get(f"tickets/{ticket_id}/macros/{macro_id}/apply.json")
            result = data.get('result', {})
            ticket = result.get('ticket', {})
            return {
                'ticket_changes': ticket,
                'comment': result.get('comment'),
            }
        except Exception as e:
            raise Exception(f"Failed to apply macro {macro_id} to ticket {ticket_id}: {str(e)}")

    # ── P3: User Tickets, Forms, Delete ─────────────────────────────────

    def get_user_tickets(self, user_id: int, role: str = 'requested',
                         page: int = 1, per_page: int = 25) -> Dict[str, Any]:
        """Get tickets for a user. role: 'requested', 'assigned', or 'ccd'."""
        try:
            per_page = min(per_page, 100)
            params = urllib.parse.urlencode({'page': str(page), 'per_page': str(per_page)})
            data = self._api_get(f"users/{user_id}/tickets/{role}.json?{params}")
            return {
                'tickets': [{
                    'id': t.get('id'), 'subject': t.get('subject'),
                    'status': t.get('status'), 'priority': t.get('priority'),
                    'created_at': t.get('created_at'),
                    'updated_at': t.get('updated_at'),
                } for t in data.get('tickets', [])],
                'has_more': data.get('next_page') is not None,
            }
        except Exception as e:
            raise Exception(f"Failed to get tickets for user {user_id}: {str(e)}")

    def list_ticket_forms(self) -> List[Dict[str, Any]]:
        """List all ticket forms."""
        try:
            data = self._api_get("ticket_forms.json")
            return [{
                'id': f.get('id'), 'name': f.get('name'),
                'display_name': f.get('display_name'),
                'active': f.get('active'), 'default': f.get('default'),
                'ticket_field_ids': f.get('ticket_field_ids', []),
            } for f in data.get('ticket_forms', [])]
        except Exception as e:
            raise Exception(f"Failed to list ticket forms: {str(e)}")

    def delete_ticket(self, ticket_id: int) -> None:
        """Permanently delete a ticket."""
        try:
            self._api_delete(f"tickets/{ticket_id}.json")
        except Exception as e:
            raise Exception(f"Failed to delete ticket {ticket_id}: {str(e)}")