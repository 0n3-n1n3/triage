"""Bounded MIME parsing with explicit ingestion trust and visible uncertainty.

Raw EML headers are evidence, not authenticated facts. Trusted-input policies
are only appropriate after a controlled mail gateway has removed forged headers.
An arbitrary message containing an attached EML is NOT automatically a report.
"""
from __future__ import annotations
import hashlib
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path

from core import config
from core.models import Attachment, AuthResults, Link, ParsedEmail
from core.normalize import canonical_host, domain_matches, host_of
from core.validation import validate_config

URL_RE = re.compile(r'''(?i)\b((?:https?://|hxxps?://|www\.)[^\s<>"'\)]+)''')
PHONE_RE = re.compile(r'(?<!\w)(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\w)')
AUTH_RE = re.compile(r'(?:^|;)\s*(spf|dkim|dmarc)(?:/\d+)?\s*=\s*([a-z]+)\b', re.I)
MAX_BODY_CHARS = 200_000
MAX_LINKS = 1000


class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []
        self._hidden = 0
        self.has_form = False
        self.has_password_input = False

    def _flush(self):
        if self._href is not None:
            self.links.append(Link(self._href.strip(), ' '.join(''.join(self._buf).split())))
        self._href, self._buf = None, []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ('script', 'style'):
            self._hidden += 1
        if tag == 'a':
            self._flush()
            self._href = a.get('href')
        elif tag == 'form':
            self.has_form = True
            if a.get('action'):
                self.links.append(Link(a['action'].strip(), 'form submission'))
        elif tag in ('button', 'input') and a.get('formaction'):
            self.links.append(Link(a['formaction'].strip(), 'form submission'))
        if tag == 'input' and (a.get('type') or '').lower() == 'password':
            self.has_password_input = True
        if tag in ('br', 'p', 'div', 'tr', 'li'):
            self.text.append('\n')

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self._hidden = max(0, self._hidden - 1)
        if tag == 'a':
            self._flush()
        if tag in ('p', 'div', 'tr', 'li'):
            self.text.append('\n')

    def handle_data(self, data):
        if not self._hidden:
            self.text.append(data)
            if self._href is not None:
                self._buf.append(data)

    def close(self):
        super().close()
        self._flush()  # malformed/unclosed anchors must not hide destinations


def _parse_bytes(raw: bytes) -> EmailMessage:
    try:
        return BytesParser(policy=policy.default).parsebytes(raw)
    except (RecursionError, ValueError) as exc:
        raise ValueError('Malformed or excessively nested MIME message') from exc


def _walk_bounded(msg: EmailMessage, settings: dict):
    stack = [(msg, 0)]
    count = 0
    while stack:
        part, depth = stack.pop()
        count += 1
        if count > settings.get('max_mime_parts', 500) or depth > settings.get('max_mime_depth', 20):
            raise ValueError('Message exceeds MIME part/depth limits')
        yield part
        payload = part.get_payload()
        if isinstance(payload, list):
            stack.extend((child, depth + 1) for child in reversed(payload))


def _content_parts(msg: EmailMessage):
    # Do not descend into attached messages or multipart attachments.
    stack = [msg]
    while stack:
        part = stack.pop()
        if part.get_content_type() == 'message/rfc822' or part.get_content_disposition() == 'attachment' or part.get_filename():
            yield part
        elif part.is_multipart():
            stack.extend(reversed(part.get_payload()))
        else:
            yield part


def _embedded_originals(msg: EmailMessage) -> list[EmailMessage]:
    out = []
    for part in _content_parts(msg):
        if part is msg:
            continue
        if part.get_content_type() == 'message/rfc822':
            payload = part.get_payload()
            if isinstance(payload, list):
                out.extend(payload)
        elif (part.get_filename() or '').lower().endswith('.eml'):
            data = part.get_payload(decode=True)
            if data:
                out.append(_parse_bytes(data))
    return out


def _auth(msg: EmailMessage, settings: dict) -> AuthResults:
    headers = [str(h) for h in msg.get_all('Authentication-Results', [])]
    if not headers:
        return AuthResults()
    trusted_ids = {s.lower().rstrip('.') for s in settings.get('trusted_authserv_ids', [])}
    selected_headers = [headers[0]]
    trusted = False
    if settings.get('trusted_input', False):
        matched = []
        for header in headers:
            server = header.split(';', 1)[0].strip().split()[0:1]
            if server and server[0].lower().rstrip('.') in trusted_ids:
                matched.append(header)
        if matched:
            selected_headers, trusted = matched, True
    server = selected_headers[0].split(';', 1)[0].strip().split()[0:1]
    result = AuthResults(available=True, trusted=trusted, authserv_id=server[0] if server else None)
    methods = {'spf': [], 'dkim': [], 'dmarc': []}
    for selected in selected_headers:
        matches = AUTH_RE.findall(selected)
        if not matches:
            result.trusted = False
        for key, value in matches:
            methods[key.lower()].append(value.lower())
    for key, values in methods.items():
        if values:
            # Do not let a duplicate pass mask an explicit failure/error.
            value = next((v for v in values if v != 'pass'), 'pass')
            setattr(result, key, value)
    if not any(methods.values()):
        result.trusted = False
    return result


def _bodies(msg: EmailMessage, warnings: list[str]) -> tuple[str, str]:
    text, html = [], []
    for part in _content_parts(msg):
        if part.is_multipart() or part.get_content_disposition() == 'attachment' or part.get_filename():
            continue
        ctype = part.get_content_type()
        if ctype not in ('text/plain', 'text/html'):
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, ValueError):
            warnings.append('Body charset/decoding fallback used; inspect original')
            content = (part.get_payload(decode=True) or b'').decode('utf-8', 'replace')
        if isinstance(content, str):
            if '\ufffd' in content:
                warnings.append('Body contains replacement characters; decoding may be incomplete')
            (text if ctype == 'text/plain' else html).append(content)
    return '\n'.join(text), '\n'.join(html)


def _attachments(msg: EmailMessage) -> list[Attachment]:
    out = []
    for part in _content_parts(msg):
        ctype = part.get_content_type()
        fname = part.get_filename()
        is_attachment = bool(fname) or part.get_content_disposition() == 'attachment' or ctype == 'message/rfc822'
        # Non-text leaf parts (including unnamed inline files) are still payloads.
        if not is_attachment and (part.is_multipart() or ctype in ('text/plain', 'text/html')):
            continue
        if not fname:
            extension = {'text/html': '.html', 'image/svg+xml': '.svg', 'message/rfc822': '.eml'}.get(ctype, '.bin')
            fname = f'unnamed-{len(out) + 1}{extension}'
        data = part.get_payload(decode=True)
        if data is None:
            data = part.as_bytes(policy=policy.default)
        ext = Path(fname.replace('\\', '/').rstrip(' .')).suffix.lower()
        out.append(Attachment(fname, ctype, len(data), hashlib.sha256(data).hexdigest(), ext))
    return out


def _phones(text: str) -> list[str]:
    return list(dict.fromkeys(
        digits for m in PHONE_RE.finditer(text)
        if 10 <= len(digits := re.sub(r'\D', '', m.group(0))) <= 13
    ))


def parse_message(msg: EmailMessage, source_file: str | None = None, *, security: dict | None = None) -> ParsedEmail:
    settings = config.load('security') if security is None else validate_config('security', security)
    parts = list(_walk_bounded(msg, settings))
    warnings = []
    if any(part.defects for part in parts):
        warnings.append('MIME defects detected; interpretation may be incomplete')
    reporter, unwrapped = None, False
    depth = 0
    while True:
        inner = _embedded_originals(msg)
        if not inner:
            break
        outer_addr = parseaddr(str(msg.get('From', '')))[1].lower()
        outer_domain = outer_addr.rsplit('@', 1)[-1] if '@' in outer_addr else ''
        outer_auth = _auth(msg, settings)
        approved = (outer_auth.trusted and outer_auth.dmarc == 'pass'
                    and len(msg.get_all('From', [])) == 1
                    and any(domain_matches(outer_domain, d) for d in settings.get('trusted_reporter_domains', [])))
        side_attachments = [part for part in _content_parts(msg)
                            if part.get_content_type() != 'message/rfc822'
                            and not (part.get_filename() or '').lower().endswith('.eml')
                            and (part.get_filename() or part.get_content_disposition() == 'attachment'
                                 or part.get_content_maintype() not in ('text', 'multipart'))]
        if side_attachments:
            warnings.append('Embedded email not unwrapped: additional wrapper attachments require review')
            break
        if not approved or len(inner) != 1:
            warnings.append('Embedded email not unwrapped: untrusted wrapper or multiple originals')
            break
        if depth >= settings.get('max_report_depth', 5):
            warnings.append('Report wrapper depth limit reached')
            break
        if not inner[0].get('From'):
            warnings.append('Attached original is missing a From header')
            break
        reporter = reporter or outer_addr
        msg, unwrapped = inner[0], True
        depth += 1
        if any(part.defects for part in _walk_bounded(msg, settings)):
            warnings.append('Attached original has MIME defects')
    if (len(msg.get_all('From', [])) != 1
            or len(getaddresses([str(msg.get('From', ''))])) != 1):
        warnings.append('Missing, duplicate or multiple-address From header')
    disp, addr = parseaddr(str(msg.get('From', '')))
    addr = addr.lower()
    domain = canonical_host(addr.rsplit('@', 1)[-1]) if '@' in addr else ''
    if not domain:
        warnings.append('Missing or invalid sender address')
    if any(getattr(value, 'defects', ()) for _, value in msg.items()):
        warnings.append('Malformed message header detected')
    body_text, body_html = _bodies(msg, warnings)
    if len(body_text) + len(body_html) > MAX_BODY_CHARS:
        warnings.append('Body inspection limit reached')
        body_text, body_html = body_text[:MAX_BODY_CHARS // 2], body_html[:MAX_BODY_CHARS // 2]
    links = []
    lx = _LinkExtractor()
    if body_html:
        lx.feed(body_html)
        lx.close()
        links.extend(lx.links)
    html_text = ''.join(lx.text)
    visible = '\n'.join(x for x in (body_text, html_text) if x.strip())
    seen = {link.url for link in links}
    for match in URL_RE.finditer(visible):
        url = match.group(1).rstrip('.,;')
        if url not in seen:
            links.append(Link(url))
            seen.add(url)
    filtered = []
    for link in links:
        if (re.match(r'(?i)^(?:https?://|hxxps?://|//|www\.)', link.url) and host_of(link.url)):
            filtered.append(link)
        elif not link.url.lower().startswith(('mailto:', 'tel:', '#')):
            warnings.append('Unsupported or malformed link target requires review')
    # Keep anchor evidence when the same URL occurs with different visible text.
    unique = {(link.url, link.text): link for link in filtered}
    if len(unique) > MAX_LINKS:
        warnings.append('Link inspection limit reached')
    attachments = _attachments(msg)
    if any(item.filename.startswith('unnamed-') for item in attachments):
        warnings.append('Unnamed attachment requires manual content verification')
    if any(part.defects for part in _walk_bounded(msg, settings)):
        warnings.append('MIME decoding defects detected; inspect original')
    headers = {}
    for key, value in msg.items():
        name = key.lower()
        headers[name] = headers[name] + '\n' + str(value) if name in headers else str(value)
    return ParsedEmail(
        message_id=str(msg.get('Message-ID', '')).strip(), subject=str(msg.get('Subject', '')),
        from_display=disp, from_address=addr, from_domain=domain,
        reply_to=parseaddr(str(msg.get('Reply-To', '')))[1].lower() or None,
        return_path=parseaddr(str(msg.get('Return-Path', '')))[1].lower() or None,
        to=[a.lower() for _, a in getaddresses([str(x) for x in msg.get_all('To', [])]) if a],
        date=str(msg.get('Date', '')) or None, body_text=visible, body_html=body_html,
        links=list(unique.values())[:MAX_LINKS], attachments=attachments,
        phone_numbers=_phones(visible), auth=_auth(msg, settings), headers=headers,
        reporter=reporter, unwrapped=unwrapped, source_file=source_file,
        warnings=list(dict.fromkeys(warnings)), has_form=lx.has_form,
        has_password_input=lx.has_password_input,
    )


def parse_bytes(raw: bytes, source_file: str | None = None, *, security: dict | None = None) -> ParsedEmail:
    settings = config.load('security') if security is None else validate_config('security', security)
    if not isinstance(raw, bytes) or not raw.strip():
        raise ValueError('Email must be nonempty bytes')
    if len(raw) > settings.get('max_email_bytes', 10_485_760):
        raise ValueError('Email exceeds configured size limit')
    return parse_message(_parse_bytes(raw), source_file, security=settings)


def parse_file(path: str | Path, *, security: dict | None = None) -> ParsedEmail:
    settings = config.load('security') if security is None else validate_config('security', security)
    p = Path(path)
    limit = settings.get('max_email_bytes', 10_485_760)
    with p.open('rb') as stream:
        raw = stream.read(limit + 1)
    return parse_bytes(raw, source_file=p.name, security=settings)
