"""Safe URL handling and approximate domain/subject grouping.

The small suffix table is a grouping heuristic, NOT a trust/authorization list.
Trust checks use exact host or dot-delimited subdomain matching instead.
"""
from __future__ import annotations
import ipaddress
import re
from urllib.parse import unquote, urlsplit

MULTI_SUFFIXES = {
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.in', 'org.in', 'net.in', 'gov.in',
    'ac.in', 'com.au', 'net.au', 'org.au', 'co.jp', 'com.br', 'com.cn', 'co.nz',
    'com.mx', 'com.sg', 'co.za', 'com.tr', 'com.hk', 'web.app', 'firebaseapp.com',
    'github.io', 'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app',
    'herokuapp.com', 'azurewebsites.net', 'blob.core.windows.net', 'appspot.com',
    'r2.dev', 'ngrok.io', 'ngrok-free.app',
}
TOKENISH = re.compile(r'^(?=.*\d)[A-Za-z0-9_\-]{6,}$|^[A-Fa-f0-9]{8,}$')
SUBJECT_PREFIX = re.compile(r'^\s*((re|fw|fwd|aw|wg|sv|tr)\s*:\s*|\[external\]\s*)+', re.I)


def refang(s: str) -> str:
    s = s.replace('[.]', '.').replace('(.)', '.').replace('[:]', ':')
    return re.sub(r'^hxxp(s?):', lambda m: 'http' + m.group(1).lower() + ':', s, flags=re.I)


def defang(s: str) -> str:
    s = re.sub(r'^http(s?):', lambda m: 'hxxp' + m.group(1).lower() + ':', s, flags=re.I)
    return s.replace('.', '[.]')


def canonical_host(host: str) -> str:
    host = (host or '').lower().rstrip('.')
    if not host or any(c.isspace() for c in host) or any(c in host for c in '/\\@%?#'):
        return ''
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.encode('idna').decode('ascii')
        except UnicodeError:
            return ''
        if len(host) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in host.split('.')):
            return ''
        return host


def domain_matches(host: str, allowed: str) -> bool:
    host, allowed = canonical_host(host), canonical_host(allowed)
    return bool(host and allowed and (host == allowed or host.endswith('.' + allowed)))


def _split_http(url: str):
    raw = refang((url or '').strip())
    if not raw or '\\' in raw or any(ord(c) < 32 or ord(c) == 127 for c in raw):
        return None
    if raw.startswith('//'):
        raw = 'https:' + raw
    elif '://' not in raw:
        # An explicit non-web scheme must never become a fabricated hostname.
        if re.match(r'^[a-z][a-z0-9+.-]*:', raw, re.I) and not re.match(r'^[^/:]+:\d+(?:/|$)', raw):
            return None
        raw = 'https://' + raw
    try:
        sp = urlsplit(raw)
        if sp.scheme.lower() not in ('http', 'https') or not canonical_host(sp.hostname or ''):
            return None
        _ = sp.port  # validate malformed/out-of-range ports too
        return sp
    except (ValueError, UnicodeError):
        return None


def host_of(url: str) -> str:
    sp = _split_http(url)
    return canonical_host(sp.hostname or '') if sp else ''


def canonical_url(url: str) -> str:
    """HTTP(S) URL suitable for an indicator lookup; never dereference it here."""
    sp = _split_http(url)
    if not sp:
        return ''
    host = canonical_host(sp.hostname or '')
    authority = f'[{host}]' if ':' in host else host
    if sp.port is not None:
        authority += f':{sp.port}'
    if sp.username is not None:
        # Preserve deception/user-info as part of the indicator, not the hostname.
        authority = sp.netloc.rsplit('@', 1)[0] + '@' + authority
    return f'{sp.scheme.lower()}://{authority}{sp.path or "/"}' + (f'?{sp.query}' if sp.query else '')


def registered_domain(host: str) -> str:
    host = canonical_host(host)
    if not host:
        return ''
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split('.')
    for n in (3, 2):
        if '.'.join(parts[-n:]) in MULTI_SUFFIXES and len(parts) > n:
            return '.'.join(parts[-n - 1:])
    return '.'.join(parts[-2:])


def normalize_url(url: str) -> str:
    sp = _split_http(url)
    if not sp:
        return ''
    host = canonical_host(sp.hostname or '')
    if ':' in host:
        host = '[' + host + ']'
    if sp.port is not None and sp.port not in (80, 443):
        host += f':{sp.port}'
    # Decode PATH only: decoding the whole URL can change its authority.
    segs = [('*' if TOKENISH.fullmatch(seg) else seg.lower())
            for seg in unquote(sp.path).split('/') if seg]
    return host + ('/' + '/'.join(segs) if segs else '')


def normalize_subject(subject: str) -> str:
    s = SUBJECT_PREFIX.sub('', subject or '').lower()
    s = re.sub(r'[\w.+-]+@[\w-]+\.[\w.]+', '<email>', s)
    s = re.sub(r'\d+([/.:-]\d+)*', '<n>', s)
    s = re.sub(r'#\s*<n>', '#', s)
    return re.sub(r'\s+', ' ', s).strip()
