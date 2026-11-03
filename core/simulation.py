"""Gate 0: verified simulation origin AND an explicit campaign marker.

A landing URL, Received IP, or attacker-supplied X-header alone is never proof.
"""
from __future__ import annotations
import fnmatch
from core import config
from core.models import ParsedEmail
from core.normalize import domain_matches, host_of
from core.validation import validate_config


def check(email: ParsedEmail, markers: dict | None = None) -> tuple[bool, str]:
    m = config.load('simulation') if markers is None else validate_config('simulation', markers)
    if not m.get('enabled', False) or email.warnings:
        return False, ''
    a = email.auth
    if not (a.trusted and a.dmarc == 'pass') or any(
        value in ('fail', 'softfail', 'temperror', 'permerror') for value in (a.spf, a.dkim, a.dmarc)
    ):
        return False, ''
    if not any(domain_matches(email.from_domain, domain) for domain in m.get('sender_domains', [])):
        return False, ''
    headers = {k.lower(): v for k, v in email.headers.items()}
    matched = next((name for name, pattern in m.get('header_markers', {}).items()
                    if headers.get(name.lower()) is not None
                    and fnmatch.fnmatchcase(headers[name.lower()], pattern)), None)
    if not matched:
        return False, ''
    allowed_urls = m.get('url_domains', [])
    if email.links and any(not any(domain_matches(host_of(link.url), domain) for domain in allowed_urls)
                           for link in email.links):
        return False, ''
    if email.attachments:
        return False, ''  # payload-bearing exercises require analyst confirmation
    return True, f'Verified simulation: trusted DMARC pass for {email.from_domain}, marker {matched}'
