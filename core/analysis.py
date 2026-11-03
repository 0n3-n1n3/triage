"""Shared analysis path for uploads and separately trusted, built-in demo data."""
from dataclasses import asdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from hashlib import sha256

from core import config, simulation
from core.cluster import cluster, fingerprint, match_reasons
from core.intelligence import Enrichment
from core.models import Signal, Verdict
from core.parser import parse_bytes
from core.scoring import Scorer

RANK = {'malicious': 3, 'uncertain': 2, 'benign': 1, 'simulation': 0}
MAX_PREVIEW = 24_000
MAX_INDICATORS = 100


def analyze(files: list[tuple[str, bytes]], *, demo: bool = False) -> dict:
    security = config.load('security')
    # Uploaded EML headers can NEVER grant themselves trust, even if an operator
    # accidentally enables trusted_input in a local configuration file.
    security.update(trusted_input=False, trusted_authserv_ids=[], trusted_reporter_domains=[])
    markers = config.load('simulation')
    markers['enabled'] = False
    if demo:
        security.update(trusted_input=True, trusted_authserv_ids=['demo-gateway.example'])
        markers.update(enabled=True, sender_domains=['phish-sim.example'],
                       url_domains=['training-portal.example'],
                       header_markers={'X-Phish-Sim': 'fictional-demo-exercise'})
    scorer = Scorer()
    parsed, results, errors = [], [], []
    seen = set()
    duplicates = 0
    for name, raw in files:
        digest = sha256(raw).hexdigest()
        if digest in seen:
            duplicates += 1
            continue
        try:
            email = parse_bytes(raw, name, security=security)
            if not email.from_address and not email.subject and not email.to:
                raise ValueError('No recognizable email headers. Export the message as an .eml file.')
            is_sim, why = simulation.check(email, markers)
            if is_sim:
                verdict = Verdict('simulation', 0, [Signal('simulation', 0, why)])
            else:
                verdict = scorer.score(email, Enrichment())
            when = None
            if email.date:
                try:
                    dt = parsedate_to_datetime(email.date)
                    # A date without a zone is ambiguous; don't silently label it UTC.
                    if dt.tzinfo is not None:
                        when = dt.astimezone(timezone.utc).isoformat()
                except (ValueError, TypeError, OverflowError):
                    pass
            unique_links = list(dict.fromkeys(link.url for link in email.links))
            results.append({
                'id': digest[:24], 'filename': name,
                'subject': email.subject or '(No subject)',
                'sender_name': email.from_display or email.from_address or 'Unknown sender',
                'sender': email.from_address or 'Unknown sender',
                'reply_to': email.reply_to, 'recipients': email.to,
                'received_at': when, 'date_header': email.date,
                'verdict': verdict.verdict, 'effective_verdict': verdict.verdict,
                'score': verdict.score,
                'signals': [asdict(signal) for signal in verdict.signals],
                'techniques': verdict.attack_techniques,
                'authentication': asdict(email.auth),
                'body': email.body_text[:MAX_PREVIEW],
                'body_truncated': len(email.body_text) > MAX_PREVIEW,
                'links': unique_links[:MAX_INDICATORS],
                'link_count': len(unique_links),
                'attachments': [asdict(a) for a in email.attachments[:MAX_INDICATORS]],
                'attachment_count': len(email.attachments),
                'phones': email.phone_numbers[:MAX_INDICATORS],
                'warnings': email.warnings, 'reviewed': False,
                'campaign_id': '', 'related_count': 0,
            })
            parsed.append(email)
            seen.add(digest)
        except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
            errors.append({'filename': name, 'message': str(exc)[:300] or 'Unable to parse this email.'})
    partitions = ['simulation' if r['verdict'] == 'simulation' else 'real' for r in results]
    campaigns = []
    for group in cluster(parsed, partitions):
        worst = max((results[i]['verdict'] for i in group.members), key=RANK.get)
        for i in group.members:
            results[i]['effective_verdict'] = worst
            if group.size > 1:
                results[i]['campaign_id'] = group.campaign_id
                results[i]['related_count'] = group.size - 1
        if group.size > 1:
            reasons = set()
            for pos, i in enumerate(group.members):
                for j in group.members[pos + 1:]:
                    reasons.update(match_reasons(fingerprint(parsed[i]), fingerprint(parsed[j])))
            campaigns.append({
                'id': group.campaign_id, 'subject': results[group.members[0]]['subject'],
                'members': [results[i]['id'] for i in group.members],
                'verdict': worst, 'reasons': sorted(reasons),
            })
    return {'source': 'demo' if demo else 'upload', 'mode': 'local_rules_only',
            'analyzed_at': datetime.now(timezone.utc).isoformat(),
            'results': results, 'campaigns': campaigns, 'errors': errors,
            'duplicates_skipped': duplicates,
            'notice': 'Local rules only. No live reputation checks. Uploaded authentication '
                      'headers are untrusted. A low score does not establish safety.'}
