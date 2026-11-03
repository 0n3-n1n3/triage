"""Validate operator-supplied configuration before it can influence a verdict."""
from __future__ import annotations

SCORING_WEIGHTS = {
    'intel_malicious', 'intel_suspicious', 'young_domain', 'dmarc_fail_brand',
    'auth_fail', 'brand_impersonation', 'exec_impersonation', 'reply_to_mismatch',
    'link_text_mismatch', 'fake_internal_link', 'credential_harvest',
    'risky_attachment', 'urgency_external', 'toad_callback',
    'allowlisted_sender', 'bulk_marketing',
}


def _strings(value, label):
    if not isinstance(value, list) or any(not isinstance(v, str) or not v.strip() for v in value):
        raise ValueError(f'{label} must be a list of nonempty strings')


def _integer(value, label, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f'{label} must be an integer >= {minimum}')


def validate_config(name: str, value: dict) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f'{name} configuration must be a JSON object')
    if name == 'scoring':
        thresholds = value.get('thresholds', {})
        if not isinstance(thresholds, dict):
            raise ValueError('scoring.thresholds must be an object')
        for key in ('benign', 'malicious'):
            _integer(thresholds.get(key), f'thresholds.{key}')
        if thresholds['benign'] >= thresholds['malicious']:
            raise ValueError('benign threshold must be below malicious threshold')
        weights = value.get('weights', {})
        if not isinstance(weights, dict) or not SCORING_WEIGHTS <= weights.keys():
            raise ValueError('scoring.weights is missing required signal names')
        for key, number in weights.items():
            if type(number) is not int:
                raise ValueError(f'weights.{key} must be an integer')
            reducer = key in {'allowlisted_sender', 'bulk_marketing'}
            if (reducer and number > 0) or (not reducer and number < 0):
                raise ValueError(f'weights.{key} has an unsafe sign')
        for key in ('young_domain_days', 'intel_malicious_min_engines', 'intel_suspicious_min_engines'):
            _integer(value.get(key), key, 1)
        for key in ('risky_extensions', 'urgency_terms', 'toad_terms', 'credential_terms'):
            _strings(value.get(key), key)
        mapping = value.get('attack_mapping', {})
        if not isinstance(mapping, dict):
            raise ValueError('attack_mapping must be an object')
        for key in ('link', 'attachment', 'voice', 'credential_harvest'):
            if not isinstance(mapping.get(key), str) or not mapping[key]:
                raise ValueError(f'attack_mapping.{key} is required')
    elif name == 'brands':
        for key, domains in value.items():
            if not key.startswith('_'):
                _strings(domains, f'brands.{key}')
    elif name in ('internal', 'allowlist', 'simulation', 'security'):
        fields = {
            'internal': ('corporate_domains', 'sharepoint_prefixes', 'executives'),
            'allowlist': ('sender_domains', 'sender_addresses'),
            'simulation': ('sender_domains', 'url_domains', 'sender_ips'),
            'security': ('trusted_authserv_ids', 'trusted_reporter_domains'),
        }[name]
        for key in fields:
            _strings(value.get(key, []), key)
        if name == 'simulation':
            if type(value.get('enabled', False)) is not bool:
                raise ValueError('simulation.enabled must be a boolean')
            markers = value.get('header_markers', {})
            if not isinstance(markers, dict) or any(
                not isinstance(k, str) or not k or not isinstance(v, str) or not v
                for k, v in markers.items()
            ):
                raise ValueError('simulation.header_markers must map header names to patterns')
        if name == 'security':
            if type(value.get('trusted_input', False)) is not bool:
                raise ValueError('security.trusted_input must be a boolean')
            for key in ('max_email_bytes', 'max_mime_parts', 'max_mime_depth', 'max_report_depth'):
                if key in value:
                    _integer(value[key], key, 1)
    else:
        raise ValueError(f'Unknown configuration name: {name}')
    return value
