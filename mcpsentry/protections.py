"""Destination restrictions and independent inspection of untrusted tool responses."""
import fnmatch
import re
from urllib.parse import urlsplit
from .dlp import OutboundInspector, validate_config
from .redaction import candidate, validate as validate_redaction


def hostname(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("Invalid destination domain")
    value = value.rstrip('.').encode('idna').decode('ascii').lower()
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
        raise ValueError("Invalid destination domain")
    return value


def validate(policy):
    config = policy.get('destinations', {})
    if not isinstance(config, dict) or set(config) - {'rules'}:
        raise ValueError('Invalid destinations configuration')
    rules = config.get('rules', [])
    if not isinstance(rules, list) or len(rules) > 128:
        raise ValueError('At most 128 destination rules are supported')
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - {'tool', 'path', 'kind', 'internal_domains', 'external_domains', 'unknown', 'allow_subdomains', 'external_action'}:
            raise ValueError('Invalid destination rule')
        if not isinstance(rule.get('tool'), str) or not 1 <= len(rule['tool']) <= 128:
            raise ValueError('Destination rule requires a tool pattern')
        path = rule.get('path')
        if not isinstance(path, str) or not path.startswith('/') or len(path) > 2048 or re.search(r'~(?![01])', path):
            raise ValueError('Destination path must be a non-root JSON pointer')
        if rule.get('kind') not in {'email', 'url', 'domain'} or rule.get('unknown', 'block') not in {'block', 'allow'}:
            raise ValueError('Invalid destination kind or unknown action')
        if rule.get('external_action', 'allow') not in {'allow', 'block', 'approval'}:
            raise ValueError('Invalid external destination action')
        if rule.get('external_action') == 'approval' and not policy.get('approvals', {}).get('enabled', False):
            raise ValueError('External destination approval requires approvals.enabled')
        if not isinstance(rule.get('allow_subdomains', False), bool):
            raise ValueError('allow_subdomains must be boolean')
        for key in ('internal_domains', 'external_domains'):
            values = rule.get(key, [])
            if not isinstance(values, list) or len(values) > 256:
                raise ValueError('Destination domains must be a bounded list')
            for domain in values:
                hostname(domain)
    response = policy.get('responses', {})
    if not isinstance(response, dict) or set(response) - {'enabled', 'dlp', 'redaction'} or not isinstance(response.get('enabled', False), bool):
        raise ValueError('Invalid responses configuration')
    validate_config(response.get('dlp', {}))
    validate_redaction(response.get('redaction', {}))
    if response.get('enabled') and not response.get('dlp', {}).get('enabled', True):
        raise ValueError('Response inspection requires DLP')


def destination_reasons(name, arguments, config):
    from .security import at_pointer, MISSING
    reasons, safe_paths = [], []
    for rule in config.get('rules', []):
        if not fnmatch.fnmatchcase(name, rule['tool']):
            continue
        value = at_pointer(arguments, rule['path'])
        values = value if isinstance(value, list) else [value]
        valid = bool(values)
        for item in values:
            try:
                if not isinstance(item, str) or not item or len(item) > 8192 or any(ord(c) <= 32 or ord(c) == 127 for c in item):
                    raise ValueError()
                if rule['kind'] == 'url':
                    url = urlsplit(item)
                    if url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None or url.fragment:
                        raise ValueError()
                    url.port  # Validate port, including malformed values.
                    domain = hostname(url.hostname)
                elif rule['kind'] == 'email':
                    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[^@]+", item):
                        raise ValueError()
                    domain = hostname(item.rsplit('@', 1)[1])
                else:
                    domain = hostname(item)
                def listed(key):
                    return any(domain == hostname(d) or rule.get('allow_subdomains', False) and domain.endswith('.' + hostname(d)) for d in rule.get(key, []))
                internal, external = listed('internal_domains'), listed('external_domains')
                known = internal or external
                if external:
                    if rule.get('external_action') == 'block':
                        reasons.append('destination_external')
                    elif rule.get('external_action') == 'approval':
                        reasons.append('operator_approval_required')
                if not known and rule.get('unknown', 'block') == 'block':
                    reasons.append('destination_unknown')
                    valid = False
            except (ValueError, UnicodeError):
                reasons.append('destination_invalid')
                valid = False
        # Exempt only explicitly approved recipient addresses from generic PII;
        # URLs can contain secrets in their path/query and are always inspected.
        if valid and rule['kind'] == 'email' and rule.get('unknown', 'block') == 'block':
            safe_paths.append(rule['path'])
            if isinstance(value, list):
                safe_paths.extend(rule['path'] + '/' + str(i) for i in range(len(value)))
    return list(dict.fromkeys(reasons)), safe_paths


def inspect_response(name, result, policy, enforce=True):
    """Never mutate originals; return sanitized result, fixed reasons, field count."""
    from .security import poisoned
    reasons = ['response_poisoning'] if policy.get('block_poisoning', True) and poisoned(result) else []
    config = policy.get('responses', {})
    if not config.get('enabled', False):
        return result, reasons, 0
    inspector = OutboundInspector(config.get('dlp', {}), True)

    def findings(value):
        inspection = inspector.inspect(name, value)
        found = ['response_sensitive_data:' + c for c in inspection.categories]
        if inspection.limit_exceeded:
            found.append('response_inspection_limit')
        if inspection.semantic_error:
            found.append('response_inspection_failed')
        return inspection, found

    inspection, detected = findings(result)
    if enforce and detected and not reasons and config.get('redaction', {}).get('enabled', False):
        rewritten, paths = candidate(result, name, config['redaction'], inspection)
        if paths:
            _, remaining = findings(rewritten)
            if not remaining and not poisoned(rewritten):
                return rewritten, [], len(paths)
    return result, reasons + detected, 0
