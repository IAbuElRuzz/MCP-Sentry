"""Hash-only catalog comparisons: never persist server descriptions or schemas."""
FIELDS = ('description', 'inputSchema', 'outputSchema', 'title', 'annotations')


def components(tool):
    from .security import fingerprint
    return {field: fingerprint({'present': field in tool, 'value': tool.get(field)}) for field in FIELDS}


def differences(approved, current):
    findings = []
    before, after = approved.get('tools', {}), current['tools']
    for name in sorted(before.keys() | after.keys()):
        reason = 'tool_added' if name not in before else 'tool_removed' if name not in after else 'tool_changed' if before[name] != after[name] else None
        fields = []
        if name in before and name in after:
            old = approved.get('components', {}).get(name, {})
            new = current.get('components', {}).get(name, {})
            if old and new:
                fields = [field for field in FIELDS if old.get(field) != new.get(field)]
                if fields:
                    reason = 'tool_changed'
        if reason:
            findings.append({'tool': name, 'reason': reason, 'fields': fields})
    if approved.get('configuration') != current.get('configuration'):
        findings.append({'tool': '', 'reason': 'configuration_changed', 'fields': []})
    return findings
