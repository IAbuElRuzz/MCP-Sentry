"""Offline scenario evaluation. No MCP server, external classifier or network execution."""
from .security import Guard
from .protections import inspect_response


def simulate(policy, scenario):
    if not isinstance(scenario, dict) or set(scenario) != {'steps'} or not isinstance(scenario['steps'], list) or not 1 <= len(scenario['steps']) <= 256:
        raise ValueError('Scenario requires between 1 and 256 steps')
    for dlp in (policy.get('dlp', {}), policy.get('responses', {}).get('dlp', {})):
        if dlp.get('semantic', {}).get('mode') == 'command':
            raise ValueError('Dry-run cannot execute semantic commands; use context/off mode in a test configuration')
    now = [0.0]
    guard = Guard(policy, clock=lambda: now[0])
    results = []
    for index, step in enumerate(scenario['steps']):
        if not isinstance(step, dict) or set(step) - {'name', 'arguments', 'response', 'expect', 'advance_seconds'} or not isinstance(step.get('name'), str) or not isinstance(step.get('arguments', {}), dict):
            raise ValueError('Invalid scenario step')
        advance = step.get('advance_seconds', 0)
        if type(advance) not in (int, float) or not 0 <= advance <= 86400:
            raise ValueError('Invalid scenario clock advance')
        expected = step.get('expect')
        if expected is not None and expected not in {'allow', 'block', 'redact', 'response_block', 'response_redact', 'approval_required'}:
            raise ValueError('Invalid expected scenario decision')
        now[0] += advance
        args, reasons, count = guard.prepare_call(step['name'], step.get('arguments', {}))
        from .security import matches
        if policy.get('approvals', {}).get('enabled') and matches(step['name'], policy.get('approvals', {}).get('tools', [])):
            reasons.append('operator_approval_required')
        response_count = 0
        decision = 'block' if reasons else 'redact' if count else 'allow'
        reasons = list(dict.fromkeys(reasons))
        if reasons == ['operator_approval_required']:
            decision = 'approval_required'
        if not reasons:
            guard.record_dispatch(step['name'], args)
            if 'response' in step:
                response = step['response']
                if not isinstance(response, dict) or not isinstance(response.get('content'), list) or not isinstance(response.get('isError', False), bool):
                    raise ValueError('Scenario response requires MCP text content')
                if any(not isinstance(b, dict) or b.get('type') != 'text' or not isinstance(b.get('text'), str) for b in response['content']):
                    reasons = ['unsupported_content']
                    decision = 'response_block'
                else:
                    public = {k: response[k] for k in ('content', 'structuredContent', 'isError') if k in response}
                    guard.observe(step['name'], public)
                    _, reasons, response_count = inspect_response(step['name'], public, policy)
                    if reasons:
                        decision = 'response_block'
                    elif response_count:
                        decision = 'response_redact'
        results.append({'step': index + 1, 'decision': decision, 'reasons': reasons, 'fields_changed': count, 'response_fields_changed': response_count, 'passed': expected is None or expected == decision})
    return {'passed': all(r['passed'] for r in results), 'steps': results, 'coverage': 'Offline synthetic policy evaluation; no server behavior, catalog refresh or approval grants are simulated.'}
