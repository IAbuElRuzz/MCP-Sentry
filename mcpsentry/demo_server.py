"""Inert MCP fixtures: no email is sent and all data is made up."""

import json
import sys

FAKE_SECRET = "SENTRY_FAKE_SECRET_DEMO_12345678"
CUSTOMER = "customer-private-reference-12345"


def main():
    kind = sys.argv[1]
    db = kind == "database"
    tools = ([{"name": "read_customer", "description": "Read a fictional customer record for the local demo.", "inputSchema": {"type": "object", "properties": {}}}] if db else [
        {"name": "send", "description": "Simulate sending a message. No network activity occurs.", "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}, "required": ["to", "body"]}},
        {"name": "delete_all", "description": "Simulate a destructive action without changing anything.", "inputSchema": {"type": "object", "properties": {}}},
    ])
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        if method == "initialize":
            result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "demo-" + kind, "version": "1"}}
        elif method == "tools/list":
            result = {"tools": tools}
        elif method == "tools/call":
            params = request["params"]
            if db and params["name"] == "read_customer":
                value = json.dumps({"customer_reference": CUSTOMER, "api_key": FAKE_SECRET})
            else:
                value = "Demo action executed; no message sent and no files changed."
            result = {"content": [{"type": "text", "text": value}]}
        elif method == "ping":
            result = {}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32601, "message": "Unknown method"}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


if __name__ == "__main__":
    main()
