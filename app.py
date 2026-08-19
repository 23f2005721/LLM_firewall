from flask import Flask, request, jsonify
import re

app = Flask(__name__)

TENANT = "tenant-8nw3r0c"
EMAIL_DOMAIN = "notify-cmz4nnp.example"


@app.route("/action-firewall", methods=["POST"])
def firewall():

    data = request.get_json()

    # 1 Top level schema
    if not isinstance(data, dict):
        return jsonify({
            "decision":"block",
            "reason":"INVALID_SCHEMA"
        })

    required = {"provenance", "humanApproved", "action"}

    if not required.issubset(data.keys()):
        return jsonify({
            "decision":"block",
            "reason":"INVALID_SCHEMA"
        })

    action = data["action"]

    if (
        not isinstance(action, dict)
        or "tool" not in action
        or "args" not in action
    ):
        return jsonify({
            "decision":"block",
            "reason":"INVALID_SCHEMA"
        })

    tool = action["tool"]
    args = action["args"]

    # 2 Tool allowlist
    allowed_tools = {
        "search",
        "lookup_record",
        "send_email",
        "render_html"
    }

    if tool not in allowed_tools:
        return jsonify({
            "decision":"block",
            "reason":"TOOL_NOT_ALLOWED"
        })

    # 3 Tool schema

    if tool == "search":

        if (
            set(args.keys()) != {"query"}
            or not isinstance(args["query"], str)
            or not (1 <= len(args["query"]) <= 200)
        ):
            return jsonify({
                "decision":"block",
                "reason":"INVALID_SCHEMA"
            })

    elif tool == "lookup_record":

        if set(args.keys()) != {
            "tenantId",
            "recordId"
        }:
            return jsonify({
                "decision":"block",
                "reason":"INVALID_SCHEMA"
            })

        if not args["recordId"]:
            return jsonify({
                "decision":"block",
                "reason":"INVALID_SCHEMA"
            })

        # 4 Tenant scope
        if args["tenantId"] != TENANT:
            return jsonify({
                "decision":"block",
                "reason":"TENANT_SCOPE"
            })

    elif tool == "send_email":

        if set(args.keys()) != {
            "to",
            "subject",
            "body"
        }:
            return jsonify({
                "decision":"block",
                "reason":"INVALID_SCHEMA"
            })

        email = args["to"]

        if "@" not in email:
            return jsonify({
                "decision":"block",
                "reason":"EGRESS_DENIED"
            })

        domain = email.split("@")[-1]

        # 5 Email domain
        if domain != EMAIL_DOMAIN:
            return jsonify({
                "decision":"block",
                "reason":"EGRESS_DENIED"
            })

        # 6 Approval
        if data["humanApproved"] is not True:
            return jsonify({
                "decision":"block",
                "reason":"APPROVAL_REQUIRED"
            })

    elif tool == "render_html":

        if set(args.keys()) != {"html"}:
            return jsonify({
                "decision":"block",
                "reason":"INVALID_SCHEMA"
            })

        html = args["html"].lower()

        # 7 HTML Safety

        if "<script" in html:
            return jsonify({
                "decision":"block",
                "reason":"UNSAFE_OUTPUT"
            })

        if "<iframe" in html:
            return jsonify({
                "decision":"block",
                "reason":"UNSAFE_OUTPUT"
            })

        if "javascript:" in html:
            return jsonify({
                "decision":"block",
                "reason":"UNSAFE_OUTPUT"
            })

        if re.search(r'on\w+\s*=', html):
            return jsonify({
                "decision":"block",
                "reason":"UNSAFE_OUTPUT"
            })

    return jsonify({
        "decision":"allow",
        "reason":"ALLOW"
    })


if __name__ == "__main__":
    app.run()
