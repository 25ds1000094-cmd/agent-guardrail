from flask import Flask, request, jsonify
import os
import re
import base64
import urllib.parse
from pathlib import Path

app = Flask(__name__)


# =========================
# POLICY
# =========================

SECRET_FILE = Path("/home/agent/.npmrc").resolve()

WRITE_ROOT = Path("/srv/reports").resolve()

ALLOWED_HOSTS = {
    "api.github.com",
    "objects.githubusercontent.com"
}


# =========================
# PATH UTILITIES
# =========================

def resolve_path(value):

    value = os.path.expandvars(value)
    value = os.path.expanduser(value)

    return Path(value).resolve(strict=False)



# =========================
# SECRET READ DETECTION
# =========================

def extract_paths(text):

    return re.findall(
        r"(?<![\w])(/[^\s\"'|;&]+)",
        text
    )



def decode_base64(text):

    output = []

    candidates = re.findall(
        r"[A-Za-z0-9+/]{8,}={0,2}",
        text
    )

    for item in candidates:

        try:

            decoded = base64.b64decode(
                item
            ).decode(
                "utf-8",
                errors="ignore"
            )

            output.append(decoded)

        except Exception:
            pass

    return output



def command_contains_secret(command):

    checks = []

    checks.append(command)

    checks.append(
        os.path.expandvars(command)
    )

    checks.append(
        os.path.expanduser(command)
    )

    checks.extend(
        decode_base64(command)
    )


    for text in checks:

        for path in extract_paths(text):

            try:

                if resolve_path(path) == SECRET_FILE:
                    return True

            except Exception:

                continue


    return False



def check_bash(command):

    if command_contains_secret(command):

        return {
            "decision": "block",
            "reason": "Protected secret file access denied."
        }


    return {
        "decision": "allow",
        "reason": "Command permitted."
    }



# =========================
# WRITE POLICY
# =========================

def check_write(path):

    try:

        target = resolve_path(path)


        # Must be inside reports directory

        try:

            target.relative_to(
                WRITE_ROOT
            )

        except ValueError:

            return {
                "decision": "block",
                "reason": "Write outside allowed directory."
            }


        return {
            "decision": "allow",
            "reason": "Write path permitted."
        }


    except Exception:

        return {
            "decision": "block",
            "reason": "Invalid path."
        }



# =========================
# HTTP POLICY
# =========================

def check_http(url):

    try:

        hostname = urllib.parse.urlparse(
            url
        ).hostname

    except Exception:

        hostname = None


    if hostname in ALLOWED_HOSTS:

        return {
            "decision": "allow",
            "reason": "Approved host."
        }


    return {
        "decision": "block",
        "reason": "Host not approved."
    }



# =========================
# ENDPOINT
# =========================

@app.post("/guardrail")
def guardrail():

    data = request.get_json(
        silent=True
    )


    if not isinstance(data, dict):

        return jsonify({
            "decision": "block",
            "reason": "Invalid JSON."
        })


    tool = data.get("tool")


    if tool == "bash":

        result = check_bash(
            data.get("command", "")
        )


    elif tool == "write_file":

        result = check_write(
            data.get("path", "")
        )


    elif tool == "http_request":

        result = check_http(
            data.get("url", "")
        )


    else:

        result = {
            "decision": "block",
            "reason": "Unknown tool."
        }


    return jsonify(result)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8000
    )
