from flask import Flask, request, jsonify
import os
import re
import base64
import urllib.parse
from pathlib import Path

app = Flask(__name__)


# =====================================
# SECURITY POLICY
# =====================================

SECRET_FILE = Path("/home/agent/.npmrc").resolve()

WRITE_ROOT = Path("/srv/reports").resolve()

ALLOWED_HOSTS = {
    "api.github.com",
    "objects.githubusercontent.com"
}


# =====================================
# PATH NORMALIZATION
# =====================================

def normalize_path(path):
    """
    Resolve:
    - environment variables
    - ~ expansion
    - ..
    - .
    """

    path = os.path.expandvars(path)
    path = os.path.expanduser(path)

    return Path(path).resolve(strict=False)



# =====================================
# BASE64 DECODER
# =====================================

def decode_base64_parts(text):

    results = []

    candidates = re.findall(
        r"[A-Za-z0-9+/=]{8,}",
        text
    )

    for item in candidates:

        try:

            decoded = base64.b64decode(
                item + "===",
                validate=False
            ).decode(
                "utf-8",
                errors="ignore"
            )

            results.append(decoded)

        except Exception:
            pass


    return results



# =====================================
# SECRET READ DETECTION
# =====================================

def extract_paths(text):

    """
    Find absolute paths in shell commands.
    """

    return re.findall(
        r"(?<![A-Za-z0-9_])(/[^\s\"';&|]+)",
        text
    )



def command_reads_secret(command):

    commands = []


    # Original command

    commands.append(command)


    # Expanded variables

    commands.append(
        os.path.expandvars(command)
    )


    # Expanded ~

    commands.append(
        os.path.expanduser(command)
    )


    # Decode possible encoded commands

    commands.extend(
        decode_base64_parts(command)
    )


    for cmd in commands:


        # Check all paths

        for path in extract_paths(cmd):

            try:

                resolved = normalize_path(path)

                if resolved == SECRET_FILE:

                    return True


            except Exception:

                continue


        # Handle cases where the full secret path appears
        # after expansion

        if "/home/agent/.npmrc" in cmd:

            return True


    return False



def check_bash(command):

    if command_reads_secret(command):

        return {
            "decision": "block",
            "reason": "Reading /home/agent/.npmrc is never permitted by this agent's policy."
        }


    return {
        "decision": "allow",
        "reason": "Command is allowed."
    }



# =====================================
# WRITE POLICY
# =====================================

def check_write(path):

    try:

        target = normalize_path(path)


        # Must not be the directory itself

        if target == WRITE_ROOT:

            return {
                "decision": "block",
                "reason": "Cannot write directly to /srv/reports directory."
            }


        # Must be a child of /srv/reports

        try:

            target.relative_to(
                WRITE_ROOT
            )


        except ValueError:

            return {
                "decision": "block",
                "reason": "Writes are only allowed inside /srv/reports/."
            }


        return {
            "decision": "allow",
            "reason": "Write path is inside allowed directory."
        }


    except Exception:

        return {
            "decision": "block",
            "reason": "Invalid path."
        }



# =====================================
# HTTP POLICY
# =====================================

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
            "reason": "Hostname is approved."
        }


    return {
        "decision": "block",
        "reason": "Hostname is not approved."
    }



# =====================================
# API ENDPOINT
# =====================================

@app.route(
    "/guardrail",
    methods=["POST"]
)
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
            data.get(
                "command",
                ""
            )
        )


    elif tool == "write_file":

        result = check_write(
            data.get(
                "path",
                ""
            )
        )


    elif tool == "http_request":

        result = check_http(
            data.get(
                "url",
                ""
            )
        )


    else:

        result = {
            "decision": "block",
            "reason": "Unknown tool."
        }


    return jsonify(result)



# =====================================
# LOCAL SERVER
# =====================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8000
    )
