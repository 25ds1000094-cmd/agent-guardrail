from flask import Flask, request, jsonify
import os
import re
import base64
import urllib.parse
import shlex

app = Flask(__name__)


# =========================
# POLICY
# =========================

SECRET_FILE = "/home/agent/.npmrc"

WRITE_ROOT = "/srv/reports"

ALLOWED_HOSTS = {
    "api.github.com",
    "objects.githubusercontent.com"
}


# =========================
# PATH NORMALIZATION
# =========================

def normalize_path(path):
    """
    Converts:
    ~/file
    $HOME/file
    ../file

    into a real canonical path
    """

    path = os.path.expandvars(path)
    path = os.path.expanduser(path)

    return os.path.realpath(path)



def is_secret_path(path):

    try:
        return normalize_path(path) == SECRET_FILE
    except Exception:
        return False



# =========================
# COMMAND ANALYSIS
# =========================

def extract_paths(text):

    """
    Extract absolute paths from commands.
    """

    return re.findall(
        r"/[A-Za-z0-9_./~${}-]+",
        text
    )



def decode_possible_base64(text):

    """
    Finds and decodes base64 strings.
    """

    decoded = []


    candidates = re.findall(
        r"[A-Za-z0-9+/=]{8,}",
        text
    )


    for item in candidates:

        try:

            value = base64.b64decode(
                item,
                validate=True
            ).decode(
                "utf-8",
                errors="ignore"
            )

            decoded.append(value)


        except Exception:
            pass


    return decoded



def command_reads_secret(command):

    """
    Checks if a bash command tries
    to access .npmrc.
    """

    # Expand variables
    expanded = os.path.expandvars(command)

    # Expand ~
    expanded = os.path.expanduser(expanded)


    # Direct secret string
    if SECRET_FILE in expanded:
        return True


    # Check extracted paths

    for path in extract_paths(expanded):

        if is_secret_path(path):
            return True


    # Check decoded commands

    for decoded in decode_possible_base64(command):

        if command_reads_secret(decoded):
            return True


    return False



# =========================
# TOOL POLICIES
# =========================

def check_bash(command):

    if command_reads_secret(command):

        return {
            "decision": "block",
            "reason": "Reading /home/agent/.npmrc is never permitted by this agent's policy."
        }


    return {
        "decision": "allow",
        "reason": "Command does not violate policy."
    }



def check_write(path):

    real_path = normalize_path(path)


    try:

        common = os.path.commonpath(
            [
                real_path,
                WRITE_ROOT
            ]
        )

    except ValueError:

        return {
            "decision": "block",
            "reason": "Invalid path."
        }


    if common == WRITE_ROOT:

        return {
            "decision": "allow",
            "reason": "Writing inside /srv/reports is allowed."
        }


    return {
        "decision": "block",
        "reason": "Writes are only allowed inside /srv/reports/."
    }



def check_http(url):

    try:

        parsed = urllib.parse.urlparse(url)

        hostname = parsed.hostname


    except Exception:

        return {
            "decision": "block",
            "reason": "Invalid URL."
        }


    if hostname in ALLOWED_HOSTS:

        return {
            "decision": "allow",
            "reason": "Hostname is on the allowlist."
        }


    return {
        "decision": "block",
        "reason": "Hostname is not allowed."
    }



# =========================
# API ENDPOINT
# =========================

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
            "reason": "Invalid JSON request."
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



# =========================
# LOCAL RUN
# =========================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8000
    )
