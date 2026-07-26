from flask import Flask, request, jsonify
import os
import re
import base64
import urllib.parse
import shlex

app = Flask(__name__)


# =====================================================
# POLICY CONFIGURATION
# =====================================================

SECRET_FILE = "/home/agent/.npmrc"

WRITE_ROOT = "/srv/reports"

ALLOWED_HOSTS = {
    "api.github.com",
    "objects.githubusercontent.com"
}


# =====================================================
# PATH NORMALIZATION
# =====================================================

def normalize_path(path):
    """
    Convert a user supplied path into a canonical path.

    Handles:
    - $HOME
    - ~
    - .
    - ..
    """

    path = os.path.expandvars(path)
    path = os.path.expanduser(path)

    return os.path.realpath(path)



def is_secret(path):
    try:
        return normalize_path(path) == SECRET_FILE
    except Exception:
        return False



# =====================================================
# BASH SECURITY CHECKS
# =====================================================

def extract_paths(text):
    """
    Extract filesystem paths from commands.
    """

    return re.findall(
        r"(?<![\w])(/[^\s\"';&|]+)",
        text
    )



def decode_base64(text):
    """
    Detect base64 wrapped shell commands.
    """

    decoded = []

    candidates = re.findall(
        r"[A-Za-z0-9+/]{8,}={0,2}",
        text
    )

    for value in candidates:

        try:

            result = base64.b64decode(
                value
            ).decode(
                "utf-8",
                errors="ignore"
            )

            decoded.append(result)

        except Exception:
            pass


    return decoded



def build_command_variants(command):
    """
    Generate possible versions of a command.
    """

    variants = []


    # Original

    variants.append(command)


    # Environment expansion

    variants.append(
        os.path.expandvars(command)
    )


    # Tilde expansion

    variants.append(
        os.path.expanduser(command)
    )


    # Base64 decoded versions

    variants.extend(
        decode_base64(command)
    )


    return variants



def command_reads_secret(command):

    for variant in build_command_variants(command):


        # Check extracted paths

        for path in extract_paths(variant):

            if is_secret(path):
                return True


        # Handle direct expanded string cases

        if SECRET_FILE in variant:

            return True


        # Handle shell-built paths

        compact = (
            variant
            .replace(" ", "")
            .replace("\\", "")
        )


        if "/home/agent/.npmrc" in compact:

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
        "reason": "Command allowed."
    }



# =====================================================
# WRITE POLICY
# =====================================================

def check_write(path):

    try:

        target = normalize_path(path)

        root = normalize_path(WRITE_ROOT)


        # Must be below /srv/reports

        if target == root:

            return {
                "decision": "block",
                "reason": "Writing to the directory itself is not allowed."
            }


        if target.startswith(root + os.sep):

            return {
                "decision": "allow",
                "reason": "Write path is inside /srv/reports."
            }


        return {
            "decision": "block",
            "reason": "Writes are only allowed inside /srv/reports/."
        }


    except Exception:

        return {
            "decision": "block",
            "reason": "Invalid path."
        }



# =====================================================
# HTTP POLICY
# =====================================================

def check_http(url):

    try:

        parsed = urllib.parse.urlparse(url)

        hostname = parsed.hostname


    except Exception:

        hostname = None


    if hostname in ALLOWED_HOSTS:

        return {
            "decision": "allow",
            "reason": "Hostname is allowed."
        }


    return {
        "decision": "block",
        "reason": "Hostname is not allowed."
    }



# =====================================================
# MAIN ENDPOINT
# =====================================================

@app.route("/guardrail", methods=["POST"])
def guardrail():

    data = request.get_json(
        silent=True
    )


    if not isinstance(data, dict):

        return jsonify({
            "decision": "block",
            "reason": "Invalid request."
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



if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8000
    )
