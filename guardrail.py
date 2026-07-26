from flask import Flask, request, jsonify
import os
import re
import base64
import urllib.parse
from pathlib import Path


app = Flask(__name__)


# ==================================
# SECURITY POLICY
# ==================================

SECRET_FILE = "/home/agent/.npmrc"

WRITE_DIRECTORY = "/srv/reports"

ALLOWED_HOSTS = {
    "api.github.com",
    "objects.githubusercontent.com"
}


# ==================================
# PATH NORMALIZATION
# ==================================

def normalize_path(path):
    """
    Converts:
    ~/file
    $HOME/file
    ../file

    into a clean absolute path.
    """

    path = os.path.expandvars(path)
    path = os.path.expanduser(path)

    return os.path.abspath(
        os.path.normpath(path)
    )



def is_secret_file(path):

    try:

        return normalize_path(path) == SECRET_FILE

    except Exception:

        return False



# ==================================
# BASH ANALYSIS
# ==================================

def extract_paths(command):
    """
    Extract absolute filesystem paths
    from a shell command.
    """

    matches = re.findall(
        r"(?<![A-Za-z0-9_])(/[^ \t\n\"';|&]+)",
        command
    )

    return matches



def decode_base64_strings(command):
    """
    Find and decode possible base64
    strings inside commands.
    """

    decoded = []


    candidates = re.findall(
        r"[A-Za-z0-9+/=]{8,}",
        command
    )


    for item in candidates:

        try:

            value = base64.b64decode(
                item + "===",
                validate=False
            ).decode(
                "utf-8",
                errors="ignore"
            )


            decoded.append(value)


        except Exception:

            pass


    return decoded



def command_reads_secret(command):

    commands_to_check = []


    # Original command

    commands_to_check.append(
        command
    )


    # Environment expansion

    commands_to_check.append(
        os.path.expandvars(command)
    )


    # Tilde expansion

    commands_to_check.append(
        os.path.expanduser(command)
    )


    # Base64 decoded commands

    commands_to_check.extend(
        decode_base64_strings(command)
    )


    for cmd in commands_to_check:


        # Extract and normalize every path

        for path in extract_paths(cmd):

            if is_secret_file(path):

                return True


        # Handle commands where the full path appears
        # after expansion but extraction misses it

        normalized = normalize_path(cmd)

        if normalized == SECRET_FILE:

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
        "reason": "Command does not violate policy."
    }



# ==================================
# WRITE FILE POLICY
# ==================================

def check_write(path):

    try:

        target = Path(
            normalize_path(path)
        )

        root = Path(
            normalize_path(WRITE_DIRECTORY)
        )


        try:

            target.relative_to(root)


        except ValueError:

            return {
                "decision": "block",
                "reason": "Writes are only allowed inside /srv/reports/."
            }


        return {
            "decision": "allow",
            "reason": "Writing inside /srv/reports is allowed."
        }


    except Exception:

        return {
            "decision": "block",
            "reason": "Invalid path."
        }



# ==================================
# HTTP POLICY
# ==================================

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



# ==================================
# API ENDPOINT
# ==================================

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



# ==================================
# LOCAL SERVER
# ==================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8000
    )
