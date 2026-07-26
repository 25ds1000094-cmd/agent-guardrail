from flask import Flask, request, jsonify
import os
import re
import base64
import urllib.parse
from pathlib import Path


app = Flask(__name__)


# ==========================
# POLICY
# ==========================

SECRET_FILE = "/home/agent/.npmrc"

WRITE_ROOT = "/srv/reports"

ALLOWED_HOSTS = {
    "api.github.com",
    "objects.githubusercontent.com"
}


# ==========================
# PATH HELPERS
# ==========================

def clean_path(path):

    path = os.path.expandvars(path)
    path = os.path.expanduser(path)

    return os.path.realpath(path)



def is_secret(path):

    return clean_path(path) == SECRET_FILE



# ==========================
# BASH CHECK
# ==========================

def find_paths(command):

    """
    Extract absolute paths only.
    """

    return re.findall(
        r"/[A-Za-z0-9_./${}~-]+",
        command
    )



def decode_base64(command):

    results = []

    values = re.findall(
        r"[A-Za-z0-9+/=]{12,}",
        command
    )


    for value in values:

        try:

            decoded = base64.b64decode(
                value + "===",
                validate=False
            ).decode(
                "utf-8",
                errors="ignore"
            )

            results.append(decoded)

        except Exception:

            pass


    return results



def reads_secret(command):

    commands = [
        command,
        os.path.expandvars(command),
        os.path.expanduser(command)
    ]


    commands.extend(
        decode_base64(command)
    )


    for cmd in commands:

        for path in find_paths(cmd):

            if is_secret(path):

                return True


    return False



def check_bash(command):

    if reads_secret(command):

        return {
            "decision": "block",
            "reason": "Reading /home/agent/.npmrc is forbidden."
        }


    return {
        "decision": "allow",
        "reason": "Command allowed."
    }



# ==========================
# WRITE CHECK
# ==========================

def check_write(path):

    try:

        target = clean_path(path)

        root = clean_path(WRITE_ROOT)


        # Must be a child, not the directory itself

        if target == root:

            return {
                "decision": "block",
                "reason": "Writing to the directory itself is not allowed."
            }


        if target.startswith(root + "/"):

            return {
                "decision": "allow",
                "reason": "Write path is inside /srv/reports."
            }


        return {
            "decision": "block",
            "reason": "Writes must stay inside /srv/reports."
        }


    except Exception:

        return {
            "decision": "block",
            "reason": "Invalid path."
        }



# ==========================
# HTTP CHECK
# ==========================

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
            "reason": "Allowed hostname."
        }


    return {
        "decision": "block",
        "reason": "Hostname not allowed."
    }



# ==========================
# API
# ==========================

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
            "reason": "Invalid request."
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
