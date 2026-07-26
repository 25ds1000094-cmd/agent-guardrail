from flask import Flask, request, jsonify
import os
import re
import base64
import urllib.parse

app = Flask(__name__)


SECRET_FILE = "/home/agent/.npmrc"

ALLOWED_WRITE_DIR = "/srv/reports"

ALLOWED_HOSTS = {
    "api.github.com",
    "objects.githubusercontent.com"
}


def normalize_path(path):
    path = os.path.expandvars(path)
    path = os.path.expanduser(path)
    return os.path.realpath(path)



def contains_secret(text):

    expanded = os.path.expandvars(text)
    expanded = os.path.expanduser(expanded)

    normalized = normalize_path(expanded)

    return (
        SECRET_FILE in expanded
        or SECRET_FILE == normalized
        or SECRET_FILE in normalized
    )



def check_bash(command):

    if contains_secret(command):
        return {
            "decision": "block",
            "reason": "Reading /home/agent/.npmrc is never permitted by this agent's policy."
        }


    # Detect base64 wrapped commands
    matches = re.findall(
        r"[A-Za-z0-9+/=]{20,}",
        command
    )

    for item in matches:
        try:
            decoded = base64.b64decode(
                item
            ).decode(
                "utf-8",
                errors="ignore"
            )

            if contains_secret(decoded):
                return {
                    "decision": "block",
                    "reason": "Encoded command attempts to access protected secret file."
                }

        except Exception:
            pass


    return {
        "decision": "allow",
        "reason": "Command does not violate policy."
    }



def check_write(path):

    real_path = normalize_path(path)

    if (
        real_path == ALLOWED_WRITE_DIR
        or real_path.startswith(ALLOWED_WRITE_DIR + "/")
    ):
        return {
            "decision": "allow",
            "reason": "Writing inside /srv/reports is allowed."
        }


    return {
        "decision": "block",
        "reason": "Writes are only allowed inside /srv/reports/."
    }



def check_http(url):

    hostname = urllib.parse.urlparse(url).hostname

    if hostname in ALLOWED_HOSTS:
        return {
            "decision": "allow",
            "reason": "Hostname is on the allowlist."
        }


    return {
        "decision": "block",
        "reason": "Hostname is not allowed."
    }



@app.route("/guardrail", methods=["POST"])
def guardrail():

    data = request.get_json()

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
