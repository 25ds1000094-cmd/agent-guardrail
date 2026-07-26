from flask import Flask, request, jsonify
import os
import re
import base64
import urllib.parse
import subprocess

app = Flask(__name__)


# ==========================
# POLICY
# ==========================

SECRET = "/home/agent/.npmrc"

WRITE_ROOT = "/srv/reports"

ALLOWED_HOSTS = {
    "api.github.com",
    "objects.githubusercontent.com"
}


# ==========================
# PATH FUNCTIONS
# ==========================

def canonical(path):

    """
    Resolve:
    - ~
    - $HOME
    - ..
    - .
    """

    path = os.path.expandvars(path)
    path = os.path.expanduser(path)

    return os.path.normpath(
        os.path.abspath(path)
    )



def forbidden_file(path):

    try:
        return canonical(path) == SECRET

    except Exception:
        return False



# ==========================
# BASH ANALYSIS
# ==========================

def expand_command(command):

    result = command

    # Environment variables
    result = os.path.expandvars(result)

    # Home expansion
    result = result.replace(
        "~",
        "/home/agent"
    )

    return result



def decode_base64(command):

    outputs = []


    # look for base64-ish strings

    parts = re.findall(
        r"[A-Za-z0-9+/=]{12,}",
        command
    )


    for part in parts:

        try:

            decoded = base64.b64decode(
                part + "===",
                validate=False
            ).decode(
                "utf-8",
                errors="ignore"
            )


            outputs.append(decoded)


        except Exception:
            pass


    return outputs



def extract_absolute_paths(command):

    return re.findall(
        r"(\/[^\s'\"|;&]+)",
        command
    )



def reads_secret(command):

    """
    Detect attempts to read .npmrc.
    """


    commands = [
        command
    ]


    # add expanded version

    commands.append(
        expand_command(command)
    )


    # add decoded versions

    commands.extend(
        decode_base64(command)
    )


    for cmd in commands:


        # direct check

        if SECRET in cmd:
            return True


        # path normalization check

        for path in extract_absolute_paths(cmd):

            if forbidden_file(path):
                return True


        # shell variable reconstruction attempts

        joined = cmd.replace(
            " ",
            ""
        )


        if (
            "home/agent/.npmrc" in joined
            or
            "home/agent/.npmrc" in joined.replace(
                "\\",
                ""
            )
        ):
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
# WRITE POLICY
# ==========================

def check_write(path):

    real = canonical(path)


    root = canonical(
        WRITE_ROOT
    )


    # Must be inside directory,
    # not just have same prefix

    if (
        real.startswith(
            root + os.sep
        )
    ):

        return {
            "decision": "allow",
            "reason": "Path is inside allowed write directory."
        }


    return {
        "decision": "block",
        "reason": "Writes outside /srv/reports are forbidden."
    }



# ==========================
# HTTP POLICY
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

    data = request.get_json()


    if not isinstance(data, dict):

        return jsonify({
            "decision": "block",
            "reason": "Invalid request."
        })


    tool = data.get(
        "tool"
    )


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
