from flask import Flask, request, send_file
import os

app = Flask(__name__)
BASE = "/srv/files"


# VULN (CWE-22): the user-supplied name is joined onto BASE with no containment
# check, so "../../etc/passwd" escapes the base directory.
@app.route("/download")
def download():
    name = request.args.get("name")
    return send_file(os.path.join(BASE, name))


# SAFE decoy: resolves the real path and rejects anything outside BASE before
# serving. A correct triager must NOT flag this as a traversal.
@app.route("/safe-download")
def safe_download():
    name = request.args.get("name")
    full = os.path.realpath(os.path.join(BASE, name))
    if not full.startswith(BASE + os.sep):
        return "denied", 403
    return send_file(full)
