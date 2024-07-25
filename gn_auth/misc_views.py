"""
Miscellaneous top-level views that have nothing to do with the application's
functionality.
"""
import os
from pathlib import Path

from flask import Blueprint, current_app as app, send_from_directory

misc = Blueprint("misc", __name__)

@misc.route("/version")
def version():
    """Get the application's version information."""
    version_file = Path("VERSION.txt")
    if version_file.exists():
        with open(version_file, encoding="utf-8") as verfl:
            return verfl.read().strip()
    return "0.0.0"


@misc.route("/favicon.ico", methods=["GET"])
def favicon():
    """Return the favicon."""
    return send_from_directory(os.path.join(app.root_path, "static"),
                               "images/CITGLogo.png",
                               mimetype="image/png")
