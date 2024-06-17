"""Utilities to deal with requests."""
from flask import request

def request_json() -> dict:
    """Retrieve the JSON sent in a request."""
    return request.json or {}
