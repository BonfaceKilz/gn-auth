"""Handle application level errors."""
import traceback

from werkzeug.exceptions import NotFound
from flask import Flask, request, jsonify, current_app, render_template

from gn_auth.auth.errors import AuthorisationError

def add_trace(exc: Exception, errobj: dict) -> dict:
    """Add the traceback to the error handling object."""
    current_app.logger.error("Endpoint: %s\n%s",
                             request.url,
                             traceback.format_exception(exc))
    return {
        **errobj,
        "error-trace": "".join(traceback.format_exception(exc))
    }

def page_not_found(exc):
    """404 handler."""
    current_app.logger.error(f"Page '{request.url}' was not found.", exc_info=True)
    content_type = request.content_type
    if bool(content_type) and content_type.lower() == "application/json":
        return jsonify(add_trace(exc, {
            "error": exc.name,
            "error_description": (f"The page '{request.url}' does not exist on "
                                  "this server.")
        })), exc.code

    return render_template("404.html", page=request.url), exc.code


def handle_general_exception(exc: Exception):
    """Handle generic unhandled exceptions."""
    current_app.logger.error("Error occurred!", exc_info=True)
    content_type = request.content_type
    if bool(content_type) and content_type.lower() == "application/json":
        msg = ("The following exception was raised while attempting to access "
               f"{request.url}: {' '.join(exc.args)}")
        return jsonify(add_trace(exc, {
            "error": type(exc).__name__,
            "error_description": msg
        })), 500

    return render_template("50x.html",
                           page=request.url,
                           error=exc,
                           trace=traceback.format_exception(exc)), 500


def handle_authorisation_error(exc: AuthorisationError):
    """Handle AuthorisationError if not handled anywhere else."""
    current_app.logger.error("Error occurred!", exc_info=True)
    current_app.logger.error(exc)
    return jsonify(add_trace(exc, {
        "error": type(exc).__name__,
        "error_description": " :: ".join(exc.args)
    })), exc.error_code

__error_handlers__ = {
    NotFound: page_not_found,
    Exception: handle_general_exception,
    AuthorisationError: handle_authorisation_error
}
def register_error_handlers(app: Flask):
    """Register ALL defined error handlers"""
    for class_, error_handler in __error_handlers__.items():
        app.register_error_handler(class_, error_handler)
