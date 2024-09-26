"""Some common utils for requests to the resources endpoints."""
from functools import reduce

from pymonad.either import Left, Right, Either

def check_form(form, *fields) -> Either:
    """Check form for errors"""
    def __check_field__(errors, field):
        if not bool(form.get(field)):
            return errors + (f"Missing `{field}` value.",)
        return errors

    errors: tuple[str, ...] = reduce(__check_field__, fields, tuple())
    if len(errors) > 0:
        return Left({
            "error": "Invalid request data!",
            "error_description": "\n\t - ".join(errors)
        })

    return Right(form)
