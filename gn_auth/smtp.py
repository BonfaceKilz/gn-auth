"""Handle sending emails. Uses Python3's `smtplib`."""
import logging
import smtplib
import mimetypes
from typing import Optional
from email.message import EmailMessage
from email.headerregistry import Address


def __read_mime__(filepath) -> dict:
    """Read mimetype for attachments"""
    _mime,_extras = mimetypes.guess_type(filepath)
    if bool(_mime):
        return dict(zip(("maintype", "subtype"),
                        _mime.split("/")))# type: ignore[union-attr]
    return {}


def build_email_message(# pylint: disable=[too-many-arguments]
        from_address: str,
        to_addresses: tuple[Address, ...],
        subject: str,
        txtmessage: str,
        htmlmessage: str = "",
        attachments: tuple[str, ...] = tuple()
) -> EmailMessage:
    """Build an email message."""
    msg = EmailMessage()
    msg["From"] = Address(display_name="GeneNetwork Automated Emails",
                          addr_spec=from_address)
    msg["To"] = to_addresses
    msg["Subject"] = subject
    msg.set_content(txtmessage)
    if bool(htmlmessage):
        msg.add_alternative(htmlmessage, subtype="html")
    for _path in attachments:
        with open(_path, "rb") as _file:
            msg.add_attachment(_file.read(), **__read_mime__(_path))

    return msg


def send_message(# pylint: disable=[too-many-arguments]
        smtp_user: str,
        smtp_passwd: str,
        message: EmailMessage,
        host: str = "",
        port: int = 587,
        local_hostname: Optional[str]=None,
        timeout: int = 200,
        source_address: Optional[tuple[tuple[str, int], ...]] = None
):
    """Set up a connection to a SMTP server and send a message."""
    logging.debug("Email to send:\n******\n%s\n******\n", message.as_string())
    with smtplib.SMTP(host, port, local_hostname, timeout, source_address) as conn:
        conn.ehlo()
        conn.send_message(message)
