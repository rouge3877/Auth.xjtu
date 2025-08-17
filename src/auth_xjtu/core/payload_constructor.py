"""
Module for constructing login payloads for XJTU authentication system.

This module constructs properly formatted login payloads by
    extracting necessary tokens
    encrypting passwords with RSA public keys
    assembling all required form fields for authentication requests
"""

import base64
import uuid
import requests
from urllib.parse import urlencode, urljoin
from bs4 import BeautifulSoup
from typing import Tuple, Optional
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


def _get_execution_token(
    session: requests.Session, auth_page: requests.Response
) -> Tuple[str, Optional[requests.Session]]:
    """
    Extract the 'execution' token from the authentication page.

    Args:
        session (requests.Session): The current session object.
        auth_page (requests.Response): The response object of the authentication page.

    Returns:
        Tuple[str, Optional[requests.Session]]: A tuple containing the 'execution' token and the session object.
    """
    try:
        soup = BeautifulSoup(auth_page.text, "html.parser")
        execution_input = soup.find("input", {"name": "execution"})
        if not execution_input or "value" not in execution_input.attrs:
            error_str = "Error: Could not find 'execution' token in page."
            return error_str, None

        execution = execution_input["value"]
        return execution, session
    except Exception as e:
        error_str = f"Error: Failed to extract 'execution' token. {e}"
        return error_str, None


def _get_public_key(
    session: requests.Session, public_key_url: str
) -> Tuple[str, Optional[requests.Session]]:
    """
    Fetch the RSA public key from the server.

    Args:
        session (requests.Session): The current session object.
        public_key_url (str): The URL to fetch the public key from.

    Returns:
        Tuple[str, Optional[requests.Session]]: A tuple containing the public key and the session object.
    """
    try:
        pk_response = session.get(public_key_url)
        pk_response.raise_for_status()
        public_key_str = pk_response.text
        return public_key_str, session
    except requests.RequestException as e:
        error_str = f"Error: Failed to fetch public key from {public_key_url}. {e}"
        return error_str, None


def _encrypt_password(
    session: requests.Session, public_key: str, password: str
) -> Tuple[str, Optional[requests.Session]]:
    """
    Encrypt the password using the provided RSA public key.

    Args:
        session (requests.Session): The current session object. (Useless here, just for consistency)
        public_key (str): The RSA public key as a string.
        password (str): The raw password to encrypt.

    Returns:
        Tuple[str, Optional[requests.Session]]: A tuple containing the encrypted password and the session object.
    """
    try:
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_v1_5.new(rsa_key)
        encrypted_bytes = cipher.encrypt(password.encode("utf-8"))
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode("utf-8")
        encrypted_password = f"__RSA__{encrypted_b64}"
        return encrypted_password, session
    except Exception as e:
        error_str = f"Error: Failed to encrypt password. {e}"
        return error_str, None


def _generate_fingerprint(
    session: requests.Session,
) -> Tuple[str, Optional[requests.Session]]:
    """
    Generate a simulated device fingerprint.

    Args:
        session (requests.Session): The current session object.

    Returns:
        Tuple[str, Optional[requests.Session]]: A tuple containing the fingerprint and the session object.
    """
    try:
        fp_visitor_id = uuid.uuid4().hex
        return fp_visitor_id, session
    except Exception as e:
        error_str = f"Error: Failed to generate fingerprint. {e}"
        return error_str, None


def payload_constructor(
    session: requests.Session,
    auth_page: requests.Response,
    username: str,
    password: str,
) -> Tuple[str, Optional[requests.Session]]:
    """
    Construct POST payload using established session and final login page response.

    Args:
        session (requests.Session): Session object with cookies from module one.
        auth_page (requests.Response): Final login page response from module one.
        username (str): Raw username.
        password (str): Raw password.

    Returns:
        str: URL-encoded payload string if Optional[requests.Session] != None, error message otherwise.
        Optional[requests.Session]: session after process successfully, None otherwise.
    """

    _public_key_url = urljoin(auth_page.url, "/cas/jwt/publicKey")

    execution, session = _get_execution_token(session, auth_page)
    if not session:
        return execution, None

    _public_key, session = _get_public_key(session, _public_key_url)
    if not session:
        return _public_key, None

    encrypted_password, session = _encrypt_password(session, _public_key, password)
    if not session:
        return encrypted_password, None

    fp_visitor_id, session = _generate_fingerprint(session)
    if not session:
        return fp_visitor_id, None

    payload_string = urlencode(
        {
            "username": username,
            "password": encrypted_password,
            "captcha": "",
            "currentMenu": "1",
            "failN": "0",
            "mfaState": "",
            "execution": execution,
            "_eventId": "submit",
            "geolocation": "",
            "fpVisitorId": fp_visitor_id,
            "trustAgent": "",
            "submit1": "Login1",
        }
    )

    return payload_string, session
