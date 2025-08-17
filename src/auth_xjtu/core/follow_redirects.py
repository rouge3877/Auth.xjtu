"""
Redirect handler module for following HTTP redirects.
"""

import requests
from typing import Tuple, Optional


def follow_redirects(
    session: requests.Session, start_url: str
) -> Tuple[str, Optional[requests.Session]]:
    """
    Follow all 302 redirects from a starting URL until reaching a final page with status code 200.

    Args:
        start_url (str): The initial URL provided by the user.
        session (requests.Session): The session object that must be passed in.

    Returns:
        str: the final URL if Optional[requests.Session] != None, error message otherwise.
        Optional[requests.Session]: session after process successfully, None otherwise.
    """
    try:
        # allow_redirects=True is the default behavior of requests,
        # it automatically handles redirects
        response = session.get(start_url, allow_redirects=True, timeout=10)

        # Print redirect history
        # if response.history:
        #     print("[*] Redirect flow detected:")
        #     for resp in response.history:
        #         print(f"    {resp.status_code} -> {resp.url}")

        # Check the status code of the final page
        if response.status_code == 200:
            return response.url, session
        else:
            error_reason = (
                f"[!] Error: Final page status code is {response.status_code}, not 200."
            )
            return error_reason, None

    except requests.exceptions.RequestException as e:
        error_reason = f"[!] Error: Network request failed: {e}"
        return error_reason, None


if __name__ == "__main__":
    """Main function for testing the redirect handler."""
    start_url = input("Please enter the initial URL: ")

    # Create session object
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        }
    )

    final_redi_url, session = follow_redirects(session, start_url)
    if session:
        print(f"[*] Final URL: {final_redi_url}")
    else:
        print(f"[*] Error: {final_redi_url}")
