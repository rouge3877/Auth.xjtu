import pytest
import os
import logging
from pathlib import Path
from auth_xjtu.authenticator import Authenticator


TESTS_DIR = Path(__file__).parent


def load_list_file(file_name):
    urls = []
    data_file = TESTS_DIR / "data" / file_name
    with open(data_file, "r") as f:
        # # as commnet in the file
        for line in f.readlines():
            if line.startswith("#"):
                continue
            line = line.strip()
            if line:
                urls.append(line)
    return urls


class TestAuthenticator:
    def test_login(self):
        app_urls_list = "entry-point-list.txt" # auto entry finding doesn't implemented
        username = os.getenv("TEST_USERNAME")
        password = os.getenv("TEST_PASSWORD")
        test_logger = logging.getLogger("auth_xjtu.test")
        test_logger.setLevel(logging.WARNING)

        for dest_app_url in load_list_file(app_urls_list):
            auth = Authenticator(username, password, logger=test_logger)
            print(f"\nTesting login for URL: {dest_app_url}")
            ret, error_message = auth.login(dest_app_url)
            if ret == 0:
                print(f"  - Login successful for {dest_app_url}")
            assert ret == 0, f"Login failed for {dest_app_url}: {error_message}"
