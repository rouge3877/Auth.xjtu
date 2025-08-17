import pytest
import os
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
        username = os.getenv("TEST_USERNAME")
        password = os.getenv("TEST_PASSWORD")

        auth = Authenticator(username, password)
        for dest_app_url in load_list_file("entry-point-list.txt"):
            print(f"Testing login for URL: {dest_app_url}")
            ret, error_message = auth.login(dest_app_url)
            if ret == 0:
                print(f"Login successful for {dest_app_url}")
            else:
                print(f"Login failed for {dest_app_url}: {error_message}")
            assert ret == 0, f"Login failed for {dest_app_url}: {error_message}"
