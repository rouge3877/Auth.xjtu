#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import logging
from Crypto.Util.Padding import pad
from typing import Tuple
from auth_xjtu.core.follow_redirects import follow_redirects
from auth_xjtu.core.payload_constructor import payload_constructor
from auth_xjtu.core.find_entry import find_entry


class Authenticator:

    _COMMON_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "sec-ch-ua": (
            '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"'
        ),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
    }

    def __init__(
        self,
        username: str,
        password: str,
        session: requests.Session = None,
        logger: logging.Logger = None,
        log_path: str = None,
        *_args,
        **kwargs,
    ):
        # initialize instance variables
        self.username = username
        self.password = password

        # initialize session
        if session is None:
            self.session = requests.Session()
            self.session.cookies = requests.cookies.RequestsCookieJar()
            self.session.headers.update(self._COMMON_HEADERS)
        else:
            self.session = session
            # self.session.headers.update(self._COMMON_HEADERS)

        if logger is not None:
            self.logger = logger
        else:
            # setup logging
            self.logger = logging.getLogger(f"{self.__class__.__name__}({username})")
            self.logger.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                "[%(asctime)s %(name)s %(levelname)s]: %(message)s",
                datefmt="%b %d %H:%M:%S",
            )

            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

            if log_path is not None:
                logfile_handler = logging.FileHandler(log_path)
                logfile_handler.setLevel(logging.DEBUG)
                logfile_handler.setFormatter(formatter)
                self.logger.addHandler(logfile_handler)

        self.logger.info("Authenticator initialized for user: %s", self.username)

    def login(self, dest_app_url: str) -> Tuple[int, str]:
        """
        Perform authentication and return process status.

        Args:
            dest_app_url (str): The destination application URL.

        Returns:
            int: The status code indicating the result of the process, should be 0 on success.
            str: An optional error message, empty if successful.
        """
        self.logger.info("Starting authentication process...")

        auth_url = ""

        # 0. app(without auth) -> entry point
        entry_point_url = find_entry(dest_app_url)

        # 1. entry point -> auth point
        ret_url, ret_session = follow_redirects(self.session, entry_point_url)
        if ret_session:
            self.logger.info("Authentication page redirected to: %s", ret_url)
            self.session = ret_session
            auth_url = ret_url
        else:
            error_message = (
                f"Failed to retrieve authentication page, because: {ret_url}"
            )
            self.logger.error(error_message)
            return 1, error_message

        # 2. construct payload @ auth point
        auth_response = self.session.get(auth_url, timeout=10)
        ret_payload, ret_session = payload_constructor(
            session=self.session,
            auth_page=auth_response,
            username=self.username,
            password=self.password,
        )
        if ret_session:
            self.logger.info("Payload constructed successfully.")
            self.session = ret_session
        else:
            error_message = f"Failed to construct payload, because: {ret_payload}"
            self.logger.error(error_message)
            return 2, error_message

        # 3. auth point -> app(auth)
        login_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        self.session.headers.update(login_headers)
        login_response = self.session.post(auth_url, data=ret_payload)
        ret_url, ret_session = follow_redirects(self.session, login_response.url)
        if ret_session:
            self.logger.info("Login successful!")
            self.session = ret_session
        else:
            error_message = f"After post payload, login failed, because: {ret_url}"
            self.logger.error(error_message)
            return 3, error_message

        return 0, ""

    def get_session(self) -> requests.Session:
        return self.session


if __name__ == "__main__":

    import sys

    if len(sys.argv) != 3:
        print("Usage: python main.py <username> <password>")
        sys.exit(1)
    username = sys.argv[1]
    password = sys.argv[2]

    dest_app_url = "http://rg.lib.xjtu.edu.cn:8086"

    auth = Authenticator(username, password)
    ret, _ = auth.login(dest_app_url)

    if ret == 0:
        print("==============Login successful!==============")
        session_for_login = auth.get_session()
        print("Content in %s:\n%s", dest_app_url, session_for_login.get(dest_app_url).text)
