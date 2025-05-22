#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import time
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64


class Authenticator:

    _BASE_AUTH_URL = "https://org.xjtu.edu.cn"
    _BASE_AUTH_PLATFORM_URL = _BASE_AUTH_URL + "/openplatform/"
    _API_REDIRECT = _BASE_AUTH_PLATFORM_URL + "oauth/auth/getRedirectUrl"
    _API_CAPTCHA = _BASE_AUTH_PLATFORM_URL + "g/admin/getJcaptchaCode"
    _API_LOGIN = _BASE_AUTH_PLATFORM_URL + "g/admin/login"
    _API_GETIDENTITY = _BASE_AUTH_PLATFORM_URL + "g/admin/getUserIdentity"

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

    _AUTH_HOST = "org.xjtu.edu.cn"

    _PASSWORD_ENCRYPTION_KEY = "0725@pwdorgopenp"
    _PASSWORD_ENCRYPTION_MODE = AES.MODE_ECB

    @staticmethod
    def encrypt_password(password: str) -> str:
        """
        Encrypt password using AES encryption in ECB mode with PKCS7 padding.
        like what xjtu do

        Args:
            password (str): The password to encrypt

        Returns:
            str: The encrypted password
        """
        try:

            # Define the key (same as in JS)
            key = Authenticator._PASSWORD_ENCRYPTION_KEY.encode("utf-8")

            # Create cipher
            cipher = AES.new(key, Authenticator._PASSWORD_ENCRYPTION_MODE)

            # Pad the password and encrypt it
            padded_data = pad(password.encode("utf-8"), AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)

            # Convert to base64 string
            return base64.b64encode(encrypted_data).decode("utf-8")
        except ImportError:
            raise ImportError(
                "Crypto package not found. "
                "Install it with: pip install pycryptodome"
            )
        except Exception as e:
            raise Exception(
                f"An error occurred during password encryption: {str(e)}"
            )

    def _handle_302(self, response):
        # Check if the response is a redirect
        if response.status_code != 302:
            self.logger.error(
                "Failed to get redirect URL, status code: %s",
                response.status_code,
            )
            raise Exception("Failed to get redirect URL")
        self.logger.debug(
            "Successfully retrieved redirect URL: %s", response.url
        )

        # Check if the response contains a redirect URL
        redirect_url = response.headers.get("Location")
        if not redirect_url:
            self.logger.error("Redirect URL is empty")
            raise Exception("Redirect URL is empty")
        self.logger.debug("Redirect URL: %s", redirect_url)

        return redirect_url

    def _check_url_200(self, url: str, host: str) -> dict:
        response = self.session.get(
            url,
            headers={
                **self._COMMON_HEADERS,
                "Host": host,
            },
        )

        if response.status_code != 200:
            self.logger.error(
                "Failed to load URL %s, status code: %s",
                url,
                response.status_code,
            )
            raise Exception(f"Failed to load URL {url}")

        self.logger.debug("Successfully loaded URL %s", url)

        # return set-cookie dict
        cookies = {}
        for cookie in response.cookies:
            cookies[cookie.name] = cookie.value
            self.logger.debug("Cookie: %s = %s", cookie.name, cookie.value)

        return cookies

    def __init__(
        self,
        username: str,
        password: str,
        logger: logging.Logger = None,
        log_path: str = None,
        *_args,
        **kwargs,
    ):
        # initialize instance variables
        self.username = username
        self.password = Authenticator.encrypt_password(password)

        # initialize session
        self.session = requests.Session()
        self.session.cookies = requests.cookies.RequestsCookieJar()

        if logger is not None:
            self.logger = logger
        else:
            # setup logging
            self.logger = logging.getLogger(
                f"{self.__class__.__name__}({username})"
            )
            self.logger.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                "[%(asctime)s %(name)s %(levelname)s]: %(message)s",
                datefmt="%b %d %H:%M:%S"
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

        self.logger.info(
            "Authenticator initialized for user: %s", self.username
        )

    def _fetch_auth_url(self, dest_url: str, dest_host: str) -> str:

        headers = {
            **self._COMMON_HEADERS,
            "Host": dest_host,
        }

        response = self.session.get(
            dest_url, headers=headers, allow_redirects=False
        )
        _redirect_url = self._handle_302(response)

        # return if this _redirect_url is like:
        # "http://org.xjtu.edu.cn/openplatform/oauth/authorize"
        # and have GET parameters: redirect_url, responseType, and scope

        if "openplatform/oauth/authorize" in _redirect_url:
            if (
                "redirectUri" in _redirect_url
                and "responseType" in _redirect_url
                and "scope" in _redirect_url
            ):
                return _redirect_url

        headers = {
            **self._COMMON_HEADERS,
            "Host": dest_host,
        }
        response = self.session.get(
            _redirect_url, headers=headers, allow_redirects=False
        )

        redirect_url = self._handle_302(response)

        # Parse the redirect URL to extract parameters
        # params = {}
        # for param in redirect_url.split("?")[1].split("&"):
        #     key, value = param.split("=")
        #     params[key] = value
        # self.logger.debug("Parsed parameters: %s", params)

        return redirect_url

    def _get_redirect_auth_endpoint(
        self, endpoint: str, host: str = None
    ) -> str:
        if host is None:
            host = self._AUTH_HOST

        response = self.session.get(
            endpoint,
            headers={
                **self._COMMON_HEADERS,
                "Host": host,
            },
            allow_redirects=False,
        )

        # Check if the response is a redirect
        # print(endpoint)
        # print(response.text)
        redirect_url = self._handle_302(response)

        # Check if set-cookie is present
        if "set-cookie" not in response.headers:
            self.logger.error(
                "Set-Cookie header not found in GET %s", endpoint
            )
            raise Exception("Set-Cookie header not found in GET %s" % endpoint)

        return redirect_url

    def _fetch_get_jcaptcha_code(
        self,
        referer:        str,
        captcha_url:    str = None,
        host:           str = None,
    ) -> str:
        # Although it return a captcha code, but it is just for cookies!!!

        if captcha_url is None:
            captcha_url = self._API_CAPTCHA
        if host is None:
            host = self._AUTH_HOST

        cap_headers = {
            **self._COMMON_HEADERS,
            "Host": host,
            "Referer": referer,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # should post data to get captcha code
        response = self.session.post(
            captcha_url,
            headers=cap_headers,
        )

        if response.status_code != 200:
            self.logger.error(
                "Failed to get captcha code, status code: %s",
                response.status_code,
            )
            raise Exception("Failed to get captcha code")

        # check if set-cookie is present
        if "set-cookie" not in response.headers:
            self.logger.error(
                "Set-Cookie header not found in GET %s", captcha_url
            )
            self.logger.debug("Response headers: %s", response.headers)
            self.logger.debug("Response text: %s", response.text)
            raise Exception(
                "Set-Cookie header not found in GET %s" % captcha_url
            )

        return None

    def _post_login(
        self,
        captcha:    str,
        referer:    str,
        login_url:  str = None,
        origin:     str = None,
        host:       str = None,
    ) -> dict:
        if login_url is None:
            login_url = self._API_LOGIN
        if origin is None:
            origin = self._BASE_AUTH_URL
        if host is None:
            host = self._AUTH_HOST

        login_headers = {
            **self._COMMON_HEADERS,
            "Content-Type": "application/json;charset=utf-8",
            "Host": host,
            "Origin": origin,
            "Referer": referer,
        }

        payload = {
            "loginType": 1,
            "username": self.username,
            "pwd": self.password,
            # jcaptchaCode == "" if captcha == None
            "jcaptchaCode": captcha,
        }

        response = self.session.post(
            login_url, json=payload, headers=login_headers
        )

        if response.status_code != 200:
            self.logger.error(
                "Login failed, status code: %s", response.status_code
            )
            raise Exception("Login failed")

        login_data = response.json()

        if login_data["code"] != 0:
            self.logger.error(
                "Login failed, error code: %s", login_data["code"]
            )
            raise Exception(
                "Login failed with error code: %s" % login_data["code"]
            )

        return login_data

    def _get_user_id(
        self,
        member_id:      str,
        referer:        str,
        identity_url:   str = None,
        origin:         str = None,
        host:           str = None,
    ) -> dict:
        if identity_url is None:
            identity_url = self._API_GETIDENTITY
        if origin is None:
            origin = self._BASE_AUTH_URL
        if host is None:
            host = self._AUTH_HOST

        identity_headers = {
            **self._COMMON_HEADERS,
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "Host": host,
            "Origin": origin,
            "Referer": referer,
        }

        identity_payload = {"memberId": member_id}
        response = self.session.post(
            identity_url, data=identity_payload, headers=identity_headers
        )

        if response.status_code != 200:
            self.logger.error(
                "Failed to get user identity, status code: %s",
                response.status_code,
            )
            raise Exception("Failed to get user identity")

        identity_data = response.json()
        self.logger.info("User identity response: %s", identity_data)
        return identity_data

    def _redi_from_oauth(
        self,
        referer:        str,
        redirect_url:   str = _API_REDIRECT,
        host:           str = _AUTH_HOST,
    ) -> str:
        if redirect_url is None:
            redirect_url = self._API_REDIRECT
        if host is None:
            host = self._AUTH_HOST

        ts = int(time.time() * 1000)
        params = {"userType": 1, "personNo": self.username, "_": ts}

        redirect_headers = {
            **self._COMMON_HEADERS,
            "Host": host,
            "Content-Type": "application/json;charset=utf-8",
            "Referer": referer,
        }

        response = self.session.get(
            redirect_url, params=params, headers=redirect_headers
        )

        if response.status_code != 200:
            self.logger.error(
                "Failed to get redirect URL, status code: %s",
                response.status_code,
            )
            raise Exception("Failed to get redirect URL")

        response_data = response.json()
        return_url = response_data["data"]
        return return_url

    def login(self, dest_url: str, dest_host: str = None) -> dict:
        """
        Perform authentication and return cookies dictionary.

        Returns:
            dict: Dictionary containing cookies
        """
        if dest_host is None:
            dest_host = dest_url.split("/")[2]

        self.logger.info("Starting authentication process...")

        # ====== 0. Request dest URL for redirectURL ======
        self.logger.info("[0] Request dest URL for redirectURL...")
        auth_url = self._fetch_auth_url(
            dest_url=dest_url,
            dest_host=dest_host
        )
        self.logger.info("[0] Redirect auth URL: %s", auth_url)

        # ====== 1. Init auth GET to obtain cookies and redirect ======
        self.logger.info(
            "[1] Init auth GET to obtain cookies and redirect..."
        )
        login_page_url = self._get_redirect_auth_endpoint(
            endpoint=auth_url,
            host=self._AUTH_HOST    # removable
        )
        self.logger.info(
            "[1] Successfully retrieved auth redirect URL: %s, and set-cookie",
            login_page_url,
        )

        # ====== 2. GET login page ======
        # (async, and don't process return, just judeg is 200 status code)
        self.logger.info("[2] Loading login page for check...")
        _ = self._check_url_200(
            url=login_page_url,
            host=self._AUTH_HOST    # removable
        )
        self.logger.info("[2] Successfully loaded login page for check")

        # ====== 3. Repeat GET authorize to set cookies ======
        #  (async, and don't process return, just judeg is 200 status code)
        self.logger.info("[3] Re-requesting authorization for check...")
        _ = self._check_url_200(
            url=auth_url,
            host=self._AUTH_HOST    # removable
        )
        self.logger.info(
            "[3] Successfully re-requested authorization for check"
        )

        # ====== 4. GET captcha code with timestamp (avoid 500 errors) ======
        self.logger.info("[4] GET g/admin/getJcaptchaCode for cookies...")
        jcaptcha_code = self._fetch_get_jcaptcha_code(
            referer=login_page_url,
            captcha_url=self._API_CAPTCHA,  # removable
            host=self._AUTH_HOST,           # removable
        )
        self.logger.info(
            "[4] Captcha code retrieved jcaptchaCode %s and set cookie",
            jcaptcha_code,
        )

        # ====== 5. POST login with username, password, and captcha ======
        self.logger.info("[5] Posting login request...")
        login_data = self._post_login(
            captcha=jcaptcha_code,
            referer=login_page_url,
            login_url=self._API_LOGIN,      # removable
            origin=self._BASE_AUTH_URL,     # removable
            host=self._AUTH_HOST,           # removable
        )
        self.logger.info("[5] Login response: %s", login_data)

        # Update cookies according to login response
        token_key = login_data["data"]["tokenKey"]
        member_id = login_data["data"]["orgInfo"]["memberId"]
        self.session.cookies.set("open_Platform_User", str(token_key))
        self.session.cookies.set("memberId", str(member_id))

        # ====== 6. POST getUserIdentity with form data ======
        self.logger.info("[6] Posting getUserIdentity request...")
        identity_data = self._get_user_id(
            member_id=str(member_id),
            referer=login_page_url,
            identity_url=self._API_GETIDENTITY,  # removable
            origin=self._BASE_AUTH_URL,          # removable
            host=self._AUTH_HOST,                # removable
        )
        self.logger.info("[6] User identity response: %s", identity_data)

        # 7. GET redirect URL for final OAuth flow
        self.logger.info("[7] Getting redirect URL for final OAuth flow...")
        after_login_url = self._redi_from_oauth(
            referer=login_page_url,
            redirect_url=self._API_REDIRECT,    # removable
            host=self._AUTH_HOST,               # removable
        )
        self.logger.info(
            "[7] Redirect URL for final OAuth flow: %s", after_login_url
        )

        # 8. Final GET to the redirect URL (our destination)
        self.logger.info("[8] Final GET to the redirect URL...")
        _ = self._check_url_200(
            url=after_login_url,
            host=dest_host
        )
        self.logger.info("[8] Final GET to the redirect URL successful")

        return self.session.cookies


def test_login(cookies: dict):
    """
    Test the authentication by making a request to the destination URL.

    Args:
        cookies (dict): Dictionary containing cookies
    """
    test_url = "http://ehall.xjtu.edu.cn/new/index.html?browser=no"
    response = requests.get(test_url, cookies=cookies)
    if response.status_code == 200:
        print("Authentication successful!")
        print("Response content:\n", response.text)
    else:
        print("Authentication failed!")


if __name__ == "__main__":
    # use rg.lib.xjtu.edu.cn to get login cookies
    # then use the cookies to log into another site

    import sys
    if len(sys.argv) != 3:
        print("Usage: python main.py <username> <password>")
        sys.exit(1)
    username = sys.argv[1]
    password = sys.argv[2]

    dest_url = "http://rg.lib.xjtu.edu.cn:8086"
    dest_host = "rg.lib.xjtu.edu.cn:8086"

    auth = Authenticator(username, password)
    cookies = auth.login(dest_url, dest_host)
    # print("Authentication successful, cookies:\n", cookies)

    test_login(cookies)
