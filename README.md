# Auth.xjtu


## Introduction
`auth-xjtu` is a `Python` package for authentication at XJTU that automates the authentication process against Xi'an Jiaotong University’s (XJTU) OpenPlatform OAuth system. It handles the complete login flow, including AES‑encrypted password submission, CAPTCHA cookie retrieval, and redirect management, returning a valid session cookie jar ready for further HTTP requests.

## Installation

Install via pip:

```bash
pip install auth-xjtu
```

Or install from source:

```bash
git clone https://github.com/rouge3877/Auth.xjtu.git
cd Auth.xjtu
pip install .
```

## Usage

```python
from auth_xjtu import Authenticator

username = "your_xjtu_id"
password = "your_plain_password"
dest_app_url = "http://rg.lib.xjtu.edu.cn:8086" # for example

# Create an authenticator instance
auth = Authenticator(username, password)

ret, message = auth.login(dest_app_url)

if ret == 0:
    print("==============Login successful!==============")
    session_for_login = auth.get_session()
    print("Content in %s:\n%s", dest_app_url, session_for_login.get(dest_app_url).text)
else:
    print("Login failed:", message)

```

## Logging
The package uses Python's built-in `logging` module for logging. You can configure the logging level and handlers as needed. By default, it logs to the console with a level of `INFO`, and logs to a file (**which you should specify**) with a level of `DEBUG`. You can change the logging configuration in the `Authenticator` class.


```python
import logging
from auth_xjtu import Authenticator

...
auth = Authenticator(username, password, log_path="your_log_file.log")
# or the following if you don't want to use the default log file
#
# your_logger = logging.getLogger("auth_xjtu")
# your_logger.setLevel(logging.DEBUG)  # Set to DEBUG or INFO as needed
# auth = Authenticator(username, password, logger=your_logger)
cookies = auth.login(dest_url, dest_host)
...

```

## Detail

### Login process
Authenticate the user and navigate to the destination application.

This login method performs a multi-step authentication process:
1. Identifies the entry point URL for the destination application.
2. Follows redirects to reach the authentication page.
3. Constructs the necessary payload for authentication using the provided credentials.
4. Submits the payload and follows redirects to complete the login process.

`dest_app_url (str)`: The URL of the destination application requiring authentication.

`Tuple[int, str]`: A tuple containing:
- `int`: Status code indicating the result of the authentication process:
    - 0: Success.
    - 1: Failure to retrieve the authentication page.
    - 2: Failure to construct the authentication payload.
    - 3: Failure during the login process after submitting the payload.
- `str`: An error message describing the failure, or an empty string on success.

## TODO
- [ ]: Automate entry point discovery (`src/auth_xjtu/core/find_entry.py`)
- [ ]: More tests

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


## Disclaimer
This project is inspired by the need for a simple and effective way to authenticate against XJTU's OpenPlatform OAuth system. This project is **not affiliated with or endorsed by Xi'an Jiaotong University**. It is intended for educational and research purposes only. Use at your own risk.
