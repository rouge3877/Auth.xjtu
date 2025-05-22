# Auth.xjtu


## Introduction
`auth-xjtu` is a `Python` package for authentication at XJTU that automates the authentication process against Xi'an Jiaotong University’s (XJTU) OpenPlatform OAuth system. It handles the complete login flow, including AES‑encrypted password submission, CAPTCHA cookie retrieval, and redirect management, returning a valid session cookie jar ready for further HTTP requests.

Features:

* **AES Password Encryption**: Replicates XJTU’s client‑side AES encryption with PKCS7 padding.
* **Cookie Management**: Automatically captures and maintains all necessary cookies across intermediate redirects.
* **Redirect Handling**: Intercepts HTTP 302 responses instead of following redirects, extracting `Location` headers for custom flows.
* **Logging**: Built‑in logging with configurable console and file handlers, using standard `logging` module.
* **Simple Interface**: Single `Authenticator` class with a `login` method that returns a `requests` cookie jar.

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
dest_url = "http://rg.lib.xjtu.edu.cn:8086" # for example
dest_host = "rg.lib.xjtu.edu.cn:8086"       # for example

# Create an authenticator instance
auth = Authenticator(username, password)

# Perform login and retrieve cookies
cookies = auth.login(dest_url, dest_host)

# Use the cookies in subsequent requests
# for test, can diff with the dest_url above
import requests
response = requests.get(
    "http://ehall.xjtu.edu.cn/new/index.html?browser=no",
    cookies=cookies
)
if response.status_code == 200:
    print("Authenticated successfully!")
else:
    print("Authentication failed.")
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


## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


## Disclaimer
This project is inspired by the need for a simple and effective way to authenticate against XJTU's OpenPlatform OAuth system. This project is **not affiliated with or endorsed by Xi'an Jiaotong University**. It is intended for educational and research purposes only. Use at your own risk.
