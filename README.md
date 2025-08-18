# Auth.xjtu

A simple `Python` module for automating authentication with Xi'an Jiaotong University's (XJTU) OpenPlatform OAuth system.

-----

## 🚀 Getting Started

### Prerequisites

  * Python 3.8+
  * pip

### Installation

Install the package from PyPI:

```bash
pip install auth-xjtu
```

Alternatively, you can install it from the source for the latest updates:

```bash
git clone https://github.com/rouge3877/Auth.xjtu.git
cd Auth.xjtu
pip install .
```

-----

## 📚 Usage

Here's a quick example of how to use `auth-xjtu` to log in and access a protected service.

```python
import logging
from auth_xjtu import Authenticator

# --- Configuration ---
# Your XJTU NetID and password
USERNAME = "your_netid"
PASSWORD = "your_password"

# The URL of the application you want to access after authentication
# For example, the library reservation system
DEST_APP_URL = "http://rg.lib.xjtu.edu.cn:8086"

# --- Authentication ---
# Create an authenticator instance
# You can optionally specify a log file path
auth = Authenticator(USERNAME, PASSWORD, log_path="auth.log")

# Attempt to log in
status_code, message = auth.login(DEST_APP_URL)

# --- Verification ---
if status_code == 0:
    print("✅ Login successful!")
    
    # Get the authenticated session object
    session = auth.get_session()
    
    # Now you can use the session to make authenticated requests
    try:
        response = session.get(DEST_APP_URL)
        response.raise_for_status() # Raise an exception for bad status codes
        print(f"\nSuccessfully accessed {DEST_APP_URL}.")
        # print("First 500 characters of the page content:")
        # print(response.text[:500])
    except Exception as e:
        print(f"❌ Failed to access the destination URL after login: {e}")

else:
    print(f"❌ Login failed: {message} (Status Code: {status_code})")

```

------


## ✨ Features

* **Dynamic Token Extraction**: Automatically parses the login page to extract dynamic security tokens (like the `execution` token) that are required for a valid login submission, preventing CSRF-style errors.
* **Standard `requests.Session` Object**: Returns a standard, fully authenticated `requests.Session` object. You can use this session immediately to interact with any XJTU service protected by the central login system, without any extra configuration.
* **Configurable and Extensible**: Allows you to provide your own `requests.Session` or `logging.Logger` objects during initialization for advanced use cases like setting custom headers, proxies, or integrating into a larger application's logging system.
* **Complete OAuth Flow Automation *(TODO)***: Navigates the entire authentication process, starting from a service URL (like the library website) and handling all necessary HTTP redirects to and from the central authentication server.

------

## 🔧 Detail

### Login Status Codes

The `login()` method returns a tuple `(status_code, message)` to provide clear feedback on the process:

| Status Code | Meaning                                                                      |
|:------------|:-----------------------------------------------------------------------------|
| `0`         | **Success**. The session is authenticated.                                   |
| `1`         | **Redirect Failure**. Failed to navigate the initial redirects to the login page. |
| `2`         | **Payload Construction Failure**. Could not extract tokens or encrypt the password. |
| `3`         | **Post-Login Redirect Failure**. The login was submitted, but the final redirect chain failed. |
| `4`         | **Login Submission Failed**. The POST request failed, likely due to incorrect credentials or a server-side change. |


### How `auth-xjtu` Works

The `auth-xjtu` library meticulously mimics the steps a user's web browser would take to log in. 

<details>
<summary><strong>The core logic resides within the `Authenticator.login()` method and can be broken down into the following stages:</strong></summary>


1.  **Entry Point Discovery**: The process begins not at the login page itself, but at the destination application you want to access (e.g., `http://rg.lib.xjtu.edu.cn:8086`). The library first calls `find_entry()` to identify the initial link that kicks off the authentication process.

2.  **Navigate to Authentication Page**: The library uses `follow_redirects()` to navigate the chain of HTTP 302 redirects. This chain typically goes from the application -> OAuth service -> central login page. This function ensures the session collects all necessary intermediate cookies along the way.

3.  **Construct Login Payload**: This is the most critical step, handled by `payload_constructor()`. Once on the actual login page, the library performs several actions to build the data for the POST request:
    * **Get `execution` Token**: It parses the HTML of the login page to find a hidden input field named `execution`. This token is essential for the server to accept the login request.
    * **Fetch Public Key**: It makes a separate request to the `/cas/jwt/publicKey` endpoint to retrieve the server's RSA public key.
    * **Encrypt Password**: The user's plaintext password is then encrypted using this public key with the PKCS1_v1_5 padding scheme. The result is Base64-encoded and prefixed with `__RSA__`.
    * **Generate Fingerprint**: A unique UUID is generated to act as a device fingerprint (`fpVisitorId`).
    * **Assemble Data**: All these pieces—`username`, the encrypted `password`, `execution` token, `fpVisitorId`, and other static form values—are assembled into a URL-encoded payload.

4.  **Submit Credentials & Finalize Session**:
    * The library sends the constructed payload via an HTTP POST request to the login URL.
    * It checks the response to ensure the login was accepted. If the response contains "西安交通大学统一身份认证网关", it indicates a failure (e.g., incorrect username or password).
    * Upon a successful POST, the server responds with another series of redirects. The library once again calls `follow_redirects()` to navigate back to the original destination application. During this final step, the session is granted the authentication cookies that prove you are logged in.

5.  **Return Authenticated Session**: The `Authenticator` object now holds a `requests.Session` with valid authentication cookies. You can retrieve it using `auth.get_session()` and use it to make further requests to protected XJTU services.

</details>



### The Session as a State Machine: The True Nature of `login()`

The key to understanding this library is to view the `Authenticator` not merely as a tool that returns authentication details (like cookies), but as a **state manager for a `requests.Session` object**.

<details>
<summary><strong>The primary role of the `login()` method is to drive this `Session` object through a critical state transition.:</strong></summary>


#### The State Transition Process

During a call to the `login()` method, a `Session` object transitions through the following states:

1.  **Initial State (Anonymous)**
    * When you instantiate an `Authenticator`, it either creates a new `requests.Session` or uses one you provide.
    * At this stage, the `Session` is effectively a blank slate. It contains generic browser headers (like `User-Agent`), but its cookie jar is empty of any site-specific authentication cookies.
    * In this state, any attempt to access a protected resource will be redirected to the login page.

2.  **Transition Process (Authenticating)**
    * When you invoke `auth.login(dest_app_url)`, the state transition begins.
    * The `Authenticator` uses this single `Session` object to perform a sequence of HTTP requests:
        * It accesses the target application, gets redirected, and automatically collects temporary cookies.
        * It follows redirects to the central authentication gateway, acquiring essential cookies like `JSESSIONID` and the `execution` token required for the login form.
        * It submits the encrypted credentials via a `POST` request.
    * With each step in this sequence, the `Session`'s state (primarily its cookies) is progressively updated by the server.

3.  **Final State (Authenticated)**
    * Upon a successful `POST` request, the server responds with one or more critical authentication tokens (e.g., `CASTGC` - the CAS "Golden Ticket") via `Set-Cookie` headers.
    * The `requests.Session` object automatically captures and stores these cookies in its cookie jar.
    * At this point, the state transition is complete. The `Session` object now contains all the necessary credentials to prove its identity.
    * This "authenticated" `Session` can now be used to freely access any protected resource within the XJTU ecosystem, just like a logged-in browser.

#### What This Architecture Provides Users

* **Encapsulation of Complexity**: Users are completely abstracted away from the complexities of cookie management. You don't need to manually parse, store, or attach cookies to subsequent requests. Simply call `login()` and use the stateful `Session` object returned by `auth.get_session()`.
* **Flexibility & Control (Dependency Injection)**: The `Authenticator` constructor accepts an optional `Session` object. This powerful mechanism allows you to pre-configure the `Session` object with custom settings before authentication, such as:
    * Setting proxies (`session.proxies = ...`)
    * Configuring SSL certificate verification (`session.verify = ...`)
    * Adding custom global headers (`session.headers.update(...)`)
* **Interoperability**: Since the result is a standard `requests.Session` object, it can be seamlessly integrated with any other Python code or library that utilizes `requests`.

</details>


-----

## 🗺️ TODO

Welcome contributions\! Here are some areas we're looking to improve:

  - [ ] Fully automate the discovery of the login entry point. (`find_entry.py`)
  - [ ] Add comprehensive unit and integration tests.

Feel free to open an issue or submit a pull request\!

-----

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This is an independent project and is **not affiliated with, authorized, or endorsed by Xi'an Jiaotong University**. It is intended for educational and research purposes only. The authors assume no liability for any misuse of this software. Use at your own risk.
