import logging
import os
import json
import stat
import argparse

import pydantic
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


# --- CLI argument parsing (single parser, parsed once) ---

_parser = argparse.ArgumentParser()
_parser.add_argument(
    "--gauth-file", type=str, default="./.gauth.json",
    help="Path to Google OAuth client secrets file",
)
_parser.add_argument(
    "--accounts-file", type=str, default="./.accounts.json",
    help="Path to accounts configuration file",
)
_parser.add_argument(
    "--credentials-dir", type=str, default=".",
    help="Directory to store OAuth2 credential files",
)
_cli_args, _ = _parser.parse_known_args()

CLIENTSECRETS_LOCATION = _cli_args.gauth_file
REDIRECT_URI = 'http://localhost:4100/code'

# Principle of least privilege — gmail.modify covers read + label + archive
# + trash + send. No need for the nuclear https://mail.google.com/ scope.
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
]


# --- Account model ---

class AccountInfo(pydantic.BaseModel):
    email: str
    account_type: str
    extra_info: str = ""
    alias: str = ""

    def to_description(self):
        if self.alias:
            return f'Account "{self.alias}" ({self.email}) — {self.account_type}'
        return f"Account {self.email} — {self.account_type}"


# --- Account registry ---

_accounts_cache: list[AccountInfo] | None = None


def get_account_info() -> list[AccountInfo]:
    """Load and cache the accounts list from disk."""
    global _accounts_cache
    if _accounts_cache is not None:
        return _accounts_cache
    with open(_cli_args.accounts_file) as f:
        data = json.load(f)
        _accounts_cache = [AccountInfo.model_validate(acc) for acc in data.get("accounts", [])]
    return _accounts_cache


def resolve_user_id(user_id: str) -> str:
    """Resolve an alias or email to the canonical email address.

    Raises ValueError if the user_id doesn't match any configured account,
    preventing credential filename injection attacks.
    """
    accounts = get_account_info()
    # Check alias first
    for account in accounts:
        if account.alias and account.alias.lower() == user_id.lower():
            return account.email
    # Check email
    for account in accounts:
        if account.email.lower() == user_id.lower():
            return account.email
    # No match — refuse to proceed
    known = [a.alias or a.email for a in accounts]
    raise ValueError(
        f"Unknown account: '{user_id}'. "
        f"Configured accounts: {', '.join(known)}"
    )


# --- Credential storage ---

def _get_credential_filename(user_id: str) -> str:
    """Build the credential file path. user_id must already be validated."""
    return os.path.join(_cli_args.credentials_dir, f".oauth2.{user_id}.json")


def get_stored_credentials(user_id: str) -> Credentials | None:
    """Load stored OAuth2 credentials for a user. Returns None if not found."""
    cred_file_path = _get_credential_filename(user_id=user_id)
    if not os.path.exists(cred_file_path):
        logging.info(f"No stored credentials for {user_id}")
        return None

    try:
        with open(cred_file_path, 'r') as f:
            cred_data = json.load(f)

        creds = Credentials(
            token=cred_data.get("token"),
            refresh_token=cred_data.get("refresh_token"),
            token_uri=cred_data.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=cred_data.get("client_id"),
            client_secret=cred_data.get("client_secret"),
            scopes=cred_data.get("scopes", SCOPES),
        )
        return creds
    except Exception as e:
        logging.error(f"Failed to load credentials for {user_id}: {e}")
        return None


def store_credentials(credentials: Credentials, user_id: str):
    """Store OAuth2 credentials to disk with restrictive file permissions (0600)."""
    cred_file_path = _get_credential_filename(user_id=user_id)
    parent_dir = os.path.dirname(cred_file_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    cred_data = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": list(credentials.scopes) if credentials.scopes else SCOPES,
    }

    # Write with 0600 permissions — owner read/write only
    fd = os.open(cred_file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(cred_data, f, indent=2)
    except Exception:
        os.close(fd)
        raise

    # Enforce permissions even if file existed with different perms
    os.chmod(cred_file_path, stat.S_IRUSR | stat.S_IWUSR)


# --- OAuth flow ---

def get_authorization_url(user_id: str) -> str:
    """Build the OAuth authorization URL for a user."""
    flow = InstalledAppFlow.from_client_secrets_file(
        CLIENTSECRETS_LOCATION, scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    auth_url, _ = flow.authorization_url(
        access_type='offline',
        prompt='consent',
        login_hint=user_id,
    )
    return auth_url


def run_oauth_flow(user_id: str) -> Credentials:
    """Run the full OAuth2 authorization flow for a user.

    Opens a browser, waits for the callback on localhost:4100, exchanges
    the code, stores credentials, and returns them.
    """
    flow = InstalledAppFlow.from_client_secrets_file(
        CLIENTSECRETS_LOCATION, scopes=SCOPES,
    )
    creds = flow.run_local_server(
        port=4100,
        prompt='consent',
        access_type='offline',
        login_hint=user_id,
    )
    # Verify the authenticated user matches the expected account
    user_info = get_user_info(creds)
    authenticated_email = user_info.get('email', '')
    if authenticated_email.lower() != user_id.lower():
        logging.warning(
            f"Authenticated as {authenticated_email} but expected {user_id}. "
            f"Storing credentials under authenticated email."
        )
    store_credentials(creds, user_id=authenticated_email)
    return creds


def refresh_credentials(credentials: Credentials) -> Credentials:
    """Refresh expired credentials. Returns refreshed credentials."""
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
    return credentials


def get_user_info(credentials: Credentials) -> dict:
    """Retrieve basic user info (email, id) from the authenticated account."""
    service = build('oauth2', 'v2', credentials=credentials)
    user_info = service.userinfo().get().execute()
    if not user_info or not user_info.get('id'):
        raise RuntimeError("Failed to retrieve user info from Google")
    return user_info
