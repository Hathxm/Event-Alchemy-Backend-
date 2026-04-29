"""
One-time script to obtain a Gmail API refresh token.

Run this from the project root with the venv activated:
    python scripts/get_gmail_refresh_token.py

It will open a browser, ask you to log in to your Gmail, and print a
refresh token. Copy the printed token into your .env as GMAIL_REFRESH_TOKEN.
"""
from decouple import config
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

CLIENT_CONFIG = {
    "installed": {
        "client_id": config('GMAIL_CLIENT_ID'),
        "client_secret": config('GMAIL_CLIENT_SECRET'),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["http://localhost"],
    }
}


def main():
    flow = InstalledAppFlow.from_client_config(CLIENT_CONFIG, SCOPES)
    creds = flow.run_local_server(
        port=0,
        access_type='offline',
        prompt='consent',
    )
    print("\n=== COPY THIS REFRESH TOKEN INTO YOUR .env ===\n")
    print(f"GMAIL_REFRESH_TOKEN={creds.refresh_token}")
    print("\n==============================================\n")


if __name__ == '__main__':
    main()
