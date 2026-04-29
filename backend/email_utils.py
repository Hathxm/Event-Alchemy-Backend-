import base64
from email.message import EmailMessage

from decouple import config
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.send']


def _get_gmail_service():
    creds = Credentials(
        token=None,
        refresh_token=config('GMAIL_REFRESH_TOKEN'),
        client_id=config('GMAIL_CLIENT_ID'),
        client_secret=config('GMAIL_CLIENT_SECRET'),
        token_uri='https://oauth2.googleapis.com/token',
        scopes=GMAIL_SCOPES,
    )
    creds.refresh(Request())
    return build('gmail', 'v1', credentials=creds, cache_discovery=False)


def send_email(subject, to, html=None, text=None, from_email=None):
    service = _get_gmail_service()

    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = from_email or config('GMAIL_FROM_EMAIL')
    message['To'] = ', '.join(to) if isinstance(to, list) else to

    if html:
        message.set_content(text or '')
        message.add_alternative(html, subtype='html')
    else:
        message.set_content(text or '')

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return service.users().messages().send(
        userId='me',
        body={'raw': raw},
    ).execute()
