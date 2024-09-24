import os.path
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# If modifying these SCOPES, delete the token.json file
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_service():
    """Get Gmail API service."""
    creds = None
    # The file token.json stores the user's access and refresh tokens
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    # If there are no valid credentials, ask the user to log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)  # Open a web server for authentication
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    service = build('gmail', 'v1', credentials=creds)
    return service

def read_latest_email(service):
    """Read the latest email from the user's inbox."""
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=1).execute()
    messages = results.get('messages', [])
    
    if not messages:
        print('No new messages.')
    else:
        # Get the message details
        msg_id = messages[0]['id']
        msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        msg_data = msg['payload']['headers']
        
        # Extract headers like 'From', 'Subject', 'Date'
        for header in msg_data:
            if header['name'] == 'From':
                print(f"From: {header['value']}")
            if header['name'] == 'Subject':
                print(f"Subject: {header['value']}")
            if header['name'] == 'Date':
                print(f"Date: {header['value']}")
        
        # Extract and print the email body (if available)
        if 'parts' in msg['payload']:
            for part in msg['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    print(f"Body: {part['body']['data']}")
        else:
            # Fallback if there's no parts (e.g., plain text email)
            if msg['payload']['mimeType'] == 'text/plain':
                print(f"Body: {msg['payload']['body']['data']}")

if __name__ == '__main__':
    service = get_service()
    read_latest_email(service)