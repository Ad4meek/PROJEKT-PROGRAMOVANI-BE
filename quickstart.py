import os.path
import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import json
import jwt
from flask import Flask, redirect, url_for, session, request, render_template

CLIENT_ID = '5795616728-aubtunb2krroa3khk2b6ph0a0od6mchv.apps.googleusercontent.com'
CLIENT_SECRET = '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'

# The authorization URL and redirect URL must match the ones you specified when you created the OAuth client ID
AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
SCOPES = ['openid', 
    'https://www.googleapis.com/auth/userinfo.email', 
    'https://www.googleapis.com/auth/userinfo.profile']

import mimetypes
mimetypes.add_type('application/javascript', '.js')
mimetypes.add_type('text/css', '.css')

app = Flask(__name__,
            template_folder='C:\\Users\\pavel.skala\\PROJEKT-PROGRAMOVANI-BE\\www',
            static_folder='C:\\Users\\pavel.skala\\PROJEKT-PROGRAMOVANI-BE\\www\\assets',
            static_url_path='/assets')

            

def to_dict(credentials):
    """
    Convert a Credentials object to a dictionary.
    The Credentials object is first converted to JSON by the native implementation
    to ensure it is converted correctly and make updates to the oauth2client module
    easier.
    """
    jsonRepr = credentials.to_json()
    dictRepr = json.loads(jsonRepr)
    print(dictRepr)
    return dictRepr


@app.route('/')
def index():
    if 'credentials' in session.keys():
        return render_template('index.html')
    else:
        return redirect(url_for('login'))


@app.route('/login')
def login():
    # Create the OAuth flow object
    flow = InstalledAppFlow.from_client_secrets_file(
        "credentials.json", scopes=SCOPES)
    flow.redirect_uri = url_for('callback', _external=True)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='select_account')

    # Save the state so we can verify the request later
    session['state'] = state

    return redirect(authorization_url)

@app.route('/callback')
def callback():
    # Verify the request state
    if request.args.get('state') != session['state']:
        raise Exception('Invalid state')

    # Create the OAuth flow object
    flow = InstalledAppFlow.from_client_secrets_file(
        "credentials.json", scopes=SCOPES, state=session['state'])
    flow.redirect_uri = url_for('callback', _external=True)

    # Exchange the authorization code for an access token
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Save the credentials to the session
    credentials = flow.credentials
    session['credentials'] = to_dict(credentials)

    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

    

if __name__ == '__main__': 
   # oauth2client.__version__
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'

    # session.init_app(app)

    app.debug = True
    app.run()

