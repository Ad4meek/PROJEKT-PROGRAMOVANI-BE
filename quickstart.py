import os.path
import config
import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import json
import jwt
from flask import Flask, redirect, url_for, session, request, render_template
from flask_cors import CORS
import requests

import mongo

from bson import json_util
from bson.objectid import ObjectId

CLIENT_ID = '5795616728-aubtunb2krroa3khk2b6ph0a0od6mchv.apps.googleusercontent.com'
CLIENT_SECRET = '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'

# The authorization URL and redirect URL must match the ones you specified when you created the OAuth client ID
AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email', 
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid']

import mimetypes
mimetypes.add_type('application/javascript', '.js')
mimetypes.add_type('text/css', '.css')

app = Flask(__name__,
            template_folder='C:\\Users\\pavel.skala\\PROJEKT-PROGRAMOVANI-BE\\www',
            static_folder='C:\\Users\\pavel.skala\\PROJEKT-PROGRAMOVANI-BE\\www\\assets',
            static_url_path='/assets')


cors = CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})
            

def to_dict(credentials):
    """
    Convert a Credentials object to a dictionary.
    The Credentials object is first converted to JSON by the native implementation
    to ensure it is converted correctly and make updates to the oauth2client module
    easier.
    """
    jsonRepr = credentials.to_json()
    dictRepr = json.loads(jsonRepr)
    # print(dictRepr)
    user_data = get_user_data(dictRepr["token"])
    return dictRepr, user_data

def get_user_data(token):
    res = requests.get(f"https://www.googleapis.com/oauth2/v3/userinfo?access_token={token}")
    response = json.loads(res.text)
    return response

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
    session['credentials']  = to_dict(credentials)

    email = session["credentials"][1]["email"]
    if email == "ad4meek@gmail.com":
        return redirect(config.REDIRECT_URL["teacher"])

    return redirect(config.REDIRECT_URL["student"])


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))



@app.route('/topics', methods=['POST'])
def create_topic():
    response = request.json

    name = response.get("name")
    year = response.get("year")
    description = response.get("description")
    type_work = response.get("type")
    subject = response.get("subject")
    topic = {
        "name": name,
        "year": year,
        "descrition": description,
        "type": type_work,
        "subject": subject
    }

    mongo.insert("topics", topic)
    return response

@app.route('/topics', methods=['GET'])
def get_topics():
    topics = mongo.db["topics"].find()
    print(topics)
    parsed = parse_json(topics)
    print(parsed)

    return parsed

@app.route('/topics/<id>', methods=['GET'])
def get_one_topic(id):
    print(id)
    result = mongo.db["topics"].find_one({'_id': ObjectId(id)})

    print(result)
    # topics = mongo.db["topics"].find({},{})
    parsed = parse_json(result)
    print(parsed)

    return parsed


def parse_json(data):
    return json.loads(json_util.dumps(data))
    

if __name__ == '__main__': 
   # oauth2client.__version__
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'

    # session.init_app(app)

    app.debug = True
    app.run()

