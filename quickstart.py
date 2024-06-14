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
from flask import Flask, redirect, url_for, session, request, render_template, jsonify, make_response
from flask_cors import CORS
import requests
from datetime import timedelta

import mongo

from bson import json_util
from bson.objectid import ObjectId

import ast

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

app = Flask(__name__)



cors = CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}}, supports_credentials=True)


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

@app.route('/setcookie', methods = ['POST', 'GET'])
def setCookie():
    email = json.dumps(session["credentials"][1]["name"])
    print(email)
    response = make_response() # We can also render new page with render_template
    response.set_cookie(key="user_info", value=email, secure=True, httponly=True, samesite="None")
    return response

@app.route('/')
def index():
    if 'credentials' in session.keys():
        return render_template('index.html')
    else:
        return redirect(url_for('login'))


@app.route('/login')
def login():
    session.permanent = True
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
    user_email = email
    print(user_email)

    response_data = {
        "message": "succesfull",
        "data": {

        }
    }


    
    # resp.set_cookie('session_token', user_info_str, secure=True, httponly=True, samesite="None")
    print(request.cookies.get("name"))
    

    if email == "pavelskalamobil@gmail.com":
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
        "description": description,
        "type": type_work,
        "subject": subject,
        "status": False,
        "student": None
    }

    mongo.insert("topics", topic)
    return response

@app.route('/topics', methods=['GET'])
def get_topics():
    topics = mongo.db["topics"].find()

    parsed = parse_json(topics)

    return parsed

@app.route('/topics/<id>', methods=['GET'])
def get_one_topic(id):
    # print(id)
    result = mongo.db["topics"].find_one({'_id': ObjectId(id)})

    # print(result)
    parsed = parse_json(result)
    # print(parsed)

    return parsed

@app.route('/topics/<id>', methods=['DELETE'])
def delete_topic(id):
    print(id)

    result = mongo.db["topics"].delete_one({"_id": ObjectId(id)})

    response_data = {
        "message": "asdfasdas",
        "data": {

        }
    }

    response = make_response(jsonify(response_data), 200)

    return response

@app.route('/topics/<id>', methods=['PUT'])
def update_topic(id):
    print(id)
    
    response = request.json

    updated_keys = response.keys()

    newValues = {"$set": {} }
    for key in updated_keys:
        newValues["$set"][key] = response.get(key)

    mongo.db["topics"].update_one({'_id': ObjectId(id)}, newValues)

    return response

@app.route('/choose', methods=['POST'])
def choose_topic():
    response = request.json

    user_info = request.cookies.get("user_info")
    
    print(user_info)
    email = ast.literal_eval(str(user_info))

    newValues = { "$set": { "status": True, "student": email } }
    print(newValues)

    mongo.db["topics"].update_one({'_id': ObjectId(response)}, newValues)

    return response


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

