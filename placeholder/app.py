import os
import base64
import hashlib
import requests
import secrets
import json

from flask import Flask, render_template, redirect, request, session, url_for
from flask_cors import CORS
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wrappers import Response

from user import User

def load_config(fname='./client_secrets.json'):
    config = None
    with open(fname) as f:
        config = json.load(f)
    return config

config = load_config()

app = Flask(__name__)
app.config.update({
    'SECRET_KEY': secrets.token_hex(64),
    'PREFERRED_URL_SCHEME': 'https' if config['redirect_uri'].startswith('https') else 'http'
})

CORS(app)

app.wsgi_app = DispatcherMiddleware(
    Response('Not Found', status=404),
    {'/placeholder': app.wsgi_app}
)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login")
def login():
    # store app state and code verifier in session
    session['app_state'] = secrets.token_urlsafe(64)
    session['code_verifier'] = secrets.token_urlsafe(64)

    # calculate code challenge
    hashed = hashlib.sha256(session['code_verifier'].encode('ascii')).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    code_challenge = encoded.decode('ascii').strip('=')

    # get request params
    query_params = {'client_id': config["client_id"],
                    #'redirect_uri': "http://localhost:8080/sample/authorization-code/callback",
                    'redirect_uri': config['redirect_uri'],
                    'scope': "openid email profile",
                    'state': session['app_state'],
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256',
                    'response_type': 'code',
                    'response_mode': 'query'}

    # build request_uri
    request_uri = "{base_url}?{query_params}".format(
        base_url=config['org_url'] + "oauth2/default/v1/authorize",
        query_params=requests.compat.urlencode(query_params)
    )

    app.logger.info(f"Redirecting to {request_uri}")

    return redirect(request_uri)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route("/authorization-code/callback")
def callback():
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    code = request.args.get("code")
    app_state = request.args.get("state")
    if app_state != session['app_state']:
        return "The app state does not match"
    if not code:
        return "The code was not returned or is not accessible", 403
    query_params = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': config['redirect_uri'],
        'code_verifier': session['code_verifier'],
    }

    app.logger.info(f"Query params: {query_params}")

    query_params = requests.compat.urlencode(query_params)
    exchange = requests.post(
        config['org_url'] + "oauth2/default/v1/token",
        headers=headers,
        data=query_params,
        auth=(config['client_id'], config['client_secret']),
    ).json()

    app.logger.info(f"Exchange response: {exchange}")

    # Get tokens and validate
    if not exchange.get("token_type"):
        return "Unsupported token type. Should be 'Bearer'.", 403
    access_token = exchange["access_token"]
    id_token = exchange["id_token"]

    # Authorization flow successful, get userinfo and login user
    userinfo_response = requests.get(config['org_url'] + "oauth2/default/v1/userinfo",
                                     headers={'Authorization': f'Bearer {access_token}'}).json()

    unique_id = userinfo_response["sub"]
    user_email = userinfo_response["email"]
    user_name = userinfo_response["given_name"]

    user = User(
        id_=unique_id, name=user_name, email=user_email
    )

    if not User.get(unique_id):
        User.create(unique_id, user_name, user_email)

    login_user(user)

    return redirect(url_for("profile"))


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/health")
def health():
    response = Response("Ok", status=200, mimetype='text/plain')

    return response

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True)
