from flask import Flask, session, redirect, url_for, escape, request, abort, render_template
import base64
import datetime
import dateutil.parser
import os
import requests
import sys
import urllib.parse
import yaml


################################################
# CONSTANTS
################################################


settings = None
try:
    with open('../settings.yaml', 'r') as stream:
        settings = yaml.load(stream)
except IOError as e:
    sys.exit("no settings.yaml found!")

# FLASK

app = Flask(__name__)

app.secret_key = settings['SECRET']

DOMAIN = settings['DOMAIN']
NETWORKS = settings['NETWORKS']

# DISCORD

D_API_ENDPOINT = settings['DISCORD']['API_ENDPOINT']
D_CLIENT_ID = settings['DISCORD']['CLIENT_ID']
D_CLIENT_SECRET = settings['DISCORD']['CLIENT_SECRET']
D_BOT_TOKEN = settings['DISCORD']['BOT_TOKEN']
D_CDN_URI = settings['DISCORD']['CDN_URI']


################################################
# ROUTES
################################################


@app.route('/')
def index():
    user_nick = False
    avatar = False
    if logged_in():
        if session['type'] == 'discord':
            user_data = discord_user(session['access_token'])
            avatar = '%s/avatars/%s/%s.png' % (D_CDN_URI,
                                               user_data['id'],
                                               user_data['avatar'])
            user_nick = user_data['username']
    return render_template('index.html',
                           user_nick=user_nick,
                           avatar=avatar,
                           users=get_users())


@app.route('/login')
def login():
    state = os.urandom(24)
    session['state'] = state
    state = urllib.parse.quote(base64.encodestring(state).decode("utf-8"))
    redirect_uri = urllib.parse.quote(DOMAIN + "/login/discord")

    discord = False
    if 'DISCORD' in NETWORKS:
        discord = True
    return render_template('login.html',
                           logged_in=logged_in(),
                           D_CLIENT_ID=D_CLIENT_ID,
                           redirect_uri=redirect_uri,
                           state=state,
                           discord=discord)


@app.route('/login/discord')
def discord_login():
    code = request.args.get('code')
    state = request.args.get('state')
    if code and state:
        state = base64.b64decode(urllib.parse.unquote(state))
        if not state == session['state']:
            app.logger.warning('state could not be validated!')
            abort(401)
        try:
            resp = exchange_code(code)
        except requests.exceptions.RequestException as e:
            app.logger.debug('could not log in with discord!')
            app.logger.debug(e)
            abort(401)

        user_data = discord_user(resp['access_token'])
        user_id = find_user(user_data['id'], 'discord')['id']

        if not in_server(user_id):
            app.logger.debug('not part of server!')
            abort(401)

        now = datetime.datetime.now()
        expires = now + datetime.timedelta(seconds=resp['expires_in'])

        session['id'] = user_id
        session['type'] = 'discord'
        session['access_token'] = resp['access_token']
        session['refresh_token'] = resp['refresh_token']
        session['expires'] = expires.isoformat()

        if 'return' in session:
            url = session['return']
            session.pop('return')
            return redirect(url)
        return redirect(url_for('index'))
    abort(400)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/vote/')
@app.route('/vote/<network>/<name>')
def vote(network=None, name=None):
    if logged_in():
        user = find_user(name, network)
        if user:
            return render_template('vote.html',
                                   user_nick=user["nick"],
                                   user_id=user["id"],
                                   avatar=user["avatar"])
        abort(404)
    else:
        session['return'] = request.url
        return redirect(url_for('login'))


@app.route('/submit', methods=['POST'])
def submit():
    app.logger.debug('validating vote...')
    if not logged_in():
        app.logger.debug('not logged in!')
        abort(401)
    if all(req in request.form for req in ('choice', 'user')):
        author = session['id']
        user = request.form['user']
        choice = request.form['choice']
        if author and user:
            app.logger.debug('{} voting on {}'.format(author, user))
            if valid_vote(choice, user, author):
                app.logger.debug('succeded!')
                return render_template('submit.html')
            app.logger.debug('invalid vote!')
    return redirect(redirect_url())


################################################
# FUNCTIONS
################################################


def redirect_url(default='index'):
    return request.args.get('next') or \
        request.referrer or \
        url_for(default)


def logged_in():
    if 'expires' in session:
        expires = dateutil.parser.parse(session['expires'])
        now = datetime.datetime.now()
        if now < expires:
            return True
    return False


def valid_vote(vote, user, author):
    if vote in ["bad", "good"]:
        return True
    else:
        return False


################################################
# discord oauth
################################################


def exchange_code(code):
    data = {
        'client_id': D_CLIENT_ID,
        'client_secret': D_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DOMAIN + "/login/discord"
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    r = requests.post('%s/oauth2/token' % D_API_ENDPOINT, data, headers)
    r.raise_for_status()
    return r.json()


def refresh_token(refresh_token):
    data = {
        'client_id': D_CLIENT_ID,
        'client_secret': D_CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'redirect_uri': DOMAIN + "/login/discord"
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    r = requests.post('%s/oauth2/token' % D_API_ENDPOINT, data, headers)
    r.raise_for_status()
    return r.json()


def discord_user(token, token_type="Bearer", user="@me"):
    headers = {
        'Authorization': '%s %s' % (token_type, token)
    }
    r = requests.get('%s/users/%s' % (D_API_ENDPOINT, user), headers=headers)
    r.raise_for_status()
    return r.json()


################################################
# user info
################################################


def get_users():
    bigby = {
        "nick": "KingAmbrose",
        "name": "187272038027755520",
        "id": "187272038027755520",
        "network": "discord"
    }
    zeratax = {
        "nick": "Videotapes",
        "name": "336219606081601537",
        "id": "336219606081601537",
        "network": "discord"
    }
    peterspark = {
        "name": "PetersPark",
        "nick": "PetersPark",
        "id": "234543643534534234",
        "network": "irc"
    }
    users = [zeratax, bigby, peterspark]
    return users


def in_server(user_id):
    for user in get_users():
        if user_id == user['id']:
            return True
    return False


def find_user(name, network):
    if network == "discord":
        user_data = discord_user(D_BOT_TOKEN, token_type="Bot", user=name)
        avatar = '%s/avatars/%s/%s.png' % (D_CDN_URI,
                                           user_data['id'],
                                           user_data['avatar'])
        user = {
            "nick": user_data['username'],
            "name": user_data['id'],
            "id": user_data['id'],
            "avatar": avatar
        }
    else:
        user = {
            "nick": name,
            "name": name,
            "id": "idtestmeme",
            "avatar": False
        }
    return user
