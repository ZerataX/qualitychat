from flask import Flask, session, redirect, url_for, escape, request, abort, render_template
import datetime
import dateutil.parser
import requests
import urllib.parse
################################################
# CONSTANTS
################################################

# FLASK

app = Flask(__name__)

# set the secret key.  keep this really secret:
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

DOMAIN = 'http://localhost:5000'

# DISCORD

D_API_ENDPOINT = 'https://discordapp.com/api/v6'
D_CLIENT_ID = '396853967390375957'
D_CLIENT_SECRET = '9j0pa4vaogHpmCV7LztwIHuT-AJCnCTd'
D_BOT_TOKEN = 'Mzk2ODUzOTY3MzkwMzc1OTU3.DXcfZQ.jN12okZlkzjCt16sWGEzmVsc_cg'
D_CDN_URI = 'https://cdn.discordapp.com'


################################################
# ROUTES
################################################

@app.route('/')
def index():
    logged_in = False
    if 'username' in session:
        logged_in = True
    return render_template('index.html', logged_in=logged_in)
    username = False
    avatar = False
    if logged_in():
        if session['type'] == 'discord':
            user_data = discord_user(session['access_token'])
            avatar = '%s/avatars/%s/%s.png' % (D_CDN_URI,
                                               user_data['id'],
                                               user_data['avatar'])
            username = user_data['username']
    return render_template('index.html',
                           username=username,
                           avatar=avatar)


@app.route('/login')
def login():
    return render_template('login.html',
                           logged_in=logged_in(),
                           D_CLIENT_ID=D_CLIENT_ID,
                           REDIRECT_URI=urllib.parse.quote(DOMAIN + "/login/discord"))


@app.route('/login/discord')
def discord_login():
    code = request.args.get('code')
    if code:
        resp = exchange_code(code)
        user_data = discord_user(resp['access_token'])

        now = datetime.datetime.now()
        expires = now + datetime.timedelta(seconds=(resp['expires_in'] - 3600))        

        session['id'] = user_data['id']
        session['type'] = 'discord'
        session['access_token'] = resp['access_token']
        session['refresh_token'] = resp['refresh_token']
        session['expires'] = expires.isoformat()

        return redirect(url_for('index'))
    abort(400)


@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.clear()
    return redirect(url_for('index'))


@app.route('/vote/')
@app.route('/vote/<network>/<name>')
def vote(network=None, name=None):
    if 'username' in session:
        author = session['username']
        user = find_user(name, network)
        return render_template('vote.html',
                               username=user["name"],
                               user_id=user["id"],
                               author=author)
    else:
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
    abort(400)

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

def valid_login(username, password):
    return True


def valid_vote(vote, user, author):
    if vote in ["bad", "good"]:
        return True
    else:
        return False


def find_user(name, network):
    if network == "discord":
        user_data = discord_user(D_BOT_TOKEN, token_type="Bot", user=name)
        user = {
            "name": user_data['username'],
            "id": user_data['id']
        }
    else:
        user = {
            "name": name,
            "id": "idtestmeme"
        }
    return user

################################################
# Discord oauth
################################################


def exchange_code(code):
    data = {
        'D_CLIENT_ID': D_CLIENT_ID,
        'D_CLIENT_SECRET': D_CLIENT_SECRET,
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
        'D_CLIENT_ID': D_CLIENT_ID,
        'D_CLIENT_SECRET': D_CLIENT_SECRET,
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
