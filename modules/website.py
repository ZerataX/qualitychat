from flask import Flask, session, redirect, url_for, escape, request, abort, render_template

################################################
# CONSTANTS
################################################

app = Flask(__name__)

# set the secret key.  keep this really secret:
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

################################################
# ROUTES
################################################

@app.route('/')
def index():
    logged_in = False
    if 'username' in session:
        logged_in = True
    return render_template('index.html', logged_in=logged_in)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        app.logger.debug('trying to log in as {}'.format(
            request.form['username']))
        if valid_login(request.form['username'],
                       request.form['password']):
            app.logger.debug('valid login!')
            app.logger.debug('setting session')
            session['username'] = request.form['username']
        app.logger.debug('invalid login!')
        return redirect(url_for('index'))
    return '''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=text name=password>
            <p><input type=submit value=Login>
        </form>
    '''


@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
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


@app.route('/submit', methods=['POST', 'GET'])
def submit():
    if request.method == 'POST':
        app.logger.debug('vote received')
        if not 'username' in session:
            app.logger.debug('not logged in!')
            abort(401)
        if all(req in request.form for req in ('choice', 'user')):
            author = session['username']
            user = request.form['user']
            if author and user:
                app.logger.debug('{} voting on {}'.format(author, user))
                if valid_vote(request.form['choice'],
                              user,
                              author):
                    app.logger.debug('succeded')
                    return render_template('submit.html')
                app.logger.debug('invalid vote!')
        abort(400)
    elif request.method == 'GET':
        return redirect(url_for('index'))

################################################
# FUNCTIONS
################################################
def redirect_url(default='index'):
    return request.args.get('next') or \
        request.referrer or \
        url_for(default)

def valid_login(username, password):
    return True


def valid_vote(vote, user, author):
    if vote in ["bad", "good"]:
        return True
    else:
        return False


def find_user(name, network):
    user = {
        "name": name,
        "id": "idtestmeme"
    }
    return user
