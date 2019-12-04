
from flask import Flask, request, render_template, session
from wtforms import Form, StringField, PasswordField, validators, TextAreaField
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user
import subprocess
import os
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
# Harish Saravanakumar
# hs3209
# Application Security Assignment 2
csrf = CSRFProtect()
app = Flask(__name__)

app.secret_key = os.urandom(50)

login_manager = LoginManager()
login_manager.init_app(app)

csrf.init_app(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spellcheckapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class userCreds(db.Model, UserMixin):
    user_id = db.Column(db.Integer(), unique=True, nullable=False, primary_key=True)
    uname = db.Column(db.String(20), unique=True, nullable=False)
    pword = db.Column(db.String(70), nullable=False)
    twofa = db.Column(db.String(11), nullable=False)
    reg_time = db.Column('register Time', db.DateTime)
    level = db.Column(db.String(100))

    def __repr__(self):
        return f"userCreds('{self.user_id}', '{self.uname}','{self.password}','{self.twofa}', '{self.reg_time}', '{self.level}')"

    def get_id(self):
        return self.user_id

    def get_active(self):
        return True


class userHistory(db.Model):
    login_id = db.Column(db.Integer(), unique=True, nullable=False, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer(), db.ForeignKey("user_creds.user_id"), unique=False)
    uname = db.Column(db.String(20), unique=False, nullable=False)
    userAction = db.Column(db.String(20))
    userLoggedIn = db.Column(db.DateTime)
    userLoggedOut = db.Column(db.DateTime)

    def __repr__(self):
        return f"userHistory('{self.login_id}','{self.user_id}','{self.uname}', '{self.userAction}','{self.userLoggedIn}','{self.userLoggedOut}')"

class userSpellHistory(db.Model):
    queryID = db.Column(db.Integer(),unique=True,nullable=False,primary_key=True,autoincrement=True)
    uname = db.Column(db.String(20), unique=False,nullable=False)
    queryText = db.Column(db.String(20000), unique=False,nullable=False)
    queryResults = db.Column(db.String(20000), unique=False,nullable=False)

    def __repr__(self):
        return f"userSpellHistory('{self.queryID}','{self.uname}','{self.queryText}','{self.queryResults}')"


db.drop_all()
db.create_all()
adminToAdd = userCreds(uname='admin', pword=bcrypt.generate_password_hash('Administrator@1').decode('utf-8'), twofa='12345678901', level='admin')
db.session.add(adminToAdd)
db.session.commit()


class registerForm(Form):
    uname = StringField('Username', [validators.DataRequired(message="Enter Username"), validators.Length(min=5, max=25)])
    pword = PasswordField('Password', [validators.DataRequired(message="Enter Password"), validators.Length(min=6, max=20)])
    twofa = StringField('2FA', [validators.DataRequired(message="Enter a 11 digit phone number"), validators.Length(min=10, max=11, message="Please enter phone number with your area code.")], id='2fa')


class spellForm(Form):
    textbox = TextAreaField('textbox', [validators.DataRequired(message="Enter Words to Check"), validators.Length(max=50000)], id='inputtext')


class userCheckForm(Form):
    textbox = TextAreaField('textbox', [validators.DataRequired(message="Enter User To Check"),validators.Length(max=20)], id='inputtext')


@login_manager.user_loader
def user_loader(user_id):
    return userCreds.query.get(user_id)


@app.route('/', methods=['GET', 'POST'])
def home():
    if session.get('bool_log') and request.method == 'POST' and request.form['button_click'] == 'Logout': # Clicked logout button
        message = 'Logged Out'
        session.pop('bool_log', None)  # log out of session
        userLogOutToAdd = userHistory(userAction='LoggedOut', uname=current_user.uname, userLoggedOut=datetime.now())
        db.session.add(userLogOutToAdd)
        db.session.commit()
        return render_template('home.html', message=message)

    elif session.get('bool_log') and request.method == 'GET':
        message = 'Logged In'
        return render_template('home.html', message=message)
    else:
        message = 'Please Login'
        return render_template('home.html', message=message)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = registerForm(request.form)
    if request.method == 'POST' and form.validate():
        uname = form.uname.data
        pword = form.pword.data
        h_pword = bcrypt.generate_password_hash(pword).decode('utf-8')
        twofa = form.twofa.data
        if userCreds.query.filter_by(uname=('%s' % uname)).first() is None:
            message = "success"
            db.session.add(userCreds(uname=uname, pword=h_pword, twofa=twofa, reg_time=datetime.now(), level='user'))
            db.session.commit()
            return render_template('register.html', form=form, message=message)
        else:
            uname_check = userCreds.query.filter_by(uname=('%s' % uname)).first().uname
            if uname == uname_check:
                message = "failure"
                return render_template('register.html', form=form, message=message)
    else:
        message = ''
        return render_template('register.html', form=form, message=message)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = registerForm(request.form)
    if request.method == 'POST' and form.validate() and not session.get('bool_log'):
        uname = form.uname.data
        pword = form.pword.data
        twofa = form.twofa.data
        userlogin = userCreds.query.filter_by(uname=('%s' % uname)).first()
        if userlogin is None:
            message = 'Incorrect'
            return render_template('login.html', form=form, message=message)
        else:
            if uname == userlogin.uname and bcrypt.check_password_hash(userlogin.pword, pword) and twofa == userlogin.twofa:
                session['bool_log'] = True
                login_user(userlogin)
                message = "success"
                userLoginToAdd = userHistory(userAction='LoggedIn', uname=uname,userLoggedIn=datetime.now())
                db.session.add(userLoginToAdd)
                return render_template('login.html', form=form, message=message)
            else:
                if bcrypt.check_password_hash(userlogin.pword, pword) is False:
                    message = 'Incorrect'
                    return render_template('login.html', form=form, message=message)
                if twofa != userlogin.twofa:
                    message = 'Two-factor failure'
                    return render_template('login.html', form=form, message=message)

    if request.method == 'POST' and form.validate() and session.get('bool_log'):
        message = 'Already logged in'
        return render_template('login.html', form=form, message=message)
    else:
        message = ''
        return render_template('login.html', form=form, message=message)


@app.route('/spell_check', methods=['GET', 'POST'])
def spellcheck():
    form = spellForm(request.form)
    message = ""
    if session.get('bool_log') and request.method == 'GET':
        message = 'inputtext'
        return render_template('spellcheck.html', form=form, message=message)

    if session.get('bool_log') and request.method == 'POST' and request.form['submit_button'] == 'Check':
        data = form.textbox.data
        test_wordlist = open("temp.txt", "w")
        test_wordlist.write(data)
        test_wordlist.close()
        arguments = ("./a.out", "temp.txt", "wordlist.txt")
        try:
            popen = subprocess.Popen(arguments, stdout=subprocess.PIPE)
            popen.wait()
            output = popen.stdout.read()
            output = output.decode().replace("\n", ",")
            popen.terminate()
            userSpellHistoryToAdd = userSpellHistory(uname=current_user.uname, queryText=data, queryResults=output)
            db.session.add(userSpellHistoryToAdd)
            db.session.commit()
            message = "success"
        except subprocess.CalledProcessError as e:
            print("Error:", e)
            message = "failure"
        return render_template('spellcheck_results.html', data=data, misspelled=output)
    if not session.get('bool_log'):
        message = 'Please log in first!'
        return render_template('spellcheck.html', form=form, message=message)
    else:
        message = 'Extraneous Error'
        return render_template('spellcheck.html', form=form, message=message)


@app.route('/history', methods=['GET', 'POST'])
def history():
    form = spellForm(request.form)
    if session.get('bool_log') and request.method == 'POST':
        try:
            userQuery = form.textbox.data
            print(userQuery)
            currentUser = userCreds.query.filter_by(uname=('%s' % current_user.uname)).first()
            if currentUser.level == 'admin':
                try:
                    numqueries = userSpellHistory.query.filter_by(uname=('%s' % userQuery)).order_by(userSpellHistory.queryID.desc()).first()
                    allqueries = userSpellHistory.query.filter_by(uname=('%s' % userQuery)).all()
                    queriesCount = numqueries.queryID
                except AttributeError:
                    queriesCount = 0
                    allqueries = ''
                return render_template('history.html', numqueries=queriesCount, allqueries=allqueries, form=form)
        except AttributeError:
            return render_template('error.html')
    if session.get('bool_log') and request.method =='GET':
        try:
            numqueries = userSpellHistory.query.filter_by(uname=('%s' % current_user.uname)).order_by(userSpellHistory.queryID.desc()).first()
            allqueries = userSpellHistory.query.filter_by(uname=('%s' % current_user.uname)).all()
            queriesCount = numqueries.queryID
        except AttributeError:
            queriesCount = 0
            allqueries = ''
        return render_template('history.html', numqueries=queriesCount,allqueries=allqueries,form=form)
    else:
        return render_template('error.html')


@app.route("/history/<query>")
def queryPage(query):
    if request.method == 'GET':
        try:
            query = query.replace('query','')
            history = userSpellHistory.query.filter_by(queryID=('%s' % query)).first()
            queryID = history.queryID
            uname = history.uname
            submitText = history.queryText
            returnedText = history.queryResults
        except AttributeError:
            return render_template('error.html')
        return render_template('queryIDresults.html', queryID=queryID, uname=uname,submitText=submitText,results=returnedText)


@app.route('/login_history', methods=['GET', 'POST'])
def login_history():
    form = userCheckForm(request.form)
    currentUser = userCreds.query.filter_by(uname=('%s' % current_user.uname)).first()
    if session.get('bool_log') and request.method == 'GET' and currentUser.level == 'admin':
        message = 'Authenticated User'
        return render_template('login_history.html', form=form, message=message)

    if session.get('bool_log') and request.method == 'POST' and request.form['submit_button'] == 'Check User Login History':
        if currentUser.level == 'admin':
            userToQuery = (form.textbox.data)
            queryResults = userHistory.query.filter_by(uname=('%s' % userToQuery)).all()
            return render_template('login_history_results.html', misspelled=queryResults)
    else:
        message = 'Unauthorized: Admin Status Required'
        return render_template('login_history.html', form=form, message=message)


if __name__ == '__main__':
    app.run(debug=True)
