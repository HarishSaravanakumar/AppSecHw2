
from flask import Flask, request, render_template, session
from wtforms import Form, StringField, PasswordField, validators, TextAreaField
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
import subprocess
import os
from flask_sqlalchemy import SQLAlchemy
csrf = CSRFProtect()
app = Flask(__name__)

app.secret_key = os.urandom(50)

login_manager = LoginManager()
login_manager.init_app(app)

csrf.init_app(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class userCreds(db.Model):
    uname = db.Column(db.String(20), unique=True, primary_key=True, nullable=False)
    pword = db.Column(db.String(50), nullable=False)
    twofa = db.Column(db.String(11), nullable=False)

    def __repr__(self):
        return f"userCreds('{self.username}','{self.password}','{self.twoFactor}')"


# class loginHistory(db.Model):
#     uid = db.Column(db.Integer(), unique=False, primary_key=True, nullable=False)
#     username = db.Column(db.String(20), unique=True, nullable=False)
#     loginTimes = db.Column(db.DateTime)
#     logoutTimes = db.Column(db.DateTime)
#
#     def __repr__(self):
#         return f"loginHistory('{self.username}','{self.loginTimes}','{self.logoutTimes}')"

db.drop_all()
db.create_all()


# Define Forms
class registerForm(Form):
    uname = StringField('Username', [validators.DataRequired(message="Enter Username"), validators.Length(min=6, max=20)])
    pword = PasswordField('Password', [validators.DataRequired(message="Enter Password"), validators.Length(min=6, max=20)])
    twofa = StringField('2FA', [validators.DataRequired(message="Enter a 11 digit phone number"), validators.Length(min=11, max=11, message="Please enter phone number with your area code.")], id='2fa')


class spellForm(Form):
    textbox = TextAreaField('textbox', [validators.DataRequired(message="Enter Words to Check"), validators.Length(max=50000)], id='inputtext')


@app.route('/', methods=['GET', 'POST'])
def home():
    if session.get('bool_log') and request.method == 'POST' and request.form['button_click'] == 'Logout': # Clicked logout button
        message = 'Logged Out'
        session.pop('bool_log', None)  # log out of session
        return render_template('home.html', message=message)

    elif session.get('bool_log') and request.method == 'GET':
        message = 'Logged In'
        return render_template('home.html', message=message)
    else:
        message = 'Please Login'
        return render_template('home.html', message=message)

# Form for register
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
            db.session.add(userCreds(uname=uname, pword=h_pword, twofa=twofa))
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

# Form for login
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
                message = "success"
                return render_template('login.html', form=form, message=message)
            else:
                if pword != userlogin.pword:
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

# Text Submission && Result Retrieval 
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
            message = "success"
        except subprocess.CalledProcessError as e:
            print("Error :", e)
            message = "failure"
        return render_template('spellcheck_results.html', data=data, misspelled=output)
    if not session.get('bool_log'):
        message = 'Please log in first!'
        return render_template('spellcheck.html', form=form, message=message)
    else:
        message = 'Extraneous Error'
        return render_template('spellcheck.html', form=form, message=message)


if __name__ == '__main__':
    app.run(debug=True)