from flask import Flask, redirect, request,url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, PasswordField, StringField, validators
from wtforms.fields.html5 import EmailField
from wtforms.validators import InputRequired, Length, EqualTo
from werkzeug import generate_password_hash,check_password_hash

from flask_login import LoginManager, logout_user,login_user, current_user,UserMixin, login_required

app =Flask(__name__)



app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:12345@localhost/wtf'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.debug = True
db = SQLAlchemy(app)
app.secret_key = "thid"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
class Login(db.Model, UserMixin):
    __tablename__ = "wtforms"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String())
    email = db.Column(db.String(), unique=True)
    password = db.Column(db.String())


@login_manager.user_loader
def load_user(user_id):
    return Login.query.get(int(user_id))

class RegisterForm(Form):
    name = StringField("name", [validators.Length(min=3)])
    email = EmailField("email",[validators.DataRequired(), validators.email()])
    password = PasswordField("password", [validators.DataRequired(), validators.EqualTo("confirm", message="password  do not match")])
    confirm  = PasswordField("confirm password")

class LoginForm(Form):
    email = EmailField("email",[validators.DataRequired(), validators.email()])
    password = PasswordField("password", [validators.DataRequired()])



@app.route('/', methods=['GET', 'POST'])
def home():
    form = RegisterForm(request.form)
    hash_password = generate_password_hash(form.password.data, method='sha256')
    if request.method == "POST" and form.validate():
        data = Login(name = form.name.data, email = form.email.data, password = hash_password)
        if Login.query.filter_by(email = form.email.data).count() == 0:
            db.session.add(data)
            db.session.commit()
            flash('registeration successful', 'success')
            return redirect(url_for('login'))
        else: 
            flash("email already exist ", 'danger')
            return render_template('home.html', form=form)
        
    return render_template('home.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        user = Login.query.filter_by(email = form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                flash('successfully logged in', "success")
                login_user(user)
                return redirect (url_for('dashboard'))
            else: 
                flash('invalid password', "danger")
                return render_template('login.html', form=form)

        else: 
            flash("invalid user", "danger")
            return render_template('login.html', form=form) 
    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", name = current_user.name)

app.route('/login')
@login_required
def logout():

    return redirect(url_for('login'))
if __name__ == "__main__":
    app.run()