import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, views
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db
from wtforms import Form, BooleanField, StringField, PasswordField, validators


bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()
        
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        print(g.user)
        if g.user is None:
            return redirect(url_for('admin.login'))

        return view(**kwargs)

    return wrapped_view

def guest_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is not None:
            return redirect(url_for('admin.index'))

        return view(**kwargs)
    return wrapped_view

class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    first_name = StringField('First Name', [validators.Length(min=4, max=25)])
    last_name = StringField('Last Name', [validators.Length(min=4, max=25)])
    email = StringField('Email Address', [validators.Length(min=6, max=35), validators.Email()])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Repeat Password')

    def validate_username(self, field):
        db = get_db()
        user = db.execute(
            "SELECT id FROM user WHERE username = ?", (field.data,)
        ).fetchone()
        if user is not None:
            raise validators.ValidationError('Username is already in use.')

    def validate_email(self, field):
        db = get_db()
        user = db.execute(
            "SELECT id FROM user WHERE email = ?", (field.data,)
        ).fetchone()
        if user is not None:
            raise validators.ValidationError('Email is already in use.')



@bp.route('/register', methods=('GET', 'POST'))
@guest_required
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        db = get_db()
        try:
            db.execute(
                "INSERT INTO user (username, first_name, last_name, email, password) VALUES (?, ?, ?, ?, ?)",
                (form.username.data, form.first_name.data, form.last_name.data, form.email.data, generate_password_hash(form.password.data)),
            )
            db.commit()
        except db.IntegrityError:
            flash(f"User {form.username.data} is already registered.",'danger')
        else:
            return redirect(url_for("admin.login"))

    return render_template('admin/auth/register.html', form=form)

class LoginForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    remember_me = BooleanField('Remember Me', default=False)
    

@bp.route('/login', methods=('GET', 'POST'))
@guest_required
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data
        db = get_db()
        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user['password'], password):
            flash('Incorrect username or password.','danger')
        else:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('admin.index'))

    return render_template('admin/auth/login.html', form=form)

@bp.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('index'))


 
@bp.route('/index')
@login_required
def index():
    return render_template('admin/index.html')