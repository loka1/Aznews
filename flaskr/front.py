import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('front', __name__, url_prefix='/')

@bp.route('/')
def index():
    return render_template('front/index.html')


@bp.route('/contact', methods=('GET', 'POST'))
def contact():
   return render_template('front/contact.html')