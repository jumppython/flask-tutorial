import functools

from flask import (
    Blueprint, flask, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db

# This creates a Blueprint named 'auth'. Like the application object, the blueprint needs to know where it's defined, so __name__ is passed as the second argument. The url_prefix will be prepended to all the URLs associated with the blueprint.
bp = Blueprint('auth', __name__, url_prefix='/auth')

# @bp.route: associates the URL /register with the register view function. When Flask receives a request to /auth/register, it will call the register view and use the return value as the response.
@bp.route('/register', methods=('GET', 'POST'))
def register():
    # If the user submitted the form, request.method will be 'POST'. In this case, start validating the input.
    if request.method == 'POST':
        # request.form: This is a special type of dict mapping submitted form keys and values. The user will input their username and password.
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        # Validate that username and password are not empty.
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        # Validate that username is not already registered by querying the database and checking if a result is returned. db.excute takes a SQL query with ? placeholders for any user input, and a tuple of values to replace the placeholders with. The database library will take care of escaping the values so you are not vulnerable to a SQL injection attack.
        # fetchone(): returns one row from the query. If the query returned no results, it returns None. Similarity, fetchall() returns a list of all results.
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)

        # If validation succeeds, insert the new user data into the database. For security, passwords should never be stored in the database directly. Instead, generate_password_hash() is used to securely hash the password, and that hash os stored. Since this query modifies data, db.commit() needs to be called afterwards to save the changes.
        if error is None:
            db.execute(
                'INSERT INTO user (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            db.commit()
            # After storing the user, they are redirected to the login page. url_for() generates the URL for the login view based on its name. This is preferable to writing the URL directly as it allows you to change the URL later without changing all code that links to it. redirect() generates a redirect responce to the generated URL.
            return redirect(url_for('auth.login'))

        # If validate fails, the error is shown to the user. flash() stores messages that can be retrieved when rendering the template.
        flash(error)

    # When the user initially navigates to auth/register, or there was an validation error, an HTML page with the registration form should be shown. render_template() will render a template containing the HTML, which you'll write in the next step of the tutorial.
    return render_template('auth/register.html')



