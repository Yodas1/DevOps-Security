from flask import Flask, request, redirect, make_response
import sqlite3
# import urllib     # REMOVED: no longer needed
import quoter_templates as templates

# Run using `poetry install && poetry run flask run --reload`
app = Flask(__name__)
app.static_folder = '.'

# ADDED: secure session cookie defaults (protects Flask's own session cookie)
# In production, ensure the app is serverd via HTTPS
app.config.update(
    SESSION_COOKIE_SECURE=True,     # send session cookie only over HTTPS
    SESSION_COOKIE_HTTPONLY=True,   # not accessible to JavaScript
    SESSION_COOKIE_SAMESITE="Lax"   # mitigates CSRF in most cases
)

# ADDED: safe error mapping
# Map safe error codes to user-friendly messages
ERORR_MESSAGES = {
    "invalid_password": "Invalid password. Please try again.",
    "unknown": "Somethin went wrong",
}

# Open the database. Have queries return dicts instead of tuples.
# The use of `check_same_thread` can cause unexpected results in rare cases. We'll
# get rid of this when we learn about SQLAlchemy.
db = sqlite3.connect("db.sqlite3", check_same_thread=False)
db.row_factory = sqlite3.Row

# Log all requests for analytics purposes
log_file = open('access.log', 'a', buffering=1)
@app.before_request
def log_request():
    log_file.write(f"{request.method} {request.path}\n") # Avoids writing sensitive infor like passwords


# Set user_id on request if user is logged in, or else set it to None.
@app.before_request
def check_authentication():
    if 'user_id' in request.cookies:
        request.user_id = int(request.cookies['user_id'])
    else:
        request.user_id = None

# The main page
@app.route("/")
def index():
    quotes = db.execute(
        "select id, text, attribution from quotes order by id"
    ).fetchall()
    # CHANGED: resolve error via ERROR_MESSAGES
    code = request.args.get('error')
    error_msg = ERORR_MESSAGES.get(code) if code else None
    return templates.main_page(quotes, request.user_id, error_msg)


# The quote comments page
@app.route("/quotes/<int:quote_id>")
def get_comments_page(quote_id):
    # CHANGED: use parameterized query for quote lookup (prevents SQLi)
    quote = db.execute(
        "select id, text, attribution from quotes where id = ?",
        (quote_id,)
    ).fetchone()

    # CHANGED: use parameterized query for comments (prevent SQLi)
    comments = db.execute(
        "select c.text, datatime(c.time,'localtime') as time, u.name as user_name "
        "from comments c left join users u on u.id = c.user_id "
        "where c.quote_id = ? order by c.id",
        (quote_id,)
    ).fetchall()

    return templates.comments_page(quote, comments, request.user_id)


# Post a new quote
@app.route("/quotes", methods=["POST"])
def post_quote():
    # CHANGED: avoid SQL injection by using parameterized query and safe accessors
    text = request.form.get("text", "")
    attribution = request.form.get("attribution", "")
    # input length limits / validation
    with db:
        db.execute(
            "insert intor quotes(text, attribution) values(?, ?)",
            (text, attribution),
        )
    return redirect("/#bottom")


# Post a new comment
@app.route("/quotes/<int:quote_id>/comments", methods=["POST"])
def post_comment(quote_id):
    # CHANGED: use paramterized query and safe accessors to prvent SQLi
    text = request.form.get("text", "")
    user_id = request.user_id if request.user_id is not None else None

    # input length limits / validation
    with db:
        db.execute(
            "insert into comments(text, quote_id, user_id) values(?, ?, ?)",
            (text, quote_id, user_id)
        )
    return redirect(f"/quotes/{quote_id}#bottom")


# Sign in user
@app.route("/signin", methods=["POST"])
def signin():
    username = request.form["username"].lower()
    password = request.form["password"]

    # CHANGED: paramterized SELECT to prevent SQLi when looking up user
    user = db.execute(
        "select id, password from users where name = ?",
        (username,)
    ).fetchone()

    if user: # user exists
        if password != user['password']:
            # wrong! redirect to main page with an error message
            return redirect('/?error=invalid_password') # CHANGED: return sage error code instead of message
        user_id = user['id']
    else: # new sign up
        with db:
            # CHANGED: paramterized INSERT to prevent SQLi during signup
            cursor = db.execute(
                "insert into user(name, password) values(?, ?)",
                (username, password),
            )
            user_id = cursor.lastrowid
    
    response = make_response(redirect('/'))

    # CHANGED: mark sensitive cookie Secure, HttpOnly, and set SameSite
    response.set_cookie(
        'user_id',
        str(user_id),
        secure=True,    # only send cookie over HTTPS
        httponly=True,  # not accessible to JavaScript
        samesite='Lax'  # mitigates CSRF for typical flows; use 'Strict" if appropriate
    )
    return response


# Sign out user
@app.route("/signout", methods=["GET"])
def signout():
    response = make_response(redirect('/'))
    # CHANGED: delete cookie with matching attributes to ensure removal in all contexts
    response.delete_cookie(
        'user_id',
        samesite='Lax',
        secure=True,
        httponly=True
    )
    return response
