from flask_login import current_user

from config import app, roles_required, Role
from flask import render_template, redirect, url_for, request, flash

from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)


@app.route('/')
def index():
    return render_template('home/index.html', current_user=current_user, Role=Role)


from flask_limiter.errors import RateLimitExceeded


@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_error(e):
    return render_template('errors/rate_limit.html'), 429


@app.errorhandler(400)
def bad_request_error(error):
    return render_template('errors/400.html', error=error, Role=Role), 400


@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html', error=error, Role=Role), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template('errors/500.html', error=error, Role=Role), 500


@app.errorhandler(501)
def not_implemented_error(error):
    return render_template('errors/501.html', error=error, Role=Role), 501


SQL_INJECTION_PATTERNS = ["union", "select", "insert", "drop", "alter", ";", "`", "'"]
XSS_PATTERNS = ["<script>", "<iframe>", "%3Cscript%3E", "%3Ciframe%3E"]
PATH_TRAVERSAL_PATTERNS = ["../", "..", "%2e%2e%2f", "%2e%2e/", "..%2f"]


def detect_attack():
    path = request.path.lower()
    query_string = request.query_string.decode().lower()

    # Checks for SQL Injection patterns
    if any(pattern in path or pattern in query_string for pattern in SQL_INJECTION_PATTERNS):
        flash("Attack detected: SQL Injection attempt.", category='danger')
        return redirect(url_for('error_page', attack_type='SQL Injection'))

    # Checks for XSS patterns
    if any(pattern in path or pattern in query_string for pattern in XSS_PATTERNS):
        flash("Attack detected: Cross-Site Scripting (XSS) attempt.", category='danger')
        return redirect(url_for('error_page', attack_type='XSS'))

    # Checks for Path Traversal patterns
    if any(pattern in path or pattern in query_string for pattern in PATH_TRAVERSAL_PATTERNS):
        flash("Attack detected: Path Traversal attempt.", category='danger')
        return redirect(url_for('error_page', attack_type='Path Traversal'))


# Register the middleware
@app.before_request
def before_request():
    # Detect attacks
    response = detect_attack()
    if response:
        return response


@app.before_request
def ensure_https():
    if not request.is_secure:
        return redirect(request.url.replace("http://", "https://"))


@app.route('/errors/<attack_type>')
def error_page(attack_type):
    return render_template('errors/attack.html', attack_type=attack_type), 403


if __name__ == '__main__':
    app.run(ssl_context=('ssl/cert.pem', 'ssl/key.pem'))
