from flask import Blueprint, render_template
from flask_login import login_required, current_user

from config import roles_required, Log, Role, db, User, log_entries

security_bp = Blueprint('security', __name__, template_folder='templates')


# Security routes
@security_bp.route('/security')
@login_required
@roles_required('sec_admin')
def security():
    logs = db.session.query(Log, User).join(User, Log.user_id == User.id).all()
    event_logs = log_entries()
    return render_template('security/security.html', logs=logs, event_logs=event_logs, current_user=current_user, Role=Role)
