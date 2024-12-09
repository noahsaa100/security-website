import base64
import hashlib
import os
from enum import Enum
from functools import wraps

from cryptography.fernet import Fernet
import pyotp
from dotenv import load_dotenv
from flask import Flask, url_for, flash, redirect, abort, render_template, request

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
import secrets

from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_talisman import Talisman
from sqlalchemy import MetaData
from datetime import datetime

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import logging


def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return render_template('errors/forbidden.html')
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)

        return wrapped

    return decorator


app = Flask(__name__)
load_dotenv()
# SECRET KEY FOR FLASK FORMS
SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(16))  # Generate if not found
RECAPTCHA_PUBLIC_KEY = os.getenv('RECAPTCHA_PUBLIC_KEY')
RECAPTCHA_PRIVATE_KEY = os.getenv('RECAPTCHA_PRIVATE_KEY')
DATABASE_URI = os.getenv('DATABASE_URI')

app.config['SECRET_KEY'] = SECRET_KEY
app.config['RECAPTCHA_PUBLIC_KEY'] = RECAPTCHA_PUBLIC_KEY
app.config['RECAPTCHA_PRIVATE_KEY'] = RECAPTCHA_PRIVATE_KEY
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI

app.config['FLASK_ADMIN_FLUID_LAYOUT'] = True

metadata = MetaData(
    naming_convention={
        "ix": 'ix_%(column_0_label)s',
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s"
    }
)

db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db)

# Login Manager Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'accounts.login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def encrypt_text(plaintext, key):
    cipher = Fernet(key)
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt_text(ciphertext, key):
    cipher = Fernet(key)
    return cipher.decrypt(ciphertext.encode()).decode()


class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'))
    created = db.Column(db.DateTime, nullable=False)
    title = db.Column(db.Text, nullable=False)
    body = db.Column(db.Text, nullable=False)
    user = db.relationship("User", back_populates="posts")

    def set_encrypted_content(self, title, body, key):
        self.title = encrypt_text(title, key)
        self.body = encrypt_text(body, key)

    def get_decrypted_content(self, key):
        return {
            'title': decrypt_text(self.title, key),
            'body': decrypt_text(self.body, key)
        }

    def __init__(self, userid, title, body):
        self.created = datetime.now()
        self.title = title
        self.body = body
        self.userid = userid

    # DATABASE ADMINISTRATOR

    def update(self, title, body):
        self.created = datetime.now()
        self.title = title
        self.body = body
        db.session.commit()


class Role(Enum):
    END_USER = "end_user"
    DB_ADMIN = "db_admin"
    SEC_ADMIN = "sec_admin"


bcrypt = Bcrypt()


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    active = db.Column(db.Boolean, default=True)  # To enable account locking
    role = db.Column(db.String(100), nullable=False, default='end_user')
    log = db.relationship('Log', back_populates='user', cascade="all, delete-orphan")

    @staticmethod
    def generate_encryption_key():
        app_secret = os.getenv('APP_SECRET')
        key_material = f"shared-key-{app_secret}".encode()

        # Derive key and encode
        derived_key = hashlib.sha256(key_material).digest()
        return base64.urlsafe_b64encode(derived_key)

    def generate_log(self):
        user_log = Log(user_id=self.id)
        db.session.add(user_log)
        db.session.commit()

    @property
    def is_active(self):
        return self.active

    mfa_key = db.Column(db.String(32), nullable=False, default=lambda: secrets.token_hex(16))
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, email, firstname, lastname, phone, password, role):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')  # Hashes the password
        self.mfa_key = pyotp.random_base32()
        self.role = role.value

    posts = db.relationship("Post", order_by=Post.id, back_populates="user")

    def verify_password(self, password):
        # Compare passwords
        return bcrypt.check_password_hash(self.password, password)

    def verify_mfa_pin(self, mfa_pin):
        if not self.mfa_key:
            print("MFA key is missing for user.")
            return False

        print("Stored MFA Key:", self.mfa_key)
        totp = pyotp.TOTP(self.mfa_key)

        # Testing
        server_generated_pin = totp.now()
        print("Server-Generated PIN:", server_generated_pin)

        if totp.verify(mfa_pin, valid_window=1):
            print("MFA PIN verified successfully.")
            return True
        else:
            print("MFA PIN verification failed.")
            return False


class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    registration_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    latest_login = db.Column(db.DateTime, nullable=True)
    previous_login = db.Column(db.DateTime, nullable=True)
    latest_ip = db.Column(db.String(45), nullable=True)
    previous_ip = db.Column(db.String(45), nullable=True)

    user = db.relationship("User", back_populates="log")

    def __init__(self, user_id):
        self.user_id = user_id
        self.registration_date = datetime.utcnow()


# Create the logger
logger = logging.getLogger('security_logger')
logger.setLevel(logging.INFO)  # Adjust the level as needed (e.g., INFO, WARNING)

# Create a file handler
file_handler = logging.FileHandler('security.log', mode='a')

# Set level
file_handler.setLevel(logging.INFO)

# formatter
formatter = logging.Formatter('%(asctime)s : %(message)s', '%d/%m/%Y %I:%M:%S %p')
file_handler.setFormatter(formatter)

# Add the file handler to the logger
logger.addHandler(file_handler)


def log_entries(logfile='security.log'):
    if not os.path.exists(logfile):
        return []

    with open(logfile, 'r') as f:
        lines = f.readlines()

    # Get the last 10 lines, or fewer if there aren't 10
    return lines[-10:]


class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for('index')


# Manages who can see database info
class SecureModelView(ModelView):
    def is_accessible(self):
        # Restrict access to authenticated users only
        # if not current_user.is_authenticated:
        #  return False
        # if current_user.role not in ['db_admin', 'sec_admin']:
        #    return False

        return True


class PostView(SecureModelView):
    column_display_pk = True
    column_hide_backrefs = False
    can_create = False
    can_edit = False
    can_delete = False
    column_list = ('id', 'userid', 'created', 'title', 'body', 'user')


class UserView(SecureModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = (
        'id', 'email', 'password', 'firstname', 'lastname', 'phone', 'posts', 'mfa_key', 'mfa_enabled', 'role')


class LogView(SecureModelView):
    column_display_pk = True
    column_list = ['id', 'user_id', 'registration_date', 'latest_login', 'previous_login', 'latest_ip', 'previous_ip']

    def inaccessible_callback(self, name, **kwargs):
        # Redirect to login page if access is denied
        logger.warning('[User: %s, Role: %s, Post ID: %d, URL: %s, IP: %s] Unauthorized access attempt',
                       current_user.email,
                       current_user.role,
                       request.url,
                       request.remote_addr
                       )
        flash('Not authorised', category='danger')
        return redirect(url_for('accounts.login'))


limiter = Limiter(
    key_func=get_remote_address,  # Get users Ip
    app=app,
    default_limits=["500 per day"]  # 500 requests/day
)

csp = {
    'default-src': ["'self'"],
    'style-src': [
        "'self'",
        "https://trusted-styles.com",
        "https://stackpath.bootstrapcdn.com",
        'https://cdn.jsdelivr.net',
    ],
    'script-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
        "https://trusted-cdn.com",
        "https://another-cdn.com",
        'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/',
        'https://cdnjs.cloudflare.com',
        'https://www.google.com/recaptcha/',
        'https://www.gstatic.com/recaptcha/',
        "'unsafe-inline'",
    ],
    'img-src': [
        "'self'",
        "https://trusted-images.com",
        "https://another-image-source.com",
        'data:',
    ],
    'font-src': [
        "'self'",
        "https://trusted-fonts.com",
    ],
    'frame-src': [
        "'self'",
        'https://www.google.com/recaptcha/',
        'https://recaptcha.google.com/recaptcha/',
    ],
    'connect-src': [
        "'self'",
        "https://trusted-api.com",
        'https://www.google.com/recaptcha/',
        'https://www.gstatic.com/recaptcha/',
    ],
    'media-src': ["'self'"],
    'object-src': ["'none'"],
    'child-src': ["'self'"],
    'manifest-src': ["'self'"],
}

Talisman(app, content_security_policy=csp)
# Roles decorator

admin = Admin(app, name='DB Admin', template_mode='bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))
admin.add_view(LogView(Log, db.session))

# IMPORT BLUEPRINTS
from accounts.views import accounts_bp
from posts.views import posts_bp
from security.views import security_bp

app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)
