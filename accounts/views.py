import os
from datetime import datetime
from functools import wraps
import pyotp
import pyqrcode
from PIL import Image
from flask import Blueprint, render_template, flash, redirect, url_for, session, request, abort
from flask_login import logout_user, login_user, login_required, current_user
from sqlalchemy.sql.functions import user

from accounts.forms import RegistrationForm, LoginForm
from config import User, db, limiter, Role, roles_required, logger

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')


# Account routes

@accounts_bp.route('/registration', methods=['GET', 'POST'])
def registration():
    if current_user.is_authenticated:
        flash('You are already logged in', category="success")
        return redirect(url_for('posts.post', _external=True).replace("http://", "https://"))

    form = RegistrationForm()

    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', category="danger")
            return render_template('accounts/registration.html', form=form)

        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role=Role.END_USER
                        )

        db.session.add(new_user)
        db.session.commit()

        new_user.generate_log()
        # Generate the MFA key
        mfa_key = pyotp.random_base32()

        # Save the key to the user's account (assuming you have a field for this)
        new_user.mfa_key = mfa_key
        db.session.commit()
        # log
        logger.info('[User: %s, Role: %s, IP: %s] Registered Successfully', new_user.email, new_user.role,
                    request.remote_addr)

        flash('Registration successful! Set up MFA before logging in.', category='info')

        # Redirect to MFA setup page with MFA key and QR code URI
        qr_uri = f"otpauth://totp/YourApp:{new_user.email}?secret={mfa_key}&issuer=YourApp"
        return redirect(url_for('accounts.mfa_setup', mfa_key=mfa_key, qr_uri=qr_uri))

    return render_template('accounts/registration.html', form=form)


Max_Attempts = 3


@accounts_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("500 per minute", error_message="Too many login attempts. Please try again later.")
def login():
    form = LoginForm()

    # Get the number of attempts from the session
    if 'attempts' not in session:
        session['attempts'] = session.get('attempts', 0)
        print("Current session attempts:", session['attempts'])

    if session.get('attempts') >= Max_Attempts:
        flash('Your account is locked. Unlock to try again.', category='danger')
        return render_template('accounts/login.html', form=None)  # Hide form when locked

    if form.validate_on_submit():
        print("Form is valid")
        user = User.query.filter_by(email=form.email.data).first()

        if not user or not user.verify_password(form.password.data):
            session['attempts'] += 1
            attempts_left = Max_Attempts - session['attempts']
            logger.warning('[User: %s, Attempts: %d, IP: %s] Invalid Login', form.email.data, session['attempts'],
                        request.remote_addr)

            if attempts_left > 0:
                flash(f'Username or Password is Incorrect. You have {attempts_left} attempts remaining.',
                      category='danger')
                return render_template('accounts/login.html', form=form)
            else:
                logger.warning('[User: %s, Attempts: %d, IP: %s] Invalid Login - Max attempts reached', user.email, session['attempts'],
                            request.remote_addr)
                flash('Your account is locked. Please unlock to try again.', category='danger')
                return render_template('accounts/login.html', form=None)

        # Handle MFA setup for users without MFA enabled
        if not user.mfa_enabled:
            # Verify MFA PIN if provided
            mfa_pin = form.mfa_pin.data
            if mfa_pin and user.verify_mfa_pin(mfa_pin):
                # Enable MFA and proceed with login
                user.mfa_enabled = True
                db.session.commit()
                login_user(user)
                logger.info('[User: %s, Role: %s, IP: %s] Logged in Successfully', user.email, user.role,
                            request.remote_addr)
                flash('MFA setup complete. Login successful!', category='success')
                session.pop('attempts', None)  # Reset attempts
                return redirect(url_for('posts.post', _external=True).replace("http://", "https://"))

            # Redirect to MFA setup if no valid PIN provided
            flash('Set up MFA before logging in.', category='info')
            qr_uri = f"otpauth://totp/Blog:{user.email}?secret={user.mfa_key}&issuer=BlogApp"
            return redirect(url_for('accounts.mfa_setup', mfa_key=user.mfa_key, qr_uri=qr_uri))

        # For users with MFA enabled, verify MFA PIN
        mfa_pin = form.mfa_pin.data
        if not user.verify_mfa_pin(mfa_pin):
            session['attempts'] += 1
            attempts_left = Max_Attempts - session['attempts']
            logger.warning('[User: %s, Attempts: %d, IP: %s] Invalid Login', user.email, session['attempts'],
                        request.remote_addr)
            flash(f'Invalid MFA PIN. You have {attempts_left} attempts remaining.', category='danger')
            return render_template('accounts/login.html', form=form)

        # Successful login: Reset attempts and redirect
        session.pop('attempts', None)
        login_user(user)
        logger.info('[User: %s, Role: %s, IP: %s] Logged in Successfully', user.email, user.role,
                    request.remote_addr)

        user_logs = user.log

        # Check if there are existing logs for the user
        if user_logs:
            user_log = user_logs[len(user_logs)-1]  # last log entry
            # Update log attributes
            user_log.previous_login = user_log.latest_login or None
            user_log.latest_login = datetime.utcnow()

            user_log.previous_ip = user_log.latest_ip or None
            user_log.latest_ip = request.remote_addr
            db.session.commit()

        else:
            # No log exists for the user so one is generated
            user.generate_log()
            user_log = user_logs[0]
            user_log.previous_login = user_log.latest_login or None
            user_log.latest_login = datetime.utcnow()
            user_log.previous_ip = user_log.latest_ip or None
            user_log.latest_ip = request.remote_addr
            db.session.commit()


        print("Logged-in user's role:", current_user.role)

        flash('Login successful!', category='success')
        if current_user.role == Role.END_USER.value:
            return redirect(url_for('posts.post', _external=True).replace("http://", "https://"))
        elif current_user.role == Role.DB_ADMIN.value:
            return redirect(url_for('admin.index', _external=True).replace("http://", "https://"))
        elif current_user.role == Role.SEC_ADMIN.value:
            return redirect(url_for('security.security', _external=True).replace("http://", "https://"))
        else:
            flash('Unknown role. Please contact an administrator.', category='warning')
            return redirect(url_for('accounts.login', _external=True).replace("http://", "https://"))

    return render_template('accounts/login.html', form=form, Role=Role)


@accounts_bp.route('/unlock', methods=['GET'])
def unlock_account():
    session.pop('attempts', None)  # Reset invalid attempts
    flash('Your account has been unlocked. You can try logging in again.', category='success')
    return redirect(url_for('accounts.login', _external=True).replace("http://", "https://"))


@accounts_bp.route('/mfa-setup')
def mfa_setup():
    mfa_key = request.args.get('mfa_key')

    # Generates QR code
    qr_uri = request.args.get('qr_uri')

    # Generates QR code image
    qr_code = pyqrcode.create(qr_uri)
    qr_code_path = os.path.join('static', 'mfa_qr.png')
    qr_code.png(qr_code_path, scale=6)  # Saves QR code as PNG in static folder
    if not mfa_key or not qr_uri:
        flash('No MFA key provided.', category='danger')
        return redirect(url_for('accounts.login', _external=True).replace("http://", "https://"))

    return render_template('accounts/mfa_setup.html', mfa_key=mfa_key, qr_uri=qr_uri, qr_code_image='mfa_qr.png', Role=Role)


@accounts_bp.route('/logout')
@roles_required('end_user', 'db_admin', 'sec_admin')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", category="info")
    return redirect(url_for('accounts.login',_external=True).replace("http://", "https://"))


@accounts_bp.route('/account')
@login_required
@roles_required('end_user', 'db_admin', 'sec_admin')
def account():
    if current_user.is_authenticated:
        user_posts = current_user.posts
        encryption_key = User.generate_encryption_key()

        # Decrypts each post
        for post in user_posts:
            decrypted_content = post.get_decrypted_content(encryption_key)
            post.title = decrypted_content['title']
            post.body = decrypted_content['body']
        return render_template('accounts/account.html', user=current_user, Role=Role)
    else:
        return render_template('accounts/account.html', user=None)