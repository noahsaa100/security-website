from flask_wtf import FlaskForm
from flask_wtf.recaptcha import RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length, Regexp, Email
import re


def strong_password(form, field):
    password = field.data

    # Check length
    if len(password) < 8 or len(password) > 15:
        raise ValidationError("Password must be between 8 and 15 characters long.")

    # Check for uppercase letter
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain at least one uppercase letter.")

    # Check for lowercase letter
    if not re.search(r"[a-z]", password):
        raise ValidationError("Password must contain at least one lowercase letter.")

    # Check for digit
    if not re.search(r"\d", password):
        raise ValidationError("Password must contain at least one digit.")

    # Check for special character
    if not re.search(r"\W", password):
        raise ValidationError("Password must contain at least one special character.")


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    firstname = StringField('First Name', validators=[
        DataRequired(),
        Regexp(r'^[a-zA-Z-]+$', message="First name can only contain letters or hyphens.")
    ])
    lastname = StringField('Last Name', validators=[
        DataRequired(),
        Regexp(r'^[a-zA-Z-]+$', message="Last name can only contain letters or hyphens.")
    ])
    phone = StringField('Phone Number', validators=[
        DataRequired(),
        Regexp(
            r'^(02\d-\d{8}|011\d-\d{7}|01\d1-\d{7}|01\d{3}-\d{5,6})$',
            message="Enter a valid UK landline phone number."
        )
    ])
    password = PasswordField('Password', validators=[DataRequired(), strong_password])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords do not match!')
    ])
    submit = SubmitField()


class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    mfa_pin = StringField('MFA PIN', validators=[
        DataRequired(),
        Length(min=6, max=6, message="MFA PIN must be exactly 6 digits."),
        Regexp(r'^\d{6}$', message="MFA PIN must only contain numbers.")
    ])
    recaptcha = RecaptchaField()
    submit = SubmitField()

