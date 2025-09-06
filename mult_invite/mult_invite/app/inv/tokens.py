# app/utils/tokens.py (Create a new file for this)
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from flask import render_template, url_for
from datetime import datetime
from flask_mail import Message, Mail
from flask import current_app 


mail = Mail() # Initialize Flask-Mail in your __init__.py/app.py


# --- IMPORTANT: Ensure current_app is available, e.g., by importing from app import create_app
# then create_app().app_context().push() if calling outside a request context.
# Or, configure SECRET_KEY in your Flask app config. ---

def generate_reset_token(email):
    """Generates a time-limited token for password reset."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    # Token valid for 1 hour (3600 seconds)
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    """Verifies a password reset token and returns the email if valid."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=expiration
        )
    except Exception: # SignatureExpired, BadTimeSignature, etc.
        return None
    return email

# app/utils/email_utils.py (Update your email sending utilities)
# Assuming you have a function to send emails, e.g., send_email
# You'll need an email configuration (SMTP server, port, user, pass) in your config.py

def send_password_reset_email(admin_email, token):
    """Sends a password reset email to the given admin_email."""
    reset_link = url_for('inv.reset_password', token=token,org_uuid='', _external=True)
    msg = Message(
        'Password Reset Request',
        sender=current_app.config['MAIL_DEFAULT_SENDER'],
        recipients=[admin_email]
    )
    msg.html = render_template('emails/password_reset.html', reset_link=reset_link)
    try:
        mail.send(msg)
        current_app.logger.info(f"Password reset email sent to {admin_email}")
    except Exception as e:
        current_app.logger.error(f"Failed to send password reset email to {admin_email}: {e}")