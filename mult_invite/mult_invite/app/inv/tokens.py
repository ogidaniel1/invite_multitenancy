# app/utils/tokens.py (Create a new file for this)
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from flask import render_template, url_for
from datetime import datetime
from flask_mail import Message, Mail
from email.mime.image import MIMEImage
import smtplib
from app.models import Organization
from threading import Thread
from app.__init__ import _send_async_email,send_async_email
from sqlalchemy.orm import joinedload



mail = Mail() # Initialize Flask-Mail in your __init__.py/app.py


# --- IMPORTANT: Ensure current_app is available, e.g., by importing from app import create_app
# then create_app().app_context().push() if calling outside a request context.
# Or, configure SECRET_KEY in your Flask app config. ---

def generate_admin_token(email):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return s.dumps(email, salt="admin-login-salt")

def verify_admin_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        return serializer.loads(token, salt="admin-login-salt", max_age=expiration)
    except Exception:
        return None


def generate_invitee_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt="invitee-login-salt")

def verify_invitee_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        return serializer.loads(token, salt="invitee-login-salt", max_age=expiration)
    except Exception:
        return None


#for new admin login...


#################################################

# send confirm mail
def send_confirm_email(invitee, event, org):
    sender_email = getattr(org, "email", None) or "noreply@noreply.com"
    try:

        html_body = render_template(
            "emails/confirm_registration.html",
            invitee=invitee,
            event=event,
            org=org
        )
        print("Confirmation email sent successfully!")

        send_async_email(
                subject=f"Welcome to {event.name.upper()}",
                sender=sender_email,
                recipients=[invitee.email],
                html_body=html_body,
        )
    except Exception as e:
        print(f"Error sending email: {e}")
        raise


# for invitee api invites..........

def send_invitee_invitation_email(invitee_id, temp_password=None):
    from app.models import Invitee, Organization, db

    invitee = Invitee.query.options(joinedload(Invitee.organization)).get(invitee_id)
    if not invitee:
        raise ValueError(f"Invitee with ID {invitee_id} not found.")

    invitation_link = url_for('inv.invitee_manual_login',org_uuid=invitee.organization.uuid,
        _external=True)

    sender_info = current_app.config.get('MAIL_DEFAULT_SENDER')
    sender_for_message = sender_info if isinstance(sender_info, tuple) else current_app.config.get('MAIL_USERNAME')

    organization_name = invitee.organization.name if invitee.organization else "Our Platform"

    subject = f"Your Login Credentials for {organization_name}"

    html_body = render_template(
        'emails/invitee_link.html',
        invitee=invitee,
        invitation_link=invitation_link,
        organization_name=organization_name,
        temp_password=temp_password,
        now=datetime.utcnow
    )

    send_async_email(
    subject=subject,
    recipients=[invitee.email],
    html_body=html_body,
    sender=sender_for_message
    )

    current_app.logger.info(f"Invitee login email queued for {invitee.email}.")



# for tracking pending or accep(admin or invitee, anybody)
def send_invitation_email(invitation_id):
    from app.models import Invitation, db

    invitation = db.session.query(Invitation).options(
        joinedload(Invitation.organization)
    ).get(invitation_id)

    if not invitation:
        raise ValueError(f"Invitation with ID {invitation_id} not found.")

    # Safe organization reference
    org = invitation.organization

        # Fallback if no org linked
    org_uuid = org.uuid if org else "unknown"
    organization_name = org.name if org else "Our Platform"
    # org_uuid = org.uuid if org else "default-uuid"  # Replace with default if needed

    # Only admin login link
    invitation_link = url_for(
        "inv.accept_invitation",
        org_uuid=org_uuid,
        token=invitation.token,
        _external=True
    )

    # Determine sender email
    sender_info = current_app.config.get('MAIL_DEFAULT_SENDER')
    sender_for_message = (
        sender_info if isinstance(sender_info, tuple)
        else current_app.config.get('MAIL_USERNAME')
    )

    # Format role nicely
    role_title = invitation.role.replace('_', ' ').title()

    # Email subject
    subject = f"You're Invited to Join {organization_name} as a {role_title}"

    # Render template safely (pass organization_name explicitly)
    html_body = render_template(
        'emails/invitation_email.html',
        invitation=invitation,
        invitation_link=invitation_link,
        organization_name=organization_name,
        # organization_name=org.name if org else "Our Platform",
        role=role_title,
        org=org,
        now=datetime.utcnow
    )

    # Send email asynchronously
    send_async_email(
        subject=subject,
        recipients=[invitation.email],
        html_body=html_body,
        sender=sender_for_message
    )

    current_app.logger.info(f"Invitation email queued for {invitation.email}.")



def send_admin_invite_email(email, name,role, temp_password, organization_name):
    from app.models import db, Organization

    # Find organization safely
    org = Organization.query.filter(
        db.func.lower(Organization.name) == organization_name.lower()
    ).first()

    if not org:
        current_app.logger.error(f"Organization '{organization_name}' not found.")
        return False

    # Safe fallback sender
    sender = getattr(org, "email", None) or \
             current_app.config.get("MAIL_DEFAULT_SENDER") or \
             current_app.config['MAIL_USERNAME']

    # NEW: Login for admins
    login_url = url_for("inv.login", org_uuid=org.uuid, _external=True)

    try:
        html_body = render_template(
            "emails/invite_admin.html",
            name=name,
            email=email,
            temp_password=temp_password,
            org=org,
            role=role,
            organization_name=organization_name,
            login_url=login_url   
        )

        send_async_email(
            subject=f"Admin Invitation - {organization_name.upper()}",
            sender=sender,
            recipients=[email],
            html_body=html_body
        )

        current_app.logger.info(
            f"Admin invite email sent → {email} for organization {organization_name}"
        )
        return True

    except Exception as mail_error:
        current_app.logger.error(f"Failed to send admin invite email: {mail_error}")
        return False
    

