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

def generate_reset_token(email):
    """Generates a time-limited token for password reset."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    # Token valid for 1 hour (3600 seconds)
    return serializer.dumps(email, salt='password-reset-salt')


def verify_reset_token(token, expiration=3600):
    """Verifies a password reset token and returns the email if valid."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token,salt='password-reset-salt', max_age=expiration
        )
    except Exception: # SignatureExpired, BadTimeSignature, etc.
        return None
    return email



#for new admin login...
# def send_admin_login_link(admin,org):

#     org = Organization.query.get(admin.organization_id)
#     if not org:
#         raise ValueError ("Organization not found")
    
#     sender = getattr(org, "email",current_app.config['MAIL_USERNAME'])

#     token=generate_reset_token(admin.email)
#     login_url= url_for('inv.login_with_token', token=token, _external=True)
#     try:
#         # HTML version
#         html_body = render_template(
#                 "emails/welcome_admin.html",
#                 admin=admin,
#                 org=org,
#                 login_url=login_url
#             )
        
#         send_async_email(
#             subject= f"Welcome! your Admin access to {org.name.upper()}",
#             recipients=[admin.email],
#             html_body=html_body,
#             sender=sender
#         )
      
#     except Exception as e:
#         print(f"Error sending email: {e}")
#         raise

def send_admin_login_link(admin, org=None):
    # lazy imports
    from app.models import Organization
   
    # ensure org instance
    if not org:
        org = Organization.query.get(admin.organization_id)
    if not org:
        raise ValueError("Organization not found")

    sender = getattr(org, "email", None) or current_app.config.get('MAIL_DEFAULT_SENDER') or current_app.config.get('MAIL_USERNAME')

    token = generate_reset_token(admin.email)
    # This route logs in via token and redirects to org pages
    login_url = url_for('inv.login_with_token', token=token, _external=True)

    html_body = render_template(
        "emails/welcome_admin.html",
        admin=admin,
        org=org,
        login_url=login_url
    )

    try:
        send_async_email(
            subject=f"Welcome! Your Admin access to {org.name}",
            sender=sender,
            recipients=[admin.email],
            html_body=html_body
        )
        current_app.logger.info("Admin login link sent to %s", admin.email)
        return True
    except Exception as exc:
        current_app.logger.error("Error sending admin email: %s", exc)
        return False


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



def send_invitation_email(invitation_id,msg_data):
    
    from app.models import Invitation,db
    """
    Sends an invitation email to a user asynchronously.
    Args:
        invitation_id: The ID of the Invitation object to send an email for.
    """
    # Re-fetch the invitation object within the current app context for robustness.
    # Eager load the organization relationship.
    invitation = db.session.query(Invitation).options(joinedload(Invitation.organization)).get(invitation_id)

    if not invitation:
        current_app.logger.error(f"Invitation with ID {invitation_id} not found for email sending.")
        # Raise an error, as we can't send an email for a non-existent invitation
        raise ValueError(f"Invitation with ID {invitation_id} not found.")

    try:
        invitation_link = url_for('inv.invitation_confirm', token=invitation.token, _external=True)
    except Exception as e:
        current_app.logger.error(f"Error generating invitation URL for {invitation.email}: {e}")
        # Re-raise the error for the calling function to catch
        raise ValueError(f"Could not generate invitation URL: {e}")

    sender_info = current_app.config.get('MAIL_DEFAULT_SENDER')
    if isinstance(sender_info, tuple) and len(sender_info) == 2:
        sender_for_message = sender_info
    else:
        sender_for_message = current_app.config.get('MAIL_USERNAME')

    # Conditionally determine organization name for subject and template
    display_organization_name = invitation.organization.name if invitation.organization else None

    # Adjust subject line based on whether an organization is present
    if display_organization_name:
        subject = f"You're Invited to Join {display_organization_name} as a {invitation.role.replace('_', ' ').title()}"
    else:
        # Generic subject for admin or non-organization-specific invitations
        subject = f"You're Invited to Join {display_organization_name} as a {invitation.role.replace('_', ' ').title()}"

    try:
    # Render HTML content for the email body
        html_body = render_template('emails/invitation_email.html',
                                invitation=invitation, # Pass the invitation object
                                invitation_link=invitation_link,
                                organization_name=display_organization_name, # Pass the (potentially None) display name
                                role=invitation.role.replace('_', ' ').title(),
                                now=datetime.utcnow # Pass datetime.utcnow for {{ now().year }}
                                )

        # Prepare data to be sent to the async thread.
        # We pass minimal, serializable data. The actual Message object is built in the async thread.
        send_async_email({
            'subject': subject,
            'sender': sender_for_message,
            'recipients': [invitation.email],
            'html_body': html_body
        })
        
        current_app.logger.info(f"Invitation email queued for {invitation.email}.")

    except Exception as e:
        current_app.logger.info(f"Invitation Failed")



    # Queue the email sending to run in a separate thread
    # The `_get_current_object()` is essential for passing the current app context to the new thread.
    # Thread(target=_send_async_email, args=(current_app._get_current_object(), msg_data)).start()

    # current_app.logger.info(f"Invitation email queued for {invitation.email}.")



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

    # NEW: Login URL
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
    

