import os
from flask import Flask, request,abort, send_file, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import qrcode
from flask_login import LoginManager, login_user, login_required, current_user, logout_user, UserMixin
from functools import wraps
import uuid
from uuid import UUID
from PIL import Image,ImageOps
from datetime import datetime
from flask import current_app
from flask_mail import Message
from app import mail
from sqlalchemy.orm import joinedload
from app.__init__ import _send_async_email
from threading import Thread

# from app import Organization

class Config:

        
    # Improved parsing of allowed export emails
    ALLOWED_EXPORT_EMAILS = [email.strip() for email in 
        os.environ.get('EXPORT_ADMIN_EMAILS', '').split(',') 
        if email.strip()
    ] or [
        'admin1@gmail.com',
        'admin@danwebit.com'
    ]

    @classmethod
    def can_export_invitees(cls, admin):
        """
        Check if an admin is authorized to export invitees.
        
        :param admin: The current admin object
        :return: Boolean indicating export permission
        """
        # Debug print to understand the authorization check
        print("--- Export Authorization Check ---")
        print(f"Admin Email: {admin.email}")
        print(f"Is Super Admin: {admin.is_super_admin}")
        print(f"Allowed Emails: {cls.ALLOWED_EXPORT_EMAILS}")
        
        # Ensure list is clean (remove any empty strings)
        allowed_emails = [email.strip().lower() for email in cls.ALLOWED_EXPORT_EMAILS if email.strip()]
        
        # Check authorization
        is_authorized = (
            admin.is_authenticated and (
                admin.is_super_admin or 
                admin.email.lower() in allowed_emails
            )
        )
        
        print(f"Is Authorized: {is_authorized}")
        return is_authorized

    @classmethod
    def add_export_admin(cls, email):
        """
        Add a new email to the list of export administrators.
        
        :param email: Email to add to export admin list
        """
        # Prevent duplicates and empty emails
        email = email.strip()
        if email and email not in cls.ALLOWED_EXPORT_EMAILS:
            # Update environment variable if possible
            current_emails = os.environ.get('EXPORT_ADMIN_EMAILS', '')
            new_emails = f"{current_emails},{email}" if current_emails else email
            os.environ['EXPORT_ADMIN_EMAILS'] = new_emails
            
            # Also update the class variable
            cls.ALLOWED_EXPORT_EMAILS.append(email)

    @classmethod
    def remove_export_admin(cls, email):
        """
        Remove an email from the list of export administrators.
        
        :param email: Email to remove from export admin list
        """
        # Remove from class variable
        if email in cls.ALLOWED_EXPORT_EMAILS:
            cls.ALLOWED_EXPORT_EMAILS.remove(email)
            
            # Update environment variable
            updated_emails = ','.join([e for e in cls.ALLOWED_EXPORT_EMAILS if e != email])
            os.environ['EXPORT_ADMIN_EMAILS'] = updated_emails

    @classmethod
    def print_allowed_emails(cls):
        """
        Helper method to print current allowed export emails.
        Useful for debugging.
        """
        print("Current Allowed Export Emails:")
        for email in cls.ALLOWED_EXPORT_EMAILS:
            print(email)


    # IMAGE_UPLOAD_FOLDER = os.getenv('IMAGE_UPLOAD_FOLDER', 'static/images')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

    @staticmethod
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

    @staticmethod
    def save_uploaded_image(file, prefix=""):
        if file and Config.allowed_file(file.filename):
            try:
                # Create filename and ensure folder exists
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{prefix}{int(datetime.utcnow().timestamp())}.{ext}"
                filepath = os.path.join(current_app.config['IMAGE_UPLOAD_FOLDER'], filename)

                if not os.path.exists(current_app.config['IMAGE_UPLOAD_FOLDER']):
                    os.makedirs(current_app.config['IMAGE_UPLOAD_FOLDER'])

                # Save original file temporarily
                file.save(filepath)

                # Open and resize image
                image = Image.open(filepath)
                image.thumbnail((800, 600))  # Resize to 800x600

                # Convert RGBA to RGB if necessary
                if image.mode in ("RGBA", "P"):
                    image = image.convert("RGB")

                # Save again after processing
                image.save(filepath, format='JPEG' if ext in ['jpg', 'jpeg'] else ext.upper())

                return filename

            except Exception as e:
                print(f"Error saving image: {e}")
                if os.path.exists(filepath):
                    os.remove(filepath)
                return None


    @staticmethod
    def delete_uploaded_image(filename):

        """Delete an uploaded image to prevent orphaned files."""
        filepath = os.path.join(current_app.config['IMAGE_UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            os.remove(filepath)


# Initialize allowed export emails on import
if not Config.ALLOWED_EXPORT_EMAILS:
    Config.add_export_admin('admin1@gmail.com')
    Config.add_export_admin('admin@danwebit.com')
    Config.print_allowed_emails()



def send_invitation_email(invitation_id):
    
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
        subject = f"You're Invited to Join My App as a {invitation.role.replace('_', ' ').title()}"


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
    msg_data = {
        'subject': subject,
        'sender': sender_for_message,
        'recipients': [invitation.email],
        'html_body': html_body
    }

    # Queue the email sending to run in a separate thread
    # The `_get_current_object()` is essential for passing the current app context to the new thread.
    Thread(target=_send_async_email, args=(current_app._get_current_object(), msg_data)).start()

    current_app.logger.info(f"Invitation email queued for {invitation.email}.")


# admin email invite
def send_admin_invite_email(email, name, temp_password, organization_name):
    """
    Sends an invitation email to a new administrator with a temporary password using HTML template.
    """
    try:
        msg = Message(
            subject=f"Admin Invitation - {organization_name}",
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[email]
        )

        # Plain text version (fallback)
        msg.body = f"""Hello {name or email},

        You have been invited to join the {organization_name} admin panel.

        Login Email: {email}
        Temporary Password: {temp_password}

        Please log in and change your password after your first login.

        Thanks,
        The {organization_name} Team
        """

        # HTML version
        msg.html = render_template(
            "emails/invite_admin.html",
            name=name,
            email=email,
            temp_password=temp_password,
            organization_name=organization_name
        )

        mail.send(msg)
        return True

    except Exception as mail_error:
        print(f"Failed to send admin invite email: {mail_error}")
        return False
