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
from threading import Thread
from itsdangerous import URLSafeSerializer


# from app import Organization



#serializer for masking qr link generation for invitee
def get_serializer():
    return URLSafeSerializer(current_app.config['SECRET_KEY'], salt="invitee-link")


class Config:
   
 
        
    # Improved parsing of allowed export emails
    ALLOWED_EXPORT_EMAILS = [email.strip() for email in 
        os.environ.get('EXPORT_ADMIN_EMAILS', '').split(',') 
        if email.strip()
    ] or [
        'hoghidan1@gmail.com',
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
                admin.is_super_admin or admin.is_org_admin or
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



