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

