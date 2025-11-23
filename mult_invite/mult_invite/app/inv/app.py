import os
from flask_wtf import CSRFProtect, FlaskForm
from werkzeug.utils import secure_filename
from functools import wraps
from flask_wtf.csrf import generate_csrf, validate_csrf,CSRFError
from flask_paginate import Pagination, get_page_parameter
from flask import Blueprint,Flask, render_template, request, redirect, url_for, flash,jsonify, abort,Response, session
from flask_sqlalchemy import SQLAlchemy
from Crypto.Hash import SHA256
from alembic import op
from datetime import datetime, timezone
import json
from sqlalchemy.orm import joinedload
import logging
import pandas as pd
from wtforms import SubmitField
from wtforms import StringField, SubmitField,SelectField,HiddenField, FloatField,PasswordField
from wtforms.validators import DataRequired, Email, EqualTo,Length,ValidationError,Optional,Regexp
# from utils import load_config, generate_db_uri
from flask_wtf.file import FileAllowed, FileRequired, FileField,FileSize
from dotenv import load_dotenv
import random, time
from datetime import timedelta
from flask import Flask, request, send_file, render_template, redirect, url_for
import qrcode
from flask_login import LoginManager, login_user, login_required, current_user, logout_user, UserMixin
from sqlalchemy import and_ , or_,cast, String,func, case
# from flask import Flask, send_from_static
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,FileField
from wtforms.validators import DataRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash
import io
from flask_mail import  Mail,Message
from email.mime.image import MIMEImage
import smtplib
import base64
# import cv2
import subprocess
import pyzbar
from pyzbar.pyzbar import decode
import pymysql
pymysql.install_as_MySQLdb()  #install mysql
from sqlalchemy import create_engine
from urllib.parse import quote  
from itertools import zip_longest
from geopy.distance import geodesic
import re 
from io import BytesIO
from config import Config,get_serializer
# ,org_admin_required,super_required
import uuid
# from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import func
from flask_cors import CORS # For handling CORS if frontend is on a different origin
from datetime import datetime
from app import db
from app.models import LoginForm,ActionLog,DeleteInviteeForm,DeleteLog,OrganizationForm,Location,OrgIdentifierForm,is_authorized_user
from app.models import Organization,Admin,Invitation,Invitee,InviteeForm,super_required,Feedback,Event,EventInvitee,Attendance,invitee_only
from app.models import FeedbackForm,AttendanceForm,AdminForm,admin_or_super_required,fetch_lgas_all,fetch_lgas,org_admin_or_super_required
from config import Config,get_serializer
from app import csrf,mail
from flask import current_app
from flask_dance.contrib.google import make_google_blueprint, google


from app.inv.tokens import generate_reset_token, verify_reset_token,send_admin_login_link,send_confirm_email
from app.models  import RequestResetForm, ResetPasswordForm # Create these forms below
from app.__init__ import send_async_email
 
# from models import get_lgas,fetch_lgas


app_ = Blueprint('inv', __name__, template_folder='../templates')


load_dotenv()

#######################################################

# Configuration
DEFAULT_ADMIN_EMAIL = os.getenv('DEFAULT_ADMIN_EMAIL')
DEFAULT_ADMIN_PASSWORD = os.getenv('DEFAULT_ADMIN_PASSWORD')




# general home page
@app_.route('/')
def home():
    return render_template('base_dashboard.html')


@app_.route('/register_organization', methods=['GET', 'POST'])
@super_required
def register_organization():
    form = OrganizationForm()

    if form.validate_on_submit():
        file = form.logo_url.data

        existing_slug = Organization.query.filter_by(slug=form.slug.data,name=form.name.data).first()
       
        if existing_slug:
            flash('Organization slug already exists. Choose another one.', 'danger')
            return redirect(url_for('inv.register_organization'))
 
        filename = Config.save_uploaded_image(file, prefix=form.slug.data + "_") if file else None

        if filename is None:
            flash("Invalid file format, please upload PNG, JPEG, GIF, or JPG!", "danger")
            return redirect(url_for('inv.register_organization'))

        try:
            new_org = Organization(
                name=form.name.data,
                slug=form.slug.data,
                logo_url=filename
            )
            db.session.add(new_org)
            db.session.commit()

            flash('Organization registered successfully.', 'info')
            return redirect(url_for('inv.login', org_uuid=new_org.uuid))

        except smtplib.SMTPException as e:
            db.session.rollback()
            flash(f"Registration successful, but email error: {str(e)}", "error")
            return redirect(url_for('inv.login', org_uuid=new_org.uuid))

        except Exception as e:
            db.session.rollback()
            flash(f"Error saving to database: {str(e)}", "error")
            return redirect(url_for('inv.register_organization'))

    return render_template('register_organization.html', form=form)

# ##############################################


# Enhanced all_org route with search and pagination
@app_.route('/all_organizations', methods=['GET', 'POST'])
@super_required  
def all_org():
    """Enhanced view all organizations with search and pagination"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Build query
    query = Organization.query
    
    # Apply search filter
    if search:
        query = query.filter(
            db.or_(
                Organization.name.contains(search),
                Organization.slug.contains(search)
            )
        )
    
    # Apply pagination
    organizations = query.order_by(Organization.created_at.desc()).paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )

    return render_template('organizations.html',organizations=organizations,search=search)

# Add these routes to your existing Flask application

@app_.route('/organization/view')
@super_required
def view_organization():
    """View a specific organization details"""

    organizations = Organization.query.all()
    org_dat=[{
        'id': org.id,
        'uuid': org.uuid,     # ← FIX HERE
        'slug': org.slug,
        'name': org.name,
        'address': org.address,
        'is_active': org.is_active,
        'created_at': org.created_at.isoformat(),
        'active_locations_count':len(org.get_active_locations())
            }
    for org in organizations
    ]
    return render_template('organizations.html', 
                         organizations=org_dat)
        
     

@app_.route('/organization/<int:org_id>/edit', methods=['GET', 'POST'])
@super_required
def edit_organization(org_id):
    """Edit an existing organization"""
    organization = Organization.query.get_or_404(org_id)
    form = OrganizationForm(obj=organization)
    
    if form.validate_on_submit():
        file = form.logo_url.data
        
        # Check if slug already exists (excluding current organization)
        existing_slug = Organization.query.filter(
            Organization.slug == form.slug.data,Organization.name == form.name.data,
            Organization.id != org_id
        ).first()
        
        # Check if name already exists (excluding current organization)
        # existing_name = Organization.query.filter(
        #     Organization.name == form.name.data,
        #     Organization.id != org_id
        # ).first()
        
        if existing_slug:
            flash('Organization slug already exists. Choose another one.', 'danger')
            return render_template('organizations.html', form=form, organization=organization)
        
        # if existing_name:
        #     flash('Organization name already exists. Choose another one.', 'danger')
        #     return render_template('organizations.html', form=form, organization=organization)
        
        try:
            # Handle logo upload
            if file:
                # Remove old logo if it exists
                if organization.logo_url:
                    old_logo_path = os.path.join(current_app.config['IMAGE_UPLOAD_FOLDER'], organization.logo_url)
                    if os.path.exists(old_logo_path):
                        try:
                            os.remove(old_logo_path)
                        except OSError:
                            pass  # Continue even if old file removal fails
                
                # Save new logo
                filename = Config.save_uploaded_image(file, prefix=form.slug.data + "_")
                if filename is None:
                    flash("Invalid file format, please upload PNG, JPEG, GIF, or JPG!", "danger")
                    return render_template('organizations.html', form=form, organization=organization)
                
                organization.logo_url = filename
            
            # Update organization fields
            organization.name = form.name.data
            organization.slug = form.slug.data
            
            db.session.commit()
            flash(f'Organization "{organization.name}" updated successfully!', 'success')
            return redirect(url_for('inv.view_organization', org_id=organization.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating organization: {str(e)}", "error")
            return render_template('organization.html', form=form, organization=organization)
    
    return render_template('organizations.html', form=form, organization=organization)


@app_.route('/organization/<int:org_id>/delete', methods=['POST'])
@super_required
def delete_organization(org_id):
    """Delete an organization"""
    organization = Organization.query.get_or_404(org_id)
    
    try:
        # Store name for flash message
        org_name = organization.name
        
        # Remove logo file if it exists
        if organization.logo_url:
            logo_path = os.path.join(current_app.config['IMAGE_UPLOAD_FOLDER'], organization.logo_url)
            if os.path.exists(logo_path):
                try:
                    os.remove(logo_path)
                except OSError:
                    pass  # Continue even if file removal fails
        
        # Check if organization has related data (locations, users, etc.)
        active_locations = organization.get_active_locations()
        if active_locations:
            flash(f'Cannot delete "{org_name}". Organization has {len(active_locations)} active locations. Please remove all locations first.', 'danger')
            return redirect(url_for('inv.view_organization', org_id=org_id))
        
        # Additional checks for related data
        # Add checks for users, bookings, etc. if they exist in your model
        # Example:
        # if organization.users.count() > 0:
        #     flash(f'Cannot delete "{org_name}". Organization has associated users.', 'danger')
        #     return redirect(url_for('view_organization', org_id=org_id))
        
        db.session.delete(organization)
        db.session.commit()
        
        flash(f'Organization "{org_name}" deleted successfully!', 'success')
        return redirect(url_for('inv.all_org'))
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting organization: {str(e)}", "error")
        return redirect(url_for('inv.view_organization', org_id=org_id))


@app_.route('/organization/<int:org_id>/toggle_status', methods=['POST'])
@super_required
def toggle_organization_status(org_id):
    """Toggle organization active status (if you have an is_active field)"""
    organization = Organization.query.get_or_404(org_id)
    
    try:
        # Assuming you might want to add an is_active field later
        # organization.is_active = not organization.is_active
        # For now, we'll just return success
        
        db.session.commit()
        flash(f'Organization "{organization.name}" status updated!', 'success')
        
        # Return JSON for AJAX requests
        if request.is_json:
            return jsonify({
                'success': True, 
                'message': f'Organization status updated',
                'is_active': getattr(organization, 'is_active', True)
            })
            
        return redirect(url_for('inv.view_organization', org_id=org_id))
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating organization status: {str(e)}", "error")
        
        if request.is_json:
            return jsonify({'success': False, 'message': str(e)}), 500
            
        return redirect(url_for('inv.view_organization', org_id=org_id))


# API Routes for AJAX operations
@app_.route('/api/organizations')
@super_required
def api_organizations():
    """API endpoint to get all organizations"""
    organization = Organization.query.order_by(Organization.created_at.desc()).all()
    
    return jsonify([{
        'id': org.id,
        'name': org.name,
        'slug': org.slug,
        'uuid': str(org.uuid),
        'logo_url': org.logo_url,
        'created_at': org.created_at.isoformat() if org.created_at else None,
        'active_locations_count': len(org.get_active_locations())
    } for org in organization])


@app_.route('/api/organization/<int:org_id>')
@super_required
def api_organization(org_id):
    """API endpoint to get a specific organization"""
    organization = Organization.query.get_or_404(org_id)
    
    return jsonify({
        'id': organization.id,
        'name': organization.name,
        'slug': organization.slug,
        'uuid': str(organization.uuid),
        'logo_url': organization.logo_url,
        'created_at': organization.created_at.isoformat() if organization.created_at else None,
        'active_locations_count': len(organization.get_active_locations())
    })

@app_.route('/api/organization/<int:org_id>/delete', methods=['DELETE'])
@super_required
def api_delete_organization(org_id):
    """API endpoint to delete an organization"""
    organization = Organization.query.get_or_404(org_id)

    try:
        org_name = organization.name

        # Check for related data
        active_locations = organization.get_active_locations()
        if active_locations:
            return jsonify({
                'success': False,
                'message': f'Cannot delete "{org_name}". Organization has {len(active_locations)} active locations.'
            }), 400

        #Disassociate all admins first
        for admin in organization.admins:
            admin.organization_id = None

        # Remove logo file
        if organization.logo_url:
            logo_path = os.path.join(current_app.config['IMAGE_UPLOAD_FOLDER'], organization.logo_url)
            if os.path.exists(logo_path):
                try:
                    os.remove(logo_path)
                except OSError:
                    pass

        # Delete the organization
        db.session.delete(organization)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Organization "{org_name}" deleted successfully!'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Error deleting organization: {str(e)}'
        }), 500

# # Bulk operations route
@app_.route('/organizations/bulk_action', methods=['POST'])
@super_required
def bulk_organization_action():
    """Handle bulk actions on organizations"""
    action = request.form.get('action')
    org_ids = request.form.getlist('org_ids')
    
    if not action or not org_ids:
        flash('Please select an action and at least one organization.', 'warning')
        return redirect(url_for('inv.all_org'))
    
    try:
        organizations = Organization.query.filter(Organization.id.in_(org_ids)).all()
        
        if action == 'delete':
            count = 0
            for org in organizations:
                # Check for related data
                if not org.get_active_locations():
                    # Remove logo file
                    if org.logo_url:
                        logo_path = os.path.join(current_app.config['IMAGE_UPLOAD_FOLDER'], org.logo_url)
                        if os.path.exists(logo_path):
                            try:
                                os.remove(logo_path)
                            except OSError:
                                pass
                    
                    db.session.delete(org)
                    count += 1
            
            db.session.commit()
            flash(f'Successfully deleted {count} organizations.', 'success')
            
        # Add other bulk actions as needed
        # elif action == 'activate':
        #     for org in organizations:
        #         org.is_active = True
        #     db.session.commit()
        #     flash(f'Successfully activated {len(organizations)} organizations.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error performing bulk action: {str(e)}', 'error')
    
    return redirect(url_for('inv.all_org'))


# #####.........routes.py...
 
@app_.route('/login/', methods=['GET', 'POST'])
def universal_login():
    form = OrgIdentifierForm()

    #  If already logged in, send them where they belong
    if current_user.is_authenticated:
        if hasattr(current_user, "is_invitee") and current_user.is_invitee:
            org = current_user.organization
            return redirect(url_for('inv.invitee_event_profile', org_uuid=org.uuid))
        elif isinstance(current_user, Admin) and current_user.is_org_admin:
                org = current_user.organization
                return redirect(url_for('inv.show_invitees', org_uuid=org.uuid))

        elif isinstance(current_user, Admin) and current_user.is_location_admin:
                org = current_user.organization
                return redirect(url_for('inv.show_invitees', org_uuid=org.uuid))

        elif isinstance(current_user, Admin):
            org = current_user.organization
            return redirect(url_for('inv.show_invitees', org_uuid=org.uuid))
        return redirect(url_for('inv.universal_login'))
    
    if form.validate_on_submit():
        identifier = form.org_identifier.data.strip()

        #Try finding organization by name or slug
        org = Organization.query.filter(
            (Organization.slug == identifier.lower()) |
            (Organization.name.ilike(f"%{identifier}%"))
        ).first()

        if org:
            flash(f"Please log in to {org.name}.", "info")
            return redirect(url_for('inv.login', org_uuid=org.uuid))

        # If identifier looks like an email, try both Admin and Invitee
        if "@" in identifier:
            admin = Admin.query.filter_by(email=identifier.lower()).first()
            invitee = Invitee.query.filter_by(email=identifier.lower()).first()

            # Admin case
            if admin:
                if admin.organization:
                    flash(f"Please log in to {admin.organization.name}.", "info")
                    return redirect(url_for('inv.login', org_uuid=admin.organization.uuid))
                elif admin.is_super_admin:
                    first_org = Organization.query.first()
                    if first_org:
                        flash("Super Admin found. Please log in with your credentials.", "info")
                        return redirect(url_for('app_.login', org_uuid=first_org.uuid))
                    else:
                        flash("Super Admin found, but no organization is available.", "danger")
                        return render_template("universal_login.html", form=form)
                else:
                    flash("Admin found, but not linked to any organization.", "danger")
                    return render_template("universal_login.html", form=form)

            # Invitee case
            elif invitee:
                org = invitee.organization
                if org:
                    flash(f"Invitee found. Please log in to {org.name}.", "info")
                    return redirect(url_for('inv.invitee_manual_login', org_uuid=org.uuid))
                else:
                    flash("Invitee account found, but not linked to an organization.", "danger")
                    return render_template("universal_login.html", form=form)

            else:
                flash("No account found with that email address.", "danger")

        else:
            # Identifier isn’t an email or a valid org slug
            flash("Invalid organization name/slug or email. Please try again.", "danger")

    return render_template("universal_login.html", form=form)


# # Routes

@app_.route('/super/login', methods=['GET', 'POST'])
def super_login():
    form = LoginForm()

    org = Organization.query.all()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(email=form.email.data).first()

        if admin and admin.check_password(form.password.data):
            if admin.is_super_admin:
                login_user(admin)
                # session['user_role'] = "admin" 
                # session['org_uuid'] = str(org.uuid)
                # session['admin_id'] = admin.id
                 # ✅ Update last login
                admin.last_login = datetime.utcnow()
                db.session.commit()
                flash('Login successful!', 'success')
                return redirect(url_for('admin.management_dashboard'))
            flash('Unauthorized access to this organization.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('super_login.html',form=form, org=org)



# login
@app_.route('/<uuid:org_uuid>/login', methods=['GET', 'POST'])
def login(org_uuid):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    form = LoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(email=form.email.data.strip().lower(), organization_id=org.id).first()
        # Also allow super_admin to login to any org by email (check separately)
        if not admin:
            admin = Admin.query.filter_by(email=form.email.data.strip().lower(), role='super_admin').first()

        if admin and admin.check_password(form.password.data):
            # check org access
            if admin.is_super_admin or admin.organization_id == org.id:
                login_user(admin, remember=form.remember_me.data)
                session['user_role'] = "admin"
                session['org_uuid'] = str(org.uuid)
                admin.last_login = datetime.utcnow()
                db.session.commit()
                flash('Login successful!', 'success')
                if admin.is_super_admin:
                    return redirect(url_for('admin.management_dashboard', org_uuid=org.uuid))
                else:
                    return redirect(url_for('inv.show_event_invitees', org_uuid=org.uuid))
            else:
                flash('Unauthorized access to this organization.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html', form=form, org=org)


@app_.route('/login/<token>')
def login_with_token(token):
    email = verify_reset_token(token)
    if not email:
        flash("Invalid or expired login link.", "danger")
        return redirect(url_for("inv.universal_login"))

    admin = Admin.query.filter_by(email=email).first()
    if not admin:
        flash("Admin account not found.", "danger")
        return redirect(url_for("inv.universal_login"))

    login_user(admin)
    flash(f"Welcome back {admin.name}!", "success")
    # redirect to latest event for the admin's org or event list
    if admin.organization:
        event = Event.query.filter_by(organization_id=admin.organization.id).order_by(Event.start_time.desc()).first()
        if event:
            return redirect(url_for("inv.show_invitee_event", org_uuid=admin.organization.uuid, event_id=event.id))
        return redirect(url_for("inv.show_event_invitees", org_uuid=admin.organization.uuid))
    return redirect(url_for("inv.universal_login"))


# -----------------------------
# GOOGLE LOGIN (Invitee)
# -----------------------------
@app_.route('/<uuid:org_uuid>/login/google')
def login_with_google(org_uuid):
    
    """   Redirect invitee to Google OAuth login.   Flask-Dance handles the redirect.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    if not google.authorized:
        # Redirect to Google login route handled by Flask-Dance
        return redirect(url_for("inv.google.login",org=org))

    # If already authorized, continue directly to callback handler
    return redirect(url_for("inv.google_auth_callback", org_uuid=org_uuid))


@app_.route('/<uuid:org_uuid>/login/google/callback')
def google_auth_callback(org_uuid):
    """
    Handle Google OAuth callback for invitee login.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    # Fetch user info from Google
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch Google user info.", "danger")
        return redirect(url_for("inv.invitee_manual_login", org_uuid=org_uuid))

    user_info = resp.json()
    email = user_info.get("email")
    name = user_info.get("name", "Guest")

    # Check if invitee exists for this organization
    invitee = Invitee.query.filter_by(email=email, organization_id=org.id).first()
    if not invitee:
        # Optionally auto-create invitee
        invitee = Invitee(
            name=name,
            email=email,
            organization_id=org.id,
        )
        db.session.add(invitee)
        db.session.commit()

    # Log user in
    login_user(invitee)
    flash(f"Welcome back, {invitee.name}!", "success")
    
    # Redirect to their event list
    return redirect(url_for("inv.invitee_event_profile", org_uuid=org.uuid))


# MANUAL LOGIN (Email or Phone)
@app_.route('/<uuid:org_uuid>/invitee/login', methods=['GET', 'POST'])
def invitee_manual_login(org_uuid):

    form = LoginForm()
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    event=Event.query.filter_by(organization_id=org.id).first_or_404()

    if form.validate_on_submit():
        
        invitee = Invitee.query.filter(Invitee.email == form.email.data,Invitee.organization_id == org.id
        ).first()

        if invitee and invitee.check_password(form.password.data):
                
            login_user(invitee, remember=form.remember_me.data) # <-- CRUCIAL CHANGE
            session['user_role'] = "invitee"
            session['org_uuid'] = str(org.uuid)
            flash('Login successful!', 'success')
            db.session.commit()
        
        if invitee:
            # login_user(invitee)
            flash(f"Welcome back, {invitee.name}!", "success")
            return redirect(url_for('inv.invitee_event_profile',event_id=event.id, event=event, org_uuid=org.uuid))
        else:
            flash("Invitee not found. Please register on-site.", "danger")
            return redirect(url_for('inv.register_on_site', org_uuid=org.uuid, event_id=event.id, event=event))

    return render_template("invitee_login.html", form=form, org=org)


@app_.route('/<uuid:org_uuid>/logout')
@login_required
def logout(org_uuid):
    logout_user()
    flash('You have been logged out!', 'success')
    # Redirect based on the user type
    if hasattr(current_user, 'is_invitee') and current_user.is_invitee:
        # Invitee → back to manual login page
        return redirect(url_for('inv.invitee_manual_login', org_uuid=org_uuid))
    else:
        # Admin/org-admin → normal admin login
        return redirect(url_for('inv.login', org_uuid=org_uuid))


@app_.route('/logout')
@login_required
def logout_super():
    logout_user()
    flash('You have been logged out!', 'success')
    return redirect(url_for('inv.super_login'))



######################...helper...#########################
#Helper Function for Logging Actions

def log_action(action_type, user_id, record_type=None, record_id=None,event_id=None, associated_org_id=None):
    if user_id is None:
        user_id = "Anonymous"  # Or any default value
    
    try:
        # Log all actions to ActionLog
        action_log = ActionLog(
            action_type=action_type,
            user_id=user_id,
            record_type=record_type,
            record_id=record_id,
            event_id=event_id,
            organization_id=associated_org_id  # 
        )
        db.session.add(action_log)
        
        # Log deletions to DeleteLog
        if action_type == 'delete':
            if not record_type or not record_id:
                raise ValueError("record_type and record_id must be provided for deletions.")
                
            delete_log = DeleteLog(
                record_type=record_type,
                record_id=record_id,
                deleted_by=user_id
            )
            db.session.add(delete_log)
        
        db.session.commit()
        print(f"Logged {action_type} action by user {user_id} on {record_type} ID {record_id}")
    except Exception as e:
        db.session.rollback()
        print(f"Error logging action: {e}")


##################################################
# ............delete function..................

# Remove from event

@app_.route('/<uuid:org_uuid>/del_event_invitee/<int:event_id>/<int:invitee_id>', methods=['GET','POST'])
@org_admin_or_super_required
def del_event_invitee(org_uuid, event_id, invitee_id):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    # event & invitee must belong to org
    event = Event.query.filter_by(id=event_id, organization_id=org.id).first_or_404()
    invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first_or_404()
    link = EventInvitee.query.filter_by(event_id=event.id, invitee_id=invitee.id).first()

    if not link:
        return jsonify({'status': 'error', 'message': 'Invitee not registered'}), 404


    if request.method == 'POST':
        try:
            csrf_token = request.headers.get('X-CSRFToken')
            validate_csrf(csrf_token)

            db.session.delete(link)
            db.session.commit()

            log_action(
               'remove invitee from event',
                user_id=current_user.id if current_user.is_authenticated else None,
                record_type='invitee',
                record_id=invitee.id,
                associated_org_id=org.id
            )
            
            return jsonify({'status': 'success','message': f"Invitee {invitee.name} removed from event {event.name}."}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'Error removing invitee', 'message': str(e)}), 400

        
# Delete completely

@app_.route('/<uuid:org_uuid>/del_invitee/<int:invitee_id>', methods=['GET','POST'])
@org_admin_or_super_required
def del_invitee(org_uuid, invitee_id):
    
    current_app.logger.info(f"DELETE INVITEE HIT org={org_uuid}, invitee={invitee_id}, user ={current_user.id if current_user.is_authenticated else 'anon'}")
     
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    
    is_authorized = False
    
    if current_user.is_super_admin:
            is_authorized = True
    elif current_user.is_org_admin and current_user.organization_id == org.id:
            is_authorized = True
        
    if not is_authorized:
        flash('You do not have the required permissions to delete invitees.', 'danger')
            # Redirect to a login page or a general unauthorized page
        return redirect(url_for('inv.universal_login')) # Assuming 'universal_login' is your generic login/dashboard


    invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first_or_404()
    
    if not invitee:
        return jsonify({'status': 'error', 'message': 'Invitee or event not found'}), 404

    if request.method == 'POST':
        try:
            csrf_token = request.headers.get('X-CSRFToken')
            validate_csrf(csrf_token)

            db.session.delete(invitee)  # cascades to EventInvitee
            db.session.commit()
            current_app.logger.info(f"Invitee{invitee.id} ({invitee.name}) deleted from DB permamnently.")

            log_action(
                'delete invitee',
                user_id=current_user.id if current_user.is_authenticated else None,
                record_type='invitee',
                record_id=invitee.id,
                associated_org_id=org.id
            )

            #permanently deleted.", "success")
            return jsonify({'status': 'success','message': f"Invitee {invitee.name} permanently deleted."}), 200
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"error deleting invitee{invitee_id}: {str(e)}")

            return jsonify({'status': 'error', 'message': str(e)}), 400
            
            
         
##################################################
# ............mark attendance function by Admins..................

@app_.route('/<uuid:org_uuid>/mark_invitee/<int:event_id>/<int:invitee_id>', methods=['POST'])
@admin_or_super_required
def mark_invitee(org_uuid,event_id,invitee_id):
    
    """Admins confirm or mark invitees attendance for a specific event.
    - Super Admin: can mark attendance for any invitee in any org.
    - Org Admin: can mark for invitees within their own org.
    - Location Admin: can only mark if they are assigned to the same location as the event.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    event=Event.query.filter_by(id=event_id, organization_id=org.id).first_or_404()
    invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first_or_404()

    today =datetime.utcnow().date()

    # --- Role based access ---
    is_authorized = False

    if current_user.is_super_admin:
        is_authorized = True
    elif current_user.is_org_admin and current_user.organization_id == org.id:
        is_authorized = True
    elif current_user.is_location_admin and current_user.organization_id == org.id:
        # Require location match for location admin
        if getattr(current_user, "location_id", None) and getattr(event, "location_id", None):
            if str(current_user.location_id) == str(event.location_id):
                is_authorized = True

    if not is_authorized:
        current_app.logger.info(f"[AUTH FAIL] user={current_user.id}, role=location_admin,"
                                f"user_loc= {getattr(current_user, 'location_id', None)},event_loc={getattr(event,'location_id',None)}")
                               
        return jsonify({'status': 'error',
            'message': 'Permission denied, because You are currently not in the location of event.'
        }), 403
    
        #ensure check in date is valid
    if not (event.start_time.date() <= today <= event.end_time.date()):
        return jsonify({'status': 'error',
            'message': 'Event is not active today.'
        }), 400
    
    #check for duplication checkin today
    existing = Attendance.query.filter_by(event_id=event.id, invitee_id=invitee.id, attendance_date=today).first()
    if existing:
        return jsonify({'status': 'error','message': f'Already marked present today on {today}.'
        }), 400
    
    #record attendance
    attendance = Attendance(organization_id=org.id,event_id=event.id, invitee_id=invitee.id,attendance_date=today,check_in_time=datetime.utcnow())
    db.session.add(attendance)
    
    # --- CSRF validation ---
    try:
        csrf_token = request.headers.get('X-CSRFToken')
        validate_csrf(csrf_token)
    except Exception:
        return jsonify({'status': 'error', 'message': 'CSRF token missing or invalid.'}), 403

    # Perform Attendance Marking Logic
    try:

        # Ensure the invitee is actually registered for the event
        link = EventInvitee.query.filter_by(event_id=event.id, invitee_id=invitee.id).first_or_404()
        
        if link:
            # return jsonify({'status': 'error', 'message': 'Invitee has already been marked Present'}), 400
        # Update event-specific attendance too
            link.status = 'Present'
            link.responded_at = datetime.utcnow()
            current_app.logger.info("Registration failed","info")

            # Prevent re-marking if already 'Present'
            # if invitee.confirmed and invitee.confirmed.lower() == 'Present' or (link.status and link.status.lower() == 'present'):
            #     return jsonify({'status': 'error', 'message': 'Invitee has already been marked as Present'}), 400
        
        # update invitee-confirmed  (summary flag)
        if invitee.confirmed != 'Present':
            invitee.confirmed = 'Present'
            invitee.confirmation_date = datetime.utcnow()

        db.session.commit()
        
        log_action('mark_attendance', user_id=current_user.id if current_user.is_authenticated else None,
            record_type='invitee',record_id=invitee.id,
            # extra_data={'event_id': event.id},
            associated_org_id=org.id)
        
        return jsonify({'status': 'success', 'message': f'{invitee.name} marked Present for {event.name}'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


###########################################################
# manual..........

@app_.route('/<uuid:org_uuid>/<int:event_id>/attendance/confirm', methods=['GET', 'POST'])
def confirm_attendance(org_uuid, event_id):
    """Invitees self-mark attendance and must be in the location"""
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    event = Event.query.filter_by(id=event_id, organization_id=org.id).first_or_404()
    org_locations = Location.query.filter_by(organization_id=org.id).all()

    form = AttendanceForm()

    if form.validate_on_submit():
        phone_number = form.phone_number.data.strip()
        # normalized_phone = normalize_phone(raw_phone, default_country_code="+234")
        user_latitude = form.latitude.data
        user_longitude = form.longitude.data

        # 1️⃣ Find invitee
        invitee = Invitee.query.filter_by(
            phone_number=phone_number, 
            organization_id=org.id
        ).first()

        # 2️⃣ Not found at all → new user (redirect to register page)
        if not invitee:
            flash("You’re not found in our records. Please register first.", "danger")
            return redirect(url_for('inv.register_on_site', org_uuid=org.uuid, event_id=event.id))

        # 3️⃣ Found but not linked to event → show “not registered for event”
        link = EventInvitee.query.filter_by(
            invitee_id=invitee.id, event_id=event.id
        ).first()

        if not link:
            return render_template(
                'invitee_status.html',
                org_uuid=org.uuid,
                status='not_registered',
                event=event,
                invitee=invitee,
                message=f"You are not registered for this event."
            )

        # 4️⃣ Date validation
        today = datetime.utcnow().date()
        if not (event.start_time.date() <= today <= event.end_time.date()):
            return render_template(
                'invitee_status.html',
                org_uuid=org.uuid,
                status='invalid_date',
                event=event,
                invitee=invitee,
                message=f"Attendance can only be confirmed between "
                        f"{event.start_time.strftime('%Y-%m-%d')} and {event.end_time.strftime('%Y-%m-%d')}."
            )

        # 5️⃣ Prevent duplicate check-in
        existing = Attendance.query.filter_by(
            event_id=event.id,
            invitee_id=invitee.id,
            attendance_date=today
        ).first()

        if existing:
            return render_template(
                'invitee_status.html',
                org_uuid=org.uuid,
                status='already_confirmed',
                event=event,
                invitee=invitee,
                message=f"Attendance already confirmed today ({today.strftime('%Y-%m-%d')})."
            )

        # 6️⃣ Verify location range
        user_location = (user_latitude, user_longitude)
        is_within_range = False
        closest_location = None
        min_distance = float('inf')

        for location in org_locations:
            if location.latitude and location.longitude:
                venue_location = (location.latitude, location.longitude)
                distance = geodesic(venue_location, user_location).meters
                if distance < min_distance:
                    min_distance = distance
                    closest_location = location
                if distance <= 100:
                    is_within_range = True
                    break

        if not is_within_range:
            return render_template(
                'invitee_status.html',
                org_uuid=org.uuid,
                status='out_of_range',
                event=event,
                invitee=invitee,
                message=f"You are not within the event location. "
                        f"You are {min_distance:.0f}m away from the nearest venue.",
                distance=min_distance,
                closest_location=closest_location.name if closest_location else "Unknown"
            )

        # 7️⃣ Record attendance
        attendance = Attendance(
            organization_id=org.id,
            event_id=event.id,
            invitee_id=invitee.id,
            attendance_date=today,
            check_in_time=datetime.utcnow()
        )
        db.session.add(attendance)

        # 8️⃣ Update invitee status
        invitee.latitude = user_latitude
        invitee.longitude = user_longitude
        invitee.confirmed = 'Present'
        invitee.status = 'confirmed'
        invitee.confirmation_date = datetime.utcnow()

        try:
            db.session.commit()
            log_action(
                'Invitee Confirmed Attendance',
                user_id=current_user.id if current_user.is_authenticated else None,
                record_type='invitee',
                event_id=event.id,
                record_id=invitee.id,
                organization_id=org.id
            )

            return render_template(
                'invitee_status.html',
                org_uuid=org.uuid,
                status='confirmed',
                event=event,
                invitee=invitee,
                message="Attendance marked successfully.",
                location_name=closest_location.name if closest_location else "Event Location"
            )
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred while confirming attendance. ({str(e)})", "danger")
            return redirect(url_for('inv.confirm_attendance', org_uuid=org.uuid, event_id=event.id))

    # Fallback GET
    return render_template(
        'confirm_attendance.html',
        org_uuid=org.uuid,
        org=org,
        form=form,
        event=event,
        locations=org_locations
    )

###############################################

def generate_qr_code(content: str):

#   # Generate the correct URL using Flask's url_for
    # for non-transparent constants.ERROR_CORRECT_L
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.
        constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )

    qr.add_data(content)
    qr.make(fit=True)
    #apply color
    img = qr.make_image(fill_color='black', back_color='white').convert("RGBA")
    
    #make bg transparent
    datas = img.getdata()
    new_data = []
    for item in datas:
        #changinging pixels
        if item[0] > 240 and item[1] > 240 and item[2] > 240:
            new_data.append((255,255,255,0))
        else:
            new_data.append(item)
    img.putdata(new_data)

    #if you dont want image saved on your server permanently
    byte_arr = io.BytesIO()
    img.save(byte_arr, format='PNG')
    byte_arr.seek(0)
    return base64.b64encode(byte_arr.getvalue()).decode('utf-8')

###################################################

# generate Qr for poster
def generate_event_qr(org_uuid,event_id, invitee_id=None):
    
    s= get_serializer()
    payload = {"event_id": event_id}
    if invitee_id:
        payload["invitee_id"] =invitee_id
    token= s.dumps(payload)

    data = url_for('inv.confirm_qr_code_self',org_uuid=org_uuid, token=token,_external=True)
    # Generate event URL for confirmation
    folder = os.path.join(current_app.root_path,'static','qrcodes')
    os.makedirs(folder, exist_ok=True)
    
    filename=f'event_{event_id}_qr.png' if not invitee_id else f"invitee_{invitee_id}_event_{event_id}.png"
    filepath = os.path.join(folder,filename)
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.
        constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )

    qr.add_data(data)
    qr.make(fit=True)
    #apply color
    img = qr.make_image(fill_color='black', back_color='white').convert("RGBA")
    
    #make bg transparent
    datas = img.getdata()
    new_data = []
    for item in datas:
        #changinging pixels
        if item[0] > 240 and item[1] > 240 and item[2] > 240:
            new_data.append((255,255,255,0))
        else:
            new_data.append(item)
    img.putdata(new_data)

    try:
        img.save(filepath)
    except Exception as e:
        current_app.logger.warning(f"Error saving QR: {e}")
    #return url path flask can serve
    return url_for('static', filename=f'qrcodes/{filename}', _external=True)


#qr link for invitation on event page
@app_.route('/<uuid:org_uuid>/generate_qr/<int:event_id>', methods =['GET'])
@login_required
def generate_qr_link(org_uuid, event_id):
    """GENERATE A EVENT QR LINK FOR ALL INVITEES TO SCAN"""
    s=get_serializer()
    token= s.dumps({"event_id":event_id})
    # this is the target link embedded in the qr
    qr_target_link = url_for('inv.confirm_qr_code_self', org_uuid=org_uuid, token=token, _external=True)

    qr_path = generate_event_qr(org_uuid, event_id,invitee_id=None)
    return jsonify({"qr_image":qr_path, "qr_link":qr_target_link})

####################################################

#Qr for onsite attendance
# generate a venue (onsite) attendance QR code
def generate_attendance_qr(org_uuid, event_id):
    attendance_url = url_for(
        'inv.confirm_attendance',
        org_uuid=org_uuid, event_id=event_id,
        _external=True
    )

    #creating QR object
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.
        constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )

    qr.add_data(attendance_url)
    qr.make(fit=True)
    #apply color
    qr_img = qr.make_image(fill_color='blue', back_color='white').convert("RGBA")
    
    #make bg transparent
    datas = qr_img.getdata()
    new_data = []
    for item in datas:
        #changinging pixels
        if item[0] > 240 and item[1] > 240 and item[2] > 240:
            new_data.append((255,255,255,0))
        else:
            new_data.append(item)
    qr_img.putdata(new_data)

    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    buffer.seek(0)
    qr_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{qr_b64}"


########################################
# @app_.route('/<uuid:org_uuid>/register', methods=['GET', 'POST'])
# def register(org_uuid):
#     org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

#     # Only upcoming events
#     upcoming_events = Event.query.filter(
#         Event.organization_id == org.id,
#         Event.start_time >= datetime.utcnow(),
#         Event.is_active.is_(True),
#         Event.status.in_(["upcoming", "pending"])
#     ).order_by(Event.start_time).all()

    
#     form = InviteeForm()
#     if form.state.data:
#         form.lga.choices = [(lga, lga) for lga in fetch_lgas(form.state.data)]

#     existing_invitee = None
#     registered_event_ids = []

#     # Prefill if existing
#     if request.method == "GET":
#         email = request.args.get("email")
#         phone = request.args.get("phone")
#         if email or phone:
#             existing_invitee = Invitee.query.filter(
#                 Invitee.organization_id == org.id,
#                 or_(
#                     Invitee.email == (email.lower() if email else None),
#                     Invitee.phone_number == phone
#                 )
#             ).first()
#             if existing_invitee:
#                 form = InviteeForm(obj=existing_invitee)
#                 registered_event_ids = [link.event_id for link in existing_invitee.event_links]

#     if form.validate_on_submit():
#         email = form.email.data.lower().strip()
#         phone = form.phone_number.data.strip()
#         # raw_phone = form.phone_number.data.strip()
#         # phone = normalize_phone(raw_phone, default_country_code="+234")
 

#         invitee = Invitee.query.filter(
#             Invitee.organization_id == org.id,
#             or_(Invitee.email == email, Invitee.phone_number == phone)
#         ).first()

#         import secrets
#             # Generate and hash temporary password
#         temp_password = secrets.token_urlsafe(8)
#         hashed_password = generate_password_hash(temp_password)
        
#         if invitee:
#             # Update profile
#             invitee.name = form.name.data.title()
#             invitee.email = email
#             invitee.phone_number = phone
#             invitee.address = form.address.data
#             invitee.state = form.state.data
#             invitee.lga = form.lga.data
#             invitee.gender = form.gender.data
#             invitee.position = form.position.data.title()
#         else:
#             invitee = Invitee(
#                 name=form.name.data.title(),
#                 email=email,
#                 phone_number=phone,
#                 address=form.address.data,
#                 state=form.state.data,
#                 lga=form.lga.data,
#                 gender=form.gender.data,
#                 position=form.position.data.title(),
#                 register_date=datetime.utcnow(),
#                 organization_id=org.id
#             )
    

#             # creating default password
#             invitee.set_password(temp_password) # password temporarily
#             db.session.add(invitee)
#             db.session.flush()  # so invitee.id is available

                  
#         # Event registration
#         event_id = request.form.get("event_id")
#         if event_id:
#             event = Event.query.get(int(event_id))
#             if not event or event.organization_id != org.id or event.start_time < datetime.utcnow():
#                 flash("Invalid or expired event selected.", "danger")
#                 return redirect(url_for('inv.register', org_uuid=org.uuid))

#             #  Check for duplicate using relationship
#             already_registered = any(link.event_id == event.id for link in invitee.event_links)
#             if already_registered:
#                 s = get_serializer()
#                 token = s.dumps({"invitee_id": invitee.id, "event_id": event.id})

#                 flash(f"You are already registered for '{event.name}'.", "info")
#                 return redirect(url_for("inv.success", org_uuid=org.uuid, token=token))

#             # Create secure token
#             s = get_serializer()
#             token = s.dumps({"invitee_id": invitee.id, "event_id": event.id})

#             # Create new registration
           
#             qr_url = url_for(
#                 "inv.confirm_qr_code_self",
#                 org_uuid=org.uuid,
#                 token=token,
#                 _external=True
#             )

#             link = EventInvitee(
#                 event_id=event.id,
#                 invitee_id=invitee.id,
#                 status="accepted",
#                 responded_at=datetime.utcnow(),
#                 qr_code_path=qr_url
#             )
#             db.session.add(link)

#             try:
#                 db.session.commit()
#                 send_qr_code_email(invitee, qr_url, org,temp_password)
               
#                 flash("Registration successful! Please check your email for the QR code.", "success")
#             except Exception as e:
#                 db.session.rollback()
#                 current_app.logger.error(f"Registration failed: {e}")
#                 flash("An error occurred during registration. Please Check your Internet and try again.", "danger")
#                 return redirect(url_for('inv.register', org_uuid=org.uuid))

#         return redirect(url_for("inv.success", org_uuid=org.uuid, token=token))

#     elif request.method == "POST":
#         current_app.logger.warning(f"Form validation failed: {form.errors}")

#     return render_template(
#         "register.html",
#         form=form,
#         org=org,
#         org_uuid=org.uuid,
#         upcoming_events=upcoming_events,
#         existing_invitee=existing_invitee,
#         registered_event_ids=registered_event_ids,
#     )


@app_.route('/<uuid:org_uuid>/register', methods=['GET', 'POST'])
def register(org_uuid):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    # Only upcoming events
    upcoming_events = Event.query.filter(
        Event.organization_id == org.id,
        Event.start_time >= datetime.utcnow(),
        Event.is_active.is_(True),
        Event.status.in_(["upcoming", "pending"])
    ).order_by(Event.start_time).all()

    form = InviteeForm()
    if form.state.data:
        form.lga.choices = [(lga, lga) for lga in fetch_lgas(form.state.data)]

    existing_invitee = None
    registered_event_ids = []

    # Prefill form if GET with email/phone
    if request.method == "GET":
        email = request.args.get("email")
        phone = request.args.get("phone")
        if email or phone:
            existing_invitee = Invitee.query.filter(
                Invitee.organization_id == org.id,
                or_(
                    Invitee.email == (email.lower() if email else None),
                    Invitee.phone_number == phone
                )
            ).first()
            if existing_invitee:
                form = InviteeForm(obj=existing_invitee)
                registered_event_ids = [link.event_id for link in existing_invitee.event_links]

    token = None  # initialize token to ensure it's always defined

    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        phone = form.phone_number.data.strip()
        import secrets
        temp_password = secrets.token_urlsafe(8)

        invitee = Invitee.query.filter(
            Invitee.organization_id == org.id,
            or_(Invitee.email == email, Invitee.phone_number == phone)
        ).first()

        if invitee:
            # Update existing invitee
            invitee.name = form.name.data.title()
            invitee.email = email
            invitee.phone_number = phone
            invitee.address = form.address.data
            invitee.state = form.state.data
            invitee.lga = form.lga.data
            invitee.gender = form.gender.data
            invitee.position = form.position.data.title()
        else:
            # Create new invitee
            invitee = Invitee(
                name=form.name.data.title(),
                email=email,
                phone_number=phone,
                address=form.address.data,
                state=form.state.data,
                lga=form.lga.data,
                gender=form.gender.data,
                position=form.position.data.title(),
                register_date=datetime.utcnow(),
                organization_id=org.id
            )
            invitee.set_password(temp_password)
            db.session.add(invitee)
            db.session.flush()  # to get invitee.id

        # Event registration
        event_id = request.form.get("event_id")
        if event_id:
            event = Event.query.get(int(event_id))
            if not event or event.organization_id != org.id or event.start_time < datetime.utcnow():
                flash("Invalid or expired event selected.", "danger")
                return redirect(url_for('inv.register', org_uuid=org.uuid))

            already_registered = any(link.event_id == event.id for link in invitee.event_links)
            s = get_serializer()
            token = s.dumps({"invitee_id": invitee.id, "event_id": event.id})

            if already_registered:
                flash(f"You are already registered for '{event.name}'.", "info")
                return redirect(url_for("inv.success", org_uuid=org.uuid, token=token))

            qr_url = url_for(
                "inv.confirm_qr_code_self",
                org_uuid=org.uuid,
                token=token,
                _external=True
            )

            link = EventInvitee(
                event_id=event.id,
                invitee_id=invitee.id,
                status="accepted",
                responded_at=datetime.utcnow(),
                qr_code_path=qr_url
            )
            db.session.add(link)

        # Commit DB and send email
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Registration failed: {e}")
            flash("An error occurred during registration. Please try again.", "danger")
            return redirect(url_for('inv.register', org_uuid=org.uuid))

        # Send email separately, don't block registration
        if event_id and token:
            try:
                send_qr_code_email(invitee, qr_url, org, temp_password)
            except Exception as e:
                current_app.logger.error(f"Email sending failed: {e}")
                flash("Registration successful, but email could not be sent.", "warning")
                return redirect(url_for("inv.success", org_uuid=org.uuid, token=token))

        flash("Registration successful! Please check your email for the QR code.", "success")
        if token:
            return redirect(url_for("inv.success", org_uuid=org.uuid, token=token))
        else:
            flash("Registration completed, but no event was selected.", "info")
            return redirect(url_for('inv.register', org_uuid=org.uuid))

    elif request.method == "POST":
        current_app.logger.warning(f"Form validation failed: {form.errors}")

    return render_template(
        "register.html",
        form=form,
        org=org,
        org_uuid=org.uuid,
        upcoming_events=upcoming_events,
        existing_invitee=existing_invitee,
        registered_event_ids=registered_event_ids,
    )


@app_.route('/<uuid:org_uuid>/event/<int:event_id>/register_on_site', methods=['GET', 'POST'])
def register_on_site(org_uuid, event_id):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    event = Event.query.filter_by(id=event_id, organization_id=org.id).first_or_404()
    # Get the organization's location(s)
    org_locations = Location.query.filter_by(organization_id=org.id).all()
   

    # Allow registration only during the event period
    today = datetime.utcnow().date()
    if not (event.start_time.date() <= today <= event.end_time.date()):
        flash("On-site registration is only available during the event period.", "danger")
        return redirect(url_for('inv.register', org_uuid=org_uuid))

    form = InviteeForm()
    if form.state.data:
        form.lga.choices = [(lga, lga) for lga in fetch_lgas(form.state.data)]

    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        phone = form.phone_number.data.strip()
        user_latitude = form.latitude.data
        user_longitude = form.longitude.data

        invitee = Invitee.query.filter(
            Invitee.organization_id == org.id,
            or_(Invitee.email == email, Invitee.phone_number == phone)
        ).first()

        if invitee:
            # Update existing details
            invitee.name = form.name.data.title()
            invitee.email = email
            invitee.phone_number = phone
            invitee.state = form.state.data
            invitee.lga = form.lga.data
            invitee.gender = form.gender.data
            invitee.position = form.position.data.title()
        
        else:
            invitee = Invitee(
                name=form.name.data.title(),
                email=email,
                phone_number=phone,
                address=form.address.data,
                state=form.state.data,
                lga=form.lga.data,
                gender=form.gender.data,
                position=form.position.data.title(),
                register_date=datetime.utcnow(),
                organization_id=org.id
            )
            db.session.add(invitee)
            db.session.flush()

        # Check for existing link
        already_linked = EventInvitee.query.filter_by(
            event_id=event.id, invitee_id=invitee.id
        ).first()

        if not already_linked:
            # Generate QR token
            s = get_serializer()
            token = s.dumps({'invitee_id': invitee.id, 'event_id': event.id})
            qr_url = url_for('inv.confirm_qr_code_self', org_uuid=org.uuid, token=token, _external=True)

            # Create event link + mark attendance
            link = EventInvitee(
                event_id=event.id,
                invitee_id=invitee.id,
                status="accepted",
                responded_at=datetime.utcnow(),
                qr_code_path=qr_url
            )

            db.session.add(link)

                #check for duplication checkin today
            existing = Attendance.query.filter_by(event_id=event.id, invitee_id=invitee.id, attendance_date=today).first()

            if existing:
                return render_template(
                        'invitee_status.html',
                        org_uuid=org.uuid,
                        status='invalid_date',
                        event=event,
                        invitee=invitee,
                        message= f"Attendance already confirmed today {today.strftime('%Y-%m-%d')}."
                        )
                
            # Check distance from any of the organization's locations
            user_location = (user_latitude, user_longitude)
            is_within_range = False
            closest_location = None
            min_distance = float('inf')
            
            for location in org_locations:
                if location.latitude is not None and location.longitude is not None:
                    venue_location = (location.latitude, location.longitude)
                    distance = geodesic(venue_location, user_location).meters
                    
                    # Keep track of the closest location
                    if distance < min_distance:
                        min_distance = distance
                        closest_location = location
                    
                    # Check if within acceptable range (100 meters)
                    if distance <= 100:
                        is_within_range = True
                        break
            
            # If not within range of any location
            if not is_within_range:
                return render_template(
                    'invitee_status.html',
                    org_uuid=org.uuid,
                    status='out_of_range',
                    event=event,
                    invitee=invitee,
                    message=f"You are not within the event location. You are {min_distance:.0f}m away from the nearest venue.",
                    distance=min_distance,
                    closest_location=closest_location.name if closest_location else "Unknown"
                )

            attendance = Attendance(
                organization_id=org.id,
                event_id=event.id,
                invitee_id=invitee.id,
                attendance_date=today,
                check_in_time=datetime.utcnow()
            )
            db.session.add(attendance)

            # Update invitee with confirmation details
            if invitee.confirmed != 'Present':
                invitee.latitude = user_latitude
                invitee.longitude = user_longitude
                invitee.confirmed = 'Present'
                invitee.status = 'confirmed'
                invitee.confirmation_date = datetime.utcnow()
    
            try:
                db.session.commit()
                send_confirm_email(invitee, event, org)
                log_action(
                    'on-site registration',
                    user_id=current_user.id if current_user.is_authenticated else None,
                    record_type='invitee',
                    record_id=invitee.id,
                    associated_org_id=org.id
                )

                return render_template(
                    'invitee_status.html',
                    org_uuid=org_uuid,
                    status='confirmed',
                    invitee=invitee,
                    event=event,
                    org=org,
                    message="You have been successfully registered and marked present. Welcome!"
                )

            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f'On-site registration failed: {e}')
                flash(f'An unexpected error occurred. Please try again.', 'danger')
                return redirect(url_for('inv.register_on_site', org_uuid=org_uuid, event_id=event_id))

        else:
            flash("You are already registered for this event.", "info")
            return redirect(url_for('inv.confirm_attendance', event_id=event.id, org_uuid=org.uuid))

    else:
        if request.method == 'POST':
            current_app.logger.warning(f"Form validation failed: {form.errors}")
            flash("Please check the form and try again.", "danger")

    return render_template('register_on_site.html', form=form, org=org, org_uuid=org_uuid, event=event)


# API LOOKUP

@app_.route('/<uuid:org_uuid>/invitee_lookup')
def invitee_lookup(org_uuid):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    phone = request.args.get("phone")
    email = request.args.get("email")

    if not phone and not email:
        return jsonify({"error": "Provide phone or email"}), 400

    invitee = Invitee.query.filter(
        Invitee.organization_id == org.id,
        or_(Invitee.phone_number == phone, Invitee.email == email.lower() if email else None)
    ).first()

    if not invitee:
        return jsonify({"exists": False})

    return jsonify({
        "exists": True,
        "id": invitee.id,
        "name": invitee.name,
        "email": invitee.email,
        "phone_number": invitee.phone_number,
        "address": invitee.address,
        "state": invitee.state,
        "lga": invitee.lga,
        "gender": invitee.gender,
        "position": invitee.position
    })


##########################################################
@app_.route('/<uuid:org_uuid>/edit_invitee/<int:event_id>/<int:id>', methods=['GET', 'POST'])
@admin_or_super_required
def edit_invitee(org_uuid, id,event_id):
    
    """Edit an existing invitee"""
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
        
    
    state_lgas = fetch_lgas_all()

    # now = datetime.utcnow() # Use UTC for consistency
    # if now < registration_deadline:
    #     flash("Editing invitees is not allowed until the specified deadline.", "danger")
    #     # Consider redirecting to a page that explains the timeline
    #     return redirect(url_for('inv.show_invitees', org_uuid=org.uuid)) # Use org.uuid consistently
    # END deadline check

    is_authorized = False
    
    if current_user.is_super_admin:
        is_authorized = True
    elif current_user.is_org_admin and current_user.organization_id == org.id:
        is_authorized = True
    
    if not is_authorized:
        flash('You do not have the required permissions to edit invitees.', 'danger')
        # Redirect to a login page or a general unauthorized page
        return redirect(url_for('inv.universal_login')) # Assuming 'universal_login' is your generic login/dashboard

    event=Event.query.filter_by(id=event_id, organization_id=org.id).first_or_404()
    invitee = Invitee.query.filter_by(id=id, organization_id=org.id).first_or_404()

    if request.method == 'POST':
        new_name = request.form['name']
        new_position = request.form['position']
        new_phone_number = request.form['phone_number']
        new_state = request.form['state']
        new_lga = request.form['lga']
        

        existing_invitee = (Invitee.query.join(EventInvitee, EventInvitee.invitee_id == Invitee.id).filter(
            Invitee.organization_id == org.id,
            EventInvitee.event_id == event.id,
            Invitee.phone_number==new_phone_number).first())

        if existing_invitee and existing_invitee.id != invitee.id:
            flash('Invitee already exists.', 'danger')
            return redirect(url_for('inv.edit_invitee', org_uuid=org.uuid, id=id,event_id=event.id))

        invitee.name = new_name
        invitee.position = new_position
        invitee.phone_number = new_phone_number
        invitee.state = new_state
        invitee.lga = new_lga
        invitee.updated_at = datetime.utcnow()

        try:
            db.session.commit()
            log_action('edit',user_id=current_user.id if current_user.is_authenticated else None,
            record_type='invitee',record_id=invitee.id,associated_org_id=org.id)
            flash('Invitee updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {e}', 'danger')

        return redirect(url_for('inv.show_invitee_event', org_uuid=org.uuid,event_id=event.id))

    return render_template('edit_invitee.html', org=org, invitee=invitee,state_lgas=state_lgas, org_uuid=org.uuid, event=event)



@app_.route('/<uuid:org_uuid>/feedback-chart', methods=['GET', 'POST'])
# @org_admin_required
def feedback_chart(org_uuid):

    # Get the Organization object using the slug
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    # org = Organization.query.filter_by(uuid=UUID(org_uuid)).first_or_404()

    # Total feedback entries for this organization
    feedback_data = Feedback.query.filter_by(organization_id=org.id).count()

    # Grouped feedback counts by source for this organization
    feedback_counts = db.session.query(
        Feedback.source,
        func.count(Feedback.source)
    ).filter(Feedback.organization_id == org.id) \
     .group_by(Feedback.source).all()

  # Define feedback sources
    source_labels = ['Social Media', 'Email', 'Flyers/Posters', 'Website', 'Friends or Family', 'Other']

    # Count feedback responses per source for this org
    source_counts = [
        Feedback.query.filter_by(organization_id=org.id, source=source).count()
        for source in source_labels
    ]

    labels = [item[0] for item in feedback_counts]  # Categories
    values = [item[1] for item in feedback_counts]  # Counts

    return render_template('feedback-chart.html',org=org, org_uuid=org.uuid, labels=labels, values=values, feedback_data=feedback_data,
                            source_labels=source_labels, source_counts=source_counts, zip=zip_longest)


# today
@app_.route('/<uuid:org_uuid>/submit-feedback', methods=['GET', 'POST'])
def submit_feedback(org_uuid):

    form = FeedbackForm()
    # org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    
    if form.validate_on_submit():

        # Get form data
        email = form.email.data
        name = form.name.data
        source = form.source.data
        comments = form.comments.data
        gender = form.gender.data

        # Check for duplicates
        existing_feedback = Feedback.query.filter_by(email=email).first()

        if existing_feedback:
            flash("Feedback Received already.", "error")
            return redirect(url_for('inv.submit_feedback',org_uuid=org.uuid))
        
        if "@" not in form.email.data:
            flash("Invalid email address.", "error")
            return redirect(url_for('inv.submit_feedback',org_uuid=org.uuid))

        try:
            # Create a new feedback
            new_feedback = Feedback( comments=comments, source=source,name=name, gender=gender, email=email,qr_code_path=None, 
                                    organization_id=org.id, submit_feedback_date= datetime.utcnow())
        
            # Add to session and commit to the database
            db.session.add(new_feedback)
            db.session.commit()

            # Log the action (ensure log_action is correctly implemented)
            log_action('submit', user_id=current_user.id if current_user.is_authenticated else None, record_type='feedback', record_id=new_feedback.id)

            flash("Feedback Received, Thank You!!", "info")
            return redirect(url_for('inv.submit_feedback',org_uuid=org.uuid))

        except Exception as e:
            db.session.rollback()
            flash(f"Error saving to database: {str(e)}", "error")
            return redirect(url_for('inv.submit_feedback',org_uuid=org.uuid))

    return render_template('feedback.html',org=org,org_uuid=org.uuid,form=form)


##########################################################

@app_.route('/<uuid:org_uuid>/success/<token>')
def success(org_uuid, token):
    """
    Displays success page with QR code after invitee registration using secure UUID in URL.
    """

    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    s = get_serializer()
    try:
        data = s.loads(token)  # verify signature
        invitee_id = data["invitee_id"]
        event_id = data["event_id"]
    except Exception:
        flash("Invalid or tampered link.", "danger")
        return redirect(url_for("inv.register", org_uuid=org_uuid,event_id=event_id))
    
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first_or_404()
    
    #get last registered event link
    link=EventInvitee.query.filter_by(invitee_id=invitee.id).order_by(EventInvitee.responded_at.desc()).first()

    if not link:
        flash("No Event Registration found", "warning")
        return redirect(url_for("inv.register", org_uuid=org.uuid))
     
    #generate QRcode image base64 from stored url
    qr_code_path = generate_qr_code(link.qr_code_path)  # Ensure it uses UUID now

    return render_template(
        'success.html',
        org=org,
        invitee=invitee,
        event=link.event,
        qr_code_path=qr_code_path
    )


# automatic
############## admin scans invitee (him/herself) ##########################
@app_.route('/<uuid:org_uuid>/confirm_qr_code_self/<token>', methods=['GET'])
# @admin_or_super_required
@csrf.exempt
def confirm_qr_code_self(org_uuid, token):
    """
    Allows admin to confirm an invitee’s presence using secure UUID-based URL.
    Invitees can also scan the same QR provided they are at the venue/location.
    """

    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    org_locations = Location.query.filter_by(organization_id=org.id).all()

    # ✅ Decode token safely before using event_id
    s = get_serializer()
    try:
        data = s.loads(token)
        invitee_id = data.get("invitee_id")
        event_id = data.get("event_id")
    except Exception:
        flash("Invalid or tampered QR code.", "danger")
        return redirect(url_for("inv.register_on_site", org_uuid=org_uuid))

    # Fetch event
    event = Event.query.filter_by(id=event_id, organization_id=org.id).first_or_404()
    invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first() if invitee_id else None
    today = datetime.utcnow().date()

    # Authorization check
    is_authorized, role = is_authorized_user(current_user, org, event)

    # --- Fix starts here ---
    # Allow both admins *and* invitees to proceed,
    # but block truly unauthorized users (wrong org, wrong event, etc.)
    if not is_authorized and role not in ("invitee", "anonymous"):
        current_app.logger.info(
            f"[AUTH FAIL] user={getattr(current_user, 'id', 'anon')} role={role}, "
            f"user_loc={getattr(current_user, 'location_id', None)}, event_loc={getattr(event, 'location_id', None)}"
        )
        return jsonify({
            'status': 'error',
            'message': 'Permission denied — you are not authorized for this event or location.'
        }), 403
    
    # --- Fix ends here ---
    #If invitee not found — allow onsite registration if event ongoing
    if not invitee:
        if event.start_time.date() <= today <= event.end_time.date():
            flash("Not registered yet. Please complete quick on-site registration to check in.", "warning")
            return redirect(url_for("inv.register_on_site", org_uuid=org_uuid, event_id=event.id))
        else:
            flash("This event is not open for on-site registration.", "danger")
            return redirect(url_for("inv.register", org_uuid=org_uuid))

    # Prevent duplicate check-ins
    existing = Attendance.query.filter_by(
        event_id=event.id, invitee_id=invitee.id, attendance_date=today
    ).first()
    if existing:
        return render_template(
            "invitee_status.html",
            org_uuid=org.uuid,
            status="already_checked_in",
            event=event,
            invitee=invitee,
            message=f"Attendance already confirmed today ({today.strftime('%Y-%m-%d')})."
        )

    # Ensure invitee linked to event
    link = EventInvitee.query.filter_by(invitee_id=invitee.id, event_id=event.id).first()
    if not link:
        flash('Invitee not found for this event.', 'danger')
        return redirect(url_for('inv.register_on_site', org_uuid=org_uuid))
    event = link.event

    # Ensure event date valid
    if not (event.start_time.date() <= today <= event.end_time.date()):
        return render_template(
            'invitee_status.html',
            org_uuid=org.uuid,
            status='invalid_date',
            event=event,
            invitee=invitee,
            message=f"Attendance can only be confirmed between {event.start_time.date()} and {event.end_time.date()}."
        )

    # Check location — only required if NOT admin or authorized staff
    if role in ("super_admin", "org_admin", "location_admin"):
        location_valid = True
    else:
        user_latitude = request.args.get("latitude", type=float)
        user_longitude = request.args.get("longitude", type=float)

        if not user_latitude or not user_longitude:
            # Fall back to manual confirmation by phone
            return redirect(url_for("inv.confirm_attendance", org_uuid=org.uuid, event_id=event.id))

        user_location = (user_latitude, user_longitude)
        is_within_range = False
        closest_location = None
        min_distance = float('inf')

        for location in org_locations:
            if location.latitude and location.longitude:
                venue_location = (location.latitude, location.longitude)
                distance = geodesic(venue_location, user_location).meters
                if distance < min_distance:
                    min_distance = distance
                    closest_location = location
                if distance <= 100:
                    is_within_range = True
                    break

        if not is_within_range:
            return render_template(
                'invitee_status.html',
                org_uuid=org.uuid,
                status='out_of_range',
                event=event,
                invitee=invitee,
                message=f"You are not within the event location. You are {min_distance:.0f}m away from the nearest venue.",
                distance=min_distance,
                closest_location=closest_location.name if closest_location else "Unknown"
            )

    # Record attendance
    attendance = Attendance(
        organization_id=org.id,
        event_id=event.id,
        invitee_id=invitee.id,
        attendance_date=today,
        check_in_time=datetime.utcnow()
    )
    db.session.add(attendance)

    if invitee.deleted:
        return render_template(
            'login.html',
            org_uuid=org_uuid,
            status='deleted',
            invitee=invitee,
            message="This invitee has been removed from the list."
        )

    try:
        if invitee.confirmed != 'Present':
            invitee.confirmed = 'Present'
            invitee.confirmation_date = datetime.utcnow()

        db.session.commit()

        log_action(
            'self confirm invitee via QR',
            user_id=current_user.id if current_user.is_authenticated else None,
            record_type='invitee',
            record_id=invitee.id,
            associated_org_id=org.id
        )

        send_confirm_email(invitee, event, org)

        return render_template(
            'invitee_status.html',
            org_uuid=org.uuid,
            status='confirmed',
            invitee=invitee,
            event=event,
            message="Invitee confirmed successfully ✅."
        )

    except Exception as e:
        db.session.rollback()
        flash(f'An unexpected error occurred: {str(e)}', 'danger')
        return redirect(url_for('inv.index', org_uuid=org_uuid))


########################################################
@app_.route('/<uuid:org_uuid>/status/<int:invitee_id>')
def invitee_status(org_uuid, invitee_id):
    """
    Displays the status page for an invitee using org UUID for better security.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first_or_404()

    return render_template('invitee_status.html', org_uuid=org.uuid, invitee=invitee)

###############################################
@app_.route('/<uuid:org_uuid>/get_qr_code/<int:invitee_id>/<int:event_id>')
def get_qr_code(org_uuid, invitee_id,event_id):
    """
    Returns the QR code path for the invitee using org UUID for security.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first_or_404()
    event = Event.query.filter_by(id=event_id, organization_id=org.id).first_or_404()
       
    # buid unique str to be passed to QR
    qr_content =f"{org.uuid}:{invitee.id}:{event.id}"
    qr_code_path = generate_qr_code(qr_content)
    # qr_code_path = generate_qr_code(org.uuid, invitee.id,event.id)  # Make sure your function supports UUID
    return jsonify({'qr_code_path': qr_code_path})

####################################

@app_.route('/<uuid:org_uuid>/manage_invitee/', methods=['GET', 'POST'])
@org_admin_or_super_required
def manage_all_invitee(org_uuid):
    """
    Allows super admins or org admins to search and manage invitees.
    Super admins can manage all specific organization's invitees.
    Org admins can only manage their own organization's invitees.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    event=Event.query.filter_by(organization_id=org.id).first_or_404()


    # Role-based access control
    if not current_user.is_super_admin:
        if not (current_user.is_org_admin) or current_user.organization_id != org.id:
            flash("You do not have permission to manage invitees for this organization.", "danger")
            return redirect(url_for('inv.login',org_uuid=org.uuid))
    
    # Base query
    invitees_query = Invitee.query.filter_by(deleted=False,organization_id=org.id)
    
    # Search & pagination
    search = request.args.get('search', '', type=str)
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if search:
        invitees_query = invitees_query.filter(
            db.or_(
                Invitee.name.ilike(f'%{search}%'),
                Invitee.email.ilike(f'%{search}%'),
                Invitee.phone_number.ilike(f'%{search}%')
            )
        )
        if invitees_query.count() == 0:
            flash("No invitees found.", "danger")

    pagination = invitees_query.order_by(Invitee.register_date,Invitee.confirmation_date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    invitees = pagination.items

    return render_template('del_inv.html',
        org=org,org_uuid=org.uuid,invitees=invitees,event=event,pagination=pagination,
        search=search, is_super=current_user.is_super)




@app_.route('/<uuid:org_uuid>/invitees')
@org_admin_or_super_required # This decorator already ensures one of the 3 admin types is logged in
def show_invitees(org_uuid):
    """
    Displays invitees for a specific organization,
    filtered by user role and optional search query.
    """

    try:
        # Use str(org_uuid) to ensure consistency with string-based UUIDs from filter_by
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
        event=Event.query.first()

    except ValueError: # This ValueError catch is for if org_uuid couldn't be converted to UUID type
        flash('Invalid organization identifier.', 'danger')
        return redirect(url_for('inv.universal_login')) # Redirect to universal login if UUID is invalid
    
    if event is None:
        flash('You have not create an Event.', 'danger')
        # Use the org.uuid if available for the universal login redirect, but only if it's the target.
        return redirect(url_for('inv.add_event',org_uuid=org.uuid))

    # --- Role-based access control (Refined) ---
    invitees_query = None # Initialize to None

    if current_user.is_super_admin: # Use the correct property name
        # Super Admins can see all invitees for any organization
        invitees_query = Invitee.query.filter_by(organization_id=org.id).options(joinedload(Invitee.event_links).joinedload(EventInvitee.event))
    
    elif current_user.is_org_admin and current_user.organization_id == org.id:
        # Org Admins can only see invitees for their own organization
        invitees_query = Invitee.query.filter_by(organization_id=org.id).options(joinedload(Invitee.event_links).joinedload(EventInvitee.event))
    
    elif current_user.is_location_admin and current_user.organization_id == org.id:
        # Location Admins can see invitees for their specific organization
        # Optionally, add further filtering if they should only see invitees for their specific location
        # For now, let's assume they see all for their org, but you can refine:
        invitees_query = Invitee.query.filter_by(organization_id=org.id).options(joinedload(Invitee.event_links).joinedload(EventInvitee.event))
        # If a Location Admin should ONLY see invitees for THEIR location:
        # if current_user.location_id: # Assuming Admin model has location_id
        #     invitees_query = invitees_query.filter_by(location_id=current_user.location_id)
        # else:
        #     flash("Location Admin without an assigned location cannot view invitees.", "danger")
        #     return redirect(url_for('app_.dashboard_or_some_safe_page')) # Redirect if location not set
    
    # If invitees_query is still None, it means the user passed the @admin_access_required
    # but didn't meet the *specific* criteria for this route's content.
    if invitees_query is None:
        flash('Access denied to this organization’s invitees based on your specific role and organization context.', 'danger')
        # Redirect to a safer, more general admin dashboard or the universal login
        # Use the org.uuid if available for the universal login redirect, but only if it's the target.
        return redirect(url_for('inv.universal_login'))


    # --- Search & filtering ---
    search = request.args.get('search', '', type=str)
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if search:
        # Using .ilike for case-insensitive search
        invitees_query = invitees_query.filter(
            (Invitee.name.ilike(f'%{search}%')) |
            (Invitee.phone_number.ilike(f'%{search}%')) |
            # Check if Invitee.id is integer; if so, convert search to int for direct comparison
            # If Invitee.id is a string, then ilike is fine. Assuming integer ID for now.
            (Invitee.id == int(search) if search.isdigit() else False) # Safer ID search
        )
        # If you want to flash only if no invitees match AND the search query was not empty
        if invitees_query.count() == 0 and search: # Only flash if search was performed and no results
            flash(f'No invitees matched your search for "{search}".', 'info')

    # --- Statistics ---
    # Perform count on the filtered query
    no_invitee_present = invitees_query.filter(Invitee.confirmed == 'Present').count()
    no_invitee_absent = invitees_query.filter(Invitee.confirmed == 'Absent').count()
    no_invitees = invitees_query.count() # Total count after search/filter

    # --- Gender Breakdown: Total ---
    total_male = invitees_query.filter(Invitee.gender == 'Male').count()
    total_female = invitees_query.filter(Invitee.gender == 'Female').count()

    # --- Gender Breakdown: Present ---
    present_male = invitees_query.filter(Invitee.confirmed == 'Present',Invitee.gender == 'Male').count()
    present_female = invitees_query.filter(Invitee.confirmed == 'Present',Invitee.gender == 'Female').count()

    # --- Gender Breakdown: Absent ---
    absent_male = invitees_query.filter(Invitee.confirmed == 'Absent',Invitee.gender == 'Male').count()
    absent_female = invitees_query.filter(Invitee.confirmed == 'Absent',Invitee.gender == 'Female').count()

    # --- Pagination ---
    # Ensure order_by is applied before paginate
    pagination = invitees_query.order_by(Invitee.register_date,Invitee.confirmation_date.desc()).paginate(page=page, per_page=per_page, error_out=False)

    invitees = pagination.items

    # --- Render Template ---
    return render_template('invitees.html',
        org=org,
        org_uuid=str(org.uuid), # Ensure this is a string for URL building if needed in template
        invitees=invitees,
        pagination=pagination,
        no_invitee_present=no_invitee_present,
        no_invitee_absent=no_invitee_absent,
        no_invitees=no_invitees,
        total_male=total_male,
        total_female=total_female,
        present_male=present_male,
        present_female=present_female,
        absent_male=absent_male,
        event=event,
        absent_female=absent_female,
        is_super=current_user.is_super_admin # Pass the correct property to the template
    )

######################################...............

@app_.route('/<uuid:org_uuid>/dashboard_events/<int:event_id>', methods=['GET', 'POST'])
@admin_or_super_required # This decorator already ensures one of the 3 admin types is logged in
def show_invitee_event(org_uuid,event_id):
    
    """
    Displays all invitees for a specific Event in specific organization,
    filtered by user role and optional search query.
    """
    # add invitee access to just events on going and their 
    try:
        # Use str(org_uuid) to ensure consistency with string-based UUIDs from filter_by
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
        event=Event.query.filter_by(id=event_id, organization_id=org.id).first_or_404()


    except ValueError: # This ValueError catch is for if org_uuid couldn't be converted to UUID type
        flash('Invalid organization identifier.', 'danger')
        return redirect(url_for('inv.universal_login')) # Redirect to universal login if UUID is invalid


    # --- Role-based access control (Refined) ---
    invitees_query = None # Initialize to None

    if current_user.is_super_admin: # Use the correct property name
        # Super Admins can see all invitees for any organization
        # --- Base query: invitees for this event only ---
        
        invitees_query = (
        Invitee.query
        .join(EventInvitee, EventInvitee.invitee_id == Invitee.id)
        .filter(
            Invitee.organization_id == org.id,
            Invitee.deleted==False,
            EventInvitee.event_id == event.id
        )
        .options(joinedload(Invitee.event_links).joinedload(EventInvitee.event))
        )
        # deleted=False,
        
    elif current_user.is_org_admin and current_user.organization_id == org.id:
        # Org Admins can only see invitees for their own organization
        invitees_query = (
        Invitee.query
        .join(EventInvitee, EventInvitee.invitee_id == Invitee.id)
        .filter(
            Invitee.deleted==False,
            Invitee.organization_id == org.id,
            EventInvitee.event_id == event.id
        )
        .options(joinedload(Invitee.event_links).joinedload(EventInvitee.event))
         )
    elif current_user.is_location_admin and current_user.organization_id == org.id:
        # Location Admins can see invitees for their specific organization
        # Optionally, add further filtering if they should only see invitees for their specific location
        # For now, let's assume they see all for their org, but you can refine:
        invitees_query = (
        Invitee.query
        .join(EventInvitee, EventInvitee.invitee_id == Invitee.id)
        .filter(
            Invitee.deleted==False,
            Invitee.organization_id == org.id,
            EventInvitee.event_id == event.id
        )
        .options(joinedload(Invitee.event_links).joinedload(EventInvitee.event))
         )
        
        # If a Location Admin should ONLY see invitees for THEIR location:
        # if current_user.location_id: # Assuming Admin model has location_id
        #     invitees_query = invitees_query.filter_by(location_id=current_user.location_id)
        # else:
        #     flash("Location Admin without an assigned location cannot view invitees.", "danger")
        #     return redirect(url_for('app_.dashboard_or_some_safe_page')) # Redirect if location not set
    
    # If invitees_query is still None, it means the user passed the @admin_access_required
    # but didn't meet the *specific* criteria for this route's content.
    if invitees_query is None:
        flash('Access denied to this organization’s invitees based on your specific role and organization context.', 'danger')
        # Redirect to a safer, more general admin dashboard or the universal login
        # Use the org.uuid if available for the universal login redirect, but only if it's the target.
        return redirect(url_for('inv.universal_login'))


    # --- Search & filtering ---
    search = request.args.get('search', '', type=str)
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if search:
        # Using .ilike for case-insensitive search
        invitees_query = invitees_query.filter(
            (Invitee.name.ilike(f'%{search}%')) |
            (Invitee.phone_number.ilike(f'%{search}%')) |
            # Check if Invitee.id is integer; if so, convert search to int for direct comparison
            # If Invitee.id is a string, then ilike is fine. Assuming integer ID for now.
            (Invitee.id == int(search) if search.isdigit() else False) # Safer ID search
        )
        # If you want to flash only if no invitees match AND the search query was not empty
        if invitees_query.count() == 0 and search: # Only flash if search was performed and no results
            flash(f'No invitees matched your search for "{search}".', 'info')

    # --- Statistics ---
    # Perform count on the filtered query
    no_invitee_present = invitees_query.filter(Invitee.confirmed == 'Present').count()
    no_invitee_absent = invitees_query.filter(Invitee.confirmed == 'Absent').count()
    no_invitees = invitees_query.count() # Total count after search/filter

    # --- Gender Breakdown: Total ---
    total_male = invitees_query.filter(Invitee.gender == 'Male').count()
    total_female = invitees_query.filter(Invitee.gender == 'Female').count()

    # --- Gender Breakdown: Present ---
    present_male = invitees_query.filter(Invitee.confirmed == 'Present',Invitee.gender == 'Male').count()
    present_female = invitees_query.filter(Invitee.confirmed == 'Present',Invitee.gender == 'Female').count()

    # --- Gender Breakdown: Absent ---
    absent_male = invitees_query.filter(Invitee.confirmed == 'Absent',Invitee.gender == 'Male').count()
    absent_female = invitees_query.filter(Invitee.confirmed == 'Absent',Invitee.gender == 'Female').count()

    # --- Pagination ---
    # Ensure order_by is applied before paginate
    pagination = invitees_query.order_by(Invitee.register_date,Invitee.confirmation_date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    # pagination = invitees_query.order_by(Invitee.id.desc()).paginate(page=page, per_page=per_page, error_out=False)

    invitees = pagination.items


    # --- Map invitee -> event link ---
    event_links_map = {}
    for invitee in invitees:
        link = next((l for l in invitee.event_links if l.event_id == event.id), None)
        if link:
            event_links_map[invitee.id] = link

    return render_template(
        "event_invitee.html",
        org=org,
        org_uuid=str(org.uuid),
        event=event,
        invitees=invitees,
        pagination=pagination,
        event_links_map=event_links_map,
        no_invitee_present=no_invitee_present,
        no_invitee_absent=no_invitee_absent,
        no_invitees=no_invitees,
        total_male=total_male,
        total_female=total_female,
        present_male=present_male,
        present_female=present_female,
        absent_male=absent_male,
        absent_female=absent_female,
        is_super=current_user.is_super_admin,
    )


@app_.route('/<uuid:org_uuid>/manage_invitee/<int:event_id>', methods=['GET', 'POST'])
@admin_or_super_required
def manage_invitee(org_uuid,event_id):
    """
    Allows super admins or org admins to search and manage invitees.
    Super admins can manage any organization's invitees.
    Org admins can only manage their own organization's invitees.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    event=Event.query.filter_by(id=event_id, organization_id=org.id).first_or_404()
    
    # Role-based access control
    if not current_user.is_super_admin:
        if not (current_user.is_location_admin or current_user.is_org_admin) or current_user.organization_id != org.id:
            flash("You do not have permission to manage invitees for this organization.", "danger")
            return redirect(url_for('inv.login',org_uuid=org.uuid))

    
    # Base query
    invitees_query = (
        Invitee.query
        .join(EventInvitee, EventInvitee.invitee_id == Invitee.id)
        .filter(
            Invitee.deleted==False,
            Invitee.organization_id==org.id, EventInvitee.event_id==event_id))
    
    # Search & pagination
    search = request.args.get('search', '', type=str)
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if search:
        invitees_query = invitees_query.filter(
            db.or_(
                Invitee.email.ilike(f'%{search}%'),
                Invitee.phone_number.ilike(f'%{search}%')
            )
        )
        if invitees_query.count() == 0:
            flash("No invitees found.", "danger")

    pagination = invitees_query.order_by(Invitee.id.desc()).paginate(page=page, per_page=per_page, error_out=False)
    invitees = pagination.items

    return render_template('del_inv.html',
        org=org,org_uuid=org.uuid,invitees=invitees,event=event,pagination=pagination,
        search=search, is_super=current_user.is_super)


# ################################################

@app_.route('/<uuid:org_uuid>/dashboard_events', methods=['GET', 'POST'])
@admin_or_super_required
def show_event_invitees(org_uuid):
    """
    Dashboard: show events for an org (past/upcoming/all) with invitee stats,
    search and pagination.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    # Base events query for this org
    events_query = Event.query.filter_by(organization_id=org.id)

    # Role-based access refinement (optional extra filtering for location_admins)
    if current_user.is_location_admin and current_user.organization_id == org.id:
        # if you want to restrict to specific location_id:
        # if hasattr(current_user, "location_id") and current_user.location_id:
        #     events_query = events_query.filter_by(location_id=current_user.location_id)
        pass

    # --- Filters from query params ---
    date_filter = request.args.get("date", "all")  # values: all | upcoming | past
    
    now = datetime.utcnow()
    
    if date_filter == "upcoming":
        events_query = events_query.filter(Event.start_time >= now)
    elif date_filter == "past":
        events_query = events_query.filter(Event.end_time < now)

    # Search by event name
    search = (request.args.get("search") or "").strip()
    
    if search:
        events_query = events_query.filter(Event.name.ilike(f"%{search}%"))

    # Optional: filter events by invitee name/phone (only show events that have that invitee)
    invitee_search = (request.args.get("invitee") or "").strip()
    if invitee_search:
        events_query = events_query.join(EventInvitee).join(Invitee).filter(
            or_(
                Invitee.name.ilike(f"%{invitee_search}%"),
                Invitee.phone_number.ilike(f"%{invitee_search}%")
            )
        ).distinct()

    # Ordering & paginate
    events_query = events_query.order_by(Event.start_time.desc())

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 5, type=int)
    paginated = events_query.paginate(page=page, per_page=per_page, error_out=False)
    events = paginated.items

    # --- Build stats per event (registered, present, rsvp break down, gender break down) ---
    event_stats = {}
    for ev in events:
        # total registered for this event
        total_registered = db.session.query(func.count(EventInvitee.invitee_id))\
            .filter(EventInvitee.event_id == ev.id)\
            .scalar() or 0

        # total present (status stored on EventInvitee.status)
        total_present = db.session.query(func.count(EventInvitee.invitee_id))\
            .filter(EventInvitee.event_id == ev.id, EventInvitee.status == 'Present')\
            .scalar() or 0

        # RSVP breakdown (status counts)
        rsvp_rows = db.session.query(EventInvitee.status, func.count(EventInvitee.invitee_id))\
            .filter(EventInvitee.event_id == ev.id)\
            .group_by(EventInvitee.status).all()
        rsvp = {row[0]: row[1] for row in rsvp_rows}

        # Gender breakdown of registered invitees (join invitee)
        gender_rows = db.session.query(Invitee.gender, func.count(Invitee.id))\
            .join(EventInvitee, Invitee.id == EventInvitee.invitee_id)\
            .filter(EventInvitee.event_id == ev.id)\
            .group_by(Invitee.gender).all()
        gender = {row[0] or "Unknown": row[1] for row in gender_rows}

        event_stats[ev.id] = {
            "total_registered": int(total_registered),
            "total_present": int(total_present),
            "rsvp": rsvp,
            "gender": gender
        }

    # --- overall quick stats for the page (optional) ---
    total_events = events_query.count()
    total_registrations = db.session.query(func.count(EventInvitee.invitee_id))\
        .join(Event, Event.id == EventInvitee.event_id)\
        .filter(
        # Invitee.deleted==False,
        Event.organization_id == org.id).scalar() or 0

    return render_template(
        "dashboard_events.html",
        org=org,
        events=events,
        pagination=paginated,
        event_stats=event_stats,
        total_events=total_events,
        total_registrations=int(total_registrations),
        search=search,
        invitee_search=invitee_search,
        date_filter=date_filter,
    )

# 

@app_.route('/<uuid:org_uuid>/invitee_event_profile', methods=['GET'])
@login_required
@invitee_only
def invitee_event_profile(org_uuid):
    
    """
    Displays all events for an invitee:
    - Ongoing/Upcoming events (they can still register)
    - Events already attended
    """

    try:
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except ValueError:
        flash("Invalid organization identifier.", "danger")
        return redirect(url_for('inv.universal_login'))

    # Ensure current_user is an invitee and belongs to this organization
    if not isinstance(current_user, Invitee):
        flash("Only invitees can access this page.", "danger")
        return redirect(url_for('inv.invitee_manual_login', org_uuid=org_uuid))

    if current_user.organization_id != org.id:
        flash("You are not authorized to view this organization's events.", "danger")
        return redirect(url_for('inv.universal_login'))

    invitee = current_user  #the logged-in invitee
    current_app.logger.info(f"Invitee{invitee.id} ({invitee.name}) dey.")

    now = datetime.utcnow()

    # Fetch all events for this org
    ongoing_events = Event.query.filter(
        Event.organization_id == org.id,
        Event.status == 'upcoming',
        Event.end_time >= now
    ).order_by(Event.start_time.asc()).all()

    # Events already attended
    attended_links = (
        EventInvitee.query
        .join(Event)
        .filter(
            EventInvitee.invitee_id == invitee.id,
            Event.organization_id == org.id,
            Invitee.confirmed == 'Present'
        )
        .options(joinedload(EventInvitee.event))
        .all()
    )
    attended_events = [link.event for link in attended_links]

    # Registered events (may not have attended yet)
    registered_links = (
        EventInvitee.query
        .join(Event)
        .filter(
            EventInvitee.invitee_id == invitee.id,
            Event.organization_id == org.id,
        )
        .options(joinedload(EventInvitee.event))
        .all()
    )

    registered_event_ids = {link.event_id for link in registered_links}
    registered_events = [link.event for link in registered_links]

    # Available events = ongoing ones they haven’t registered for
    available_events = [ev for ev in ongoing_events if ev.id not in registered_event_ids]

    return render_template(
        "invitee_event_profile.html",
        org=org,
        org_uuid=str(org.uuid),
        invitee=invitee,
        available_events=available_events,
        registered_events=registered_events,
        attended_events=attended_events,
    )



#send qr to email
def send_qr_code_email(invitee, qr_url, org,temp_password):
    try:
        # Generate QR code as Base64
        qr = qrcode.make(qr_url)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        sender_email = getattr(org, "email", None) or "info@danwebit.com"

        # temporary password
        temp_password=temp_password

        login_url =url_for('inv.invitee_manual_login', org_uuid=org.uuid,_external=True)

        msg = Message(
            subject=f"Registration Confirmation - {org.name}",
            sender=sender_email,
            recipients=[invitee.email],
        )

        msg.html = render_template(
            "emails/qr_code_email.html",
            invitee=invitee,
            org=org,
            qr_base64=qr_base64,
            qr_url=qr_url,
            login_url=login_url,
            temp_password=temp_password
        )

        mail.send(msg)
        print("QR Code email sent successfully!")

    except Exception as e:
        print(f"Error sending email: {e}")
        raise



######################################################
# @app_.route('/<uuid:org_uuid>/export_invitees', methods=['GET'])
# @login_required
# def export_invitees(org_uuid):
#     if not current_user.can_export_invitees:
#         flash('Access denied. You are not authorized to export invitees.', 'danger')
#         return redirect(url_for('inv.login'))

#     org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
#     event = Event.query.filter_by(organization_id=org.id).first()

#     invitees = []
#     pagination = None  # <-- define it here
#     event = None

#     try:
#         invitees_query = Invitee.query.filter_by(
#             organization_id=org.id)
#         page = request.args.get('page', 1, type=int)
#         pagination = invitees_query.paginate(page=page, per_page=10)
#         invitees = pagination.items

#         if not invitees:
#             flash('Records not found yet..', 'warning')
#             return redirect(url_for('inv.show_invitees', org_uuid=org.uuid))

#         data = [{
#             'Name': i.name or '',
#             'Phone': i.phone_number or '',
#             'Gender': i.gender or '',
#             'Email': i.email or '',
#             'State': i.state or '',
#             'LGA': i.lga or '',
#             'Position': i.position or '',
#             'Register Date': i.register_date.strftime('%Y-%m-%d') if i.register_date else '',
#             'Confirmed': i.confirmed if i.confirmed is not None else ''
#         } for i in invitees]

#         df = pd.DataFrame(data)
#         output = io.BytesIO()
#         with pd.ExcelWriter(output, engine='openpyxl') as writer:
#             df.to_excel(writer, index=False, sheet_name='Invitees')

#         output.seek(0)
#         return send_file(
#             output,
#             download_name=f"invitees_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx",
#             as_attachment=True,
#             mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#         )

#     except Exception as e:
#         flash(f'An error occurred while exporting data: {str(e)}', 'danger')
#         return render_template(
#             'invitees.html',
#             org=org,
#         org_uuid=org.uuid,
#         invitees=invitees,
#         event=event,
#         pagination=pagination
#     )

@app_.route('/<uuid:org_uuid>/export_invitees', methods=['GET'])
@login_required
def export_invitees(org_uuid):
    if not current_user.can_export_invitees:
        flash('Access denied. You are not authorized to export invitees.', 'danger')
        return redirect(url_for('inv.login'))

    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    invitees = []
    pagination = None

    try:
        invitees_query = Invitee.query.filter_by(organization_id=org.id)

        page = request.args.get('page', 1, type=int)
        pagination = invitees_query.paginate(page=page, per_page=10)
        invitees = pagination.items

        if not invitees:
            flash('No invitees found to export.', 'warning')
            return redirect(url_for('inv.show_invitees', org_uuid=org.uuid))

        # Prepare CSV data
        data = [{
            'Name': i.name or '',
            'Phone': i.phone_number or '',
            'Gender': i.gender or '',
            'Email': i.email or '',
            'State': i.state or '',
            'LGA': i.lga or '',
            'Position': i.position or '',
            'Register Date': i.register_date.strftime('%Y-%m-%d') if i.register_date else '',
            'Confirmed': i.confirmed if i.confirmed is not None else ''
        } for i in invitees]

        df = pd.DataFrame(data)

        # Convert DataFrame to CSV in memory
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)

        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            download_name=f"invitees_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
            as_attachment=True,
            mimetype="text/csv"
        )
    except Exception as e:
        flash(f'An error occurred while exporting data: {str(e)}', 'danger')
        return redirect(url_for('inv.show_invitees', org_uuid=org.uuid))


######################################################

@app_.route('/<uuid:org_uuid>/register_admin', methods=['GET', 'POST'])
@org_admin_or_super_required
def register_admin(org_uuid):
    form = AdminForm()
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    # location choices
    form.location_id.choices = [(0, "Unassigned")] + [
        (loc.id, loc.name) for loc in Location.query.filter_by(organization_id=org.id).all()
    ]

    if form.validate_on_submit():
        location_id = form.location_id.data if form.location_id.data != 0 else None
        name = form.name.data.title().strip()
        gender = form.gender.data
        email = form.email.data.strip().lower()
        address = form.address.data.title().strip() if form.address.data else None
        role = form.role.data
        phone_number = form.phone_number.data.strip() if form.phone_number.data else None
        password = form.password.data

        # uniqueness within organization
        existing_admin = Admin.query.filter(
            Admin.organization_id == org.id,
            or_(Admin.phone_number == phone_number, Admin.email == email)
        ).first()

        if existing_admin:
            flash("An Admin with this phone number or email already exists in this organization.", "error")
            return redirect(url_for('inv.register_admin', org_uuid=org.uuid))

        try:
            new_admin = Admin(
                name=name,
                gender=gender,
                phone_number=phone_number,
                address=address,
                email=email,
                role=role,
                location_id=location_id,
                organization_id=org.id
            )
            new_admin.set_password(password)
            db.session.add(new_admin)
            db.session.commit()

            send_admin_login_link(new_admin, org)
            log_action('add', user_id=current_user.id, record_type='Admin', record_id=new_admin.id, associated_org_id=org.id)
            flash(f"Admin '{new_admin.name}' registered successfully.", "success")
            return redirect(url_for('admin.management_dashboard', org_uuid=org.uuid))
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Error registering admin")
            flash("Error registering admin.", "danger")
            return render_template('register_admin.html', org=org, form=form)

    return render_template('register_admin.html', org=org, form=form)


#............edit function....................

# @app_.route('/<uuid:org_uuid>/edit_admin/<int:id>', methods=['GET', 'POST'])
# @admin_or_super_required
# def edit_admin(org_uuid, id):
#     org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
#     admin = Admin.query.filter_by(id=id, organization_id=org.id).first_or_404()
#     org_locations = Location.query.filter_by(organization_id=org.id).all()

#     if request.method == 'POST':
#         new_name = request.form.get('name', '').strip()
#         new_email = request.form.get('email', '').strip().lower()
#         new_password = request.form.get('password', '').strip()
#         new_gender = request.form.get('gender', '').strip()
#         new_phone_number = request.form.get('phone_number', '').strip()
#         new_location_id = request.form.get('location_id', '').strip() or None
#         new_location_id = int(new_location_id) if new_location_id else None

#         existing_admin = Admin.query.filter_by(email=new_email, organization_id=org.id).first()
#         if existing_admin and existing_admin.id != admin.id:
#             flash('An admin with this email already exists.', 'danger')
#             return redirect(url_for('inv.edit_admin', id=admin.id, org_uuid=org.uuid))

#         if new_password:
#             if len(new_password) < 6:
#                 flash('Password must be at least 6 characters long.', 'danger')
#                 return redirect(url_for('inv.edit_admin', id=admin.id, org_uuid=org.uuid))
#             admin.set_password(new_password)

#         admin.name = new_name
#         admin.email = new_email
#         admin.phone_number = new_phone_number
#         admin.gender = new_gender

#         # only assign location if role is location_admin
#         if admin.role == 'location_admin':
#             admin.location_id = new_location_id

#         admin.updated_at = datetime.utcnow()

#         try:
#             db.session.commit()
#             log_action('edit', user_id=current_user.id if current_user.is_authenticated else None,
#                        record_type='Admin', record_id=admin.id, associated_org_id=org.id)
#             flash('Admin updated successfully!', 'success')
#             return redirect(url_for('inv.manage_admin', org_uuid=org.uuid))
#         except Exception as e:
#             db.session.rollback()
#             current_app.logger.exception("Error updating admin")
#             flash(f'An error occurred: {e}', 'danger')
#             return render_template('edit_admin.html', admin=admin, org=org, org_locations=org_locations)

#     return render_template('edit_admin.html', admin=admin, org=org, org_locations=org_locations)

@app_.route('/<uuid:org_uuid>/edit_admin/<int:id>', methods=['GET', 'POST'])
@admin_or_super_required
def edit_admin(org_uuid, id):

    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    admin = Admin.query.filter_by(id=id, organization_id=org.id).first_or_404()
    org_locations = Location.query.filter_by(organization_id=org.id).all()

    if request.method == 'POST':

        # --- Pull form fields ---
        new_name = request.form.get('name', '').strip()
        new_email = request.form.get('email', '').strip().lower()
        new_password = request.form.get('password', '').strip()
        new_gender = request.form.get('gender', '').strip()
        new_phone = request.form.get('phone_number', '').strip()
        new_role = request.form.get('role', '').strip()

        new_location_id = request.form.get('location_id') or None
        new_location_id = int(new_location_id) if new_location_id else None

        # --- Validate email uniqueness ---
        existing_admin = Admin.query.filter_by(email=new_email, organization_id=org.id).first()
        if existing_admin and existing_admin.id != admin.id:
            flash("An admin with this email already exists in this organization.", "danger")
            return redirect(url_for('inv.edit_admin', id=admin.id, org_uuid=org.uuid))

        # --- Only super admins can change super_admin role ---
        if admin.role == "super_admin" and not current_user.is_super_admin:
            flash("Please Contact Support.", "danger")
            return redirect(url_for('inv.edit_admin', id=admin.id, org_uuid=org.uuid))

        # --- Update password if provided ---
        if new_password:
            if len(new_password) < 6:
                flash("Password must be at least 6 characters long.", "danger")
                return redirect(url_for('inv.edit_admin', id=admin.id, org_uuid=org.uuid))
            admin.set_password(new_password)

        # --- Update basic fields ---
        old_role = admin.role
        admin.name = new_name
        admin.email = new_email
        admin.phone_number = new_phone
        admin.gender = new_gender
        admin.role = new_role   # <-- IMPORTANT FIX

        # --- Handle location assignment ---
        if new_role == "location_admin":
            admin.location_id = new_location_id
        else:
            # Any other role must NOT retain a location
            admin.location_id = None

        admin.updated_at = datetime.utcnow()

        # --- Save changes ---
        try:
            db.session.commit()
            log_action(
                "edit",
                user_id=current_user.id if current_user.is_authenticated else None,
                record_type="Admin",
                record_id=admin.id,
                associated_org_id=org.id
            )

            # If the admin edited himself and the role changed → force relogin
            if admin.id == current_user.id and old_role != new_role:
                logout_user()
                flash("Your role has been updated. Please log in again.", "info")
                return redirect(url_for("inv.universal_login"))

            flash("Admin updated successfully!", "success")
            return redirect(url_for('inv.manage_admin', org_uuid=org.uuid))

        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Error updating admin")
            flash(f"An error occurred: {e}", "danger")

            return render_template('edit_admin.html',admin=admin,org=org,org_locations=org_locations
            )

    # GET request
    return render_template('edit_admin.html',admin=admin,org=org,org_locations=org_locations)



@app_.route('/<uuid:org_uuid>/profile', methods=['GET', 'POST'])
@admin_or_super_required
def view_admin(org_uuid):

    # Get the organization using UUID
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    
    if not current_user.is_super_admin:
        if current_user.organization_id != org.id:
            flash("You are not authorized to view this profile","danger")
            return redirect(url_for('inv.universal_login',org=org))
    return render_template("view_admin.html", org=org, admin=current_user)
        

# ............delete function..................

@app_.route('/<uuid:org_uuid>/del_admin/<int:admin_id>', methods=['POST'])
@org_admin_or_super_required
def del_admin(org_uuid, admin_id):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    admin = Admin.query.filter_by(id=admin_id, organization_id=org.id).first_or_404()

    try:
        csrf_token = request.headers.get('X-CSRFToken')
        validate_csrf(csrf_token)

        if admin.organization.uuid != org_uuid:
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        # super admin
        if admin.role == 'super_admin':
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        # Detach location if exists
        if admin.location_id:
            admin.location_id = None

        if current_user.is_super_admin:
            # Delete permanently
            db.session.delete(admin)
            action ="permanent_delete"
        elif current_user.is_org_admin and current_user.organization_id == org.id:
            #soft delete
            admin.is_active = False
            action= "soft delete"
        else:
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403
    
         # Delete permanently
        # db.session.delete(admin)
        db.session.commit()

        log_action(
            'delete',
            user_id=current_user.id if current_user.is_authenticated else None,
            record_type='Admin',
            record_id=admin.id,
            associated_org_id=org.id
        )
        return jsonify({'status': 'success', 'message': 'Admin deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400



@app_.route('/<uuid:org_uuid>/manage_admin', methods=['GET', 'POST'])
@org_admin_or_super_required
def manage_admin(org_uuid):
    
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    # if not ((current_user.is_super_admin and current_user.organization_id != org.id) or (current_user.is_org_admin and current_user.organization_id != org.id)):
    #     flash("Unauthorized access to this organization's admins.", 'danger')
    #     return redirect(url_for('inv.login', org_uuid=org.uuid))

    search = request.args.get('search', '', type=str)
    page = request.args.get('page', 1, type=int)
    per_page = 10

    admins_query = Admin.query.filter_by(organization_id=org.id)

    if search:
        admins_query = admins_query.filter(
            (Admin.email.ilike(f'%{search}%')) |
            (Admin.phone_number.ilike(f'%{search}%'))
        )
        if admins_query.count() == 0:
            flash('Admin not found', 'danger')
    # i am trying not 
    pagination = admins_query.filter(Admin.role != 'super_admin').order_by(Admin.updated_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False)
    admins = pagination.items

    return render_template('del_admin.html', org=org, org_uuid=org.uuid,
                            admins=admins, pagination=pagination, search=search)
  

@app_.route('/<uuid:org_uuid>/action_logs', methods=['GET'])
@super_required
def action_logs(org_uuid):

    try:
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
        action_logs = ActionLog.query.filter_by(organization_id=org.id).order_by(ActionLog.id.desc()).all()

        if not action_logs:
            return render_template('action_logs.html', message="No logs found.")

        return render_template('action_logs.html', org=org, org_uuid=org.uuid, action_logs=action_logs)

    except Exception as e:
        return render_template('action_logs.html', message=f"An error occurred: {e}")


@app_.route('/<uuid:org_uuid>/<int:event_id>/all_feedbacks')
# @org_admin_required
def all_feedback(org_uuid,event_id):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    event=Event.query.filter_by(id=event_id, organization_id=org.id).first_or_404()
    all_feedback = Feedback.query.filter_by(organization_id=org.id).all()

    return render_template('all_feedbacks.html', org=org, org_uuid=org.uuid,event=event,event_id=event.id, all_feedback=all_feedback)

###################################################

# ....................................#

@app_.route('/<uuid:org_uuid>/locations')
@org_admin_or_super_required # This decorator is key for initial permission and org_uuid validation
def manage_locations(org_uuid):
    
    """location managers"""
    try:
        # Get the Organization object based on the URL's org_uuid.
        # org_uuid is already a UUID object from Flask's converter.
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except Exception as e: # Catch broader exceptions for robustness
        current_app.logger.error(f"Error fetching organization for UUID {org_uuid}: {e}")
        flash('Invalid organization identifier.', 'danger')
        # Redirect to your generic login or a safe default page
        return redirect(url_for('inv.universal_login'))

    # Initialize the query for locations. It will remain None if access is denied.
    locations_query = None

    # --- Role-based Access Control and Data Filtering ---
    if current_user.is_super_admin:
        # Super Admins can manage locations for ANY organization, as specified by the URL's org_uuid.
        locations_query = Location.query.filter_by(organization_id=org.id)

    elif current_user.is_org_admin or current_user.is_location_admin:
        # For Organization Admins and Location Admins, check if they belong to the requested organization.
        if current_user.organization_id == org.id:
            # They are authorized for this organization. Filter locations by their organization.
            locations_query = Location.query.filter_by(organization_id=current_user.organization_id)

            # --- Optional: Further filter for Location Admins ---
            # If a Location Admin should *only* see locations they are specifically assigned to,
            # you'd add another filter here. Example:
            # if current_user.is_location_admin and current_user.location_id: # Assuming Admin model has location_id
            #     locations_query = locations_query.filter_by(id=current_user.location_id)
            #     # If a Location Admin is missing location_id, deny access here
            #     # else:
            #     #     flash("Your location admin account is not assigned to a specific location.", "danger")
            #     #     return redirect(url_for('app_.universal_login'))

        else:
            # This user (org/location admin) is trying to access locations for an organization they don't belong to.
            flash('You do not have permission to view locations for this organization.', 'danger')
            
            # If they have an assigned organization, redirect them to its locations page.
            if current_user.organization and current_user.organization.uuid:
                return redirect(url_for('inv.manage_locations', org_uuid=current_user.organization.uuid))
            else:
                # If their own organization isn't set for some reason, redirect to a safe default.
                return redirect(url_for('inv.universal_login'))
    
    # --- Final Check: If no specific access rule allowed a query to be built ---
    if locations_query is None:
            # for *this particular organization's* locations.
        flash('You do not have sufficient permissions to view this page or its specific organization\'s locations.', 'danger')
        return redirect(url_for('inv.universal_login')) # Redirect to a generic login or dashboard

    # Execute the query if one was successfully built
    # locations = locations_query.all()
    locations = Location.query.filter_by(organization_id=org.id).order_by(Location.created_at.desc()).limit(10).all()
            
    return render_template('manage_locations.html', org=org, locations=locations)



@app_.route('/<uuid:org_uuid>/locations/add', methods=['GET', 'POST'])
# @org_admin_required
def add_location(org_uuid):
    """Add a new location for the organization"""
    try:
        # Get the Organization object based on the URL's org_uuid.
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except Exception as e: # Catch broader exceptions for robustness
        flash('Invalid organization identifier.', 'danger')
        return redirect(url_for('inv.universal_login'))
    
    if current_user.is_super_admin:
        pass
    elif current_user.is_org_admin and current_user.organization_id == org.id:
            pass
    else:
        # This user (org/location admin) is trying to access locations for an organization they don't belong to.
        flash('You do not have permission to add locations for this organization.', 'danger')
        return redirect(url_for('inv.universal_login'))
    
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            description = request.form.get('description', '')
            address = request.form.get('address', '')
            latitude = float(request.form.get('latitude'))
            longitude = float(request.form.get('longitude'))
            radius = int(request.form.get('radius',100))
            
            # Validation
            if not name:
                flash('Location name is required', 'danger')
                return redirect(request.url)
            
            if not (1 <= radius <= 100):
                flash('Invalid Radius. Must be between 1 to 100 meters', 'danger')
                return redirect(request.url)
            
            if not (-90 <= latitude <= 90):
                flash('Invalid latitude. Must be between -90 and 90', 'danger')
                return redirect(request.url)
            
            if not (-180 <= longitude <= 180):
                flash('Invalid longitude. Must be between -180 and 180', 'danger')
                return redirect(request.url)
            
            # Create new location
            location = Location(name=name,address=address,latitude=latitude, longitude=longitude,
                description=description,radius=radius, organization_id=org.id, created_at=datetime.utcnow()
            )
            
            db.session.add(location)
            db.session.commit()
            
            flash(f'Location "{name}" added successfully', 'success')
            return redirect(url_for('inv.manage_locations', org_uuid=org.uuid))
            
        except ValueError:
            flash('Invalid coordinates. Please enter valid numbers.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding location: {str(e)}', 'danger')
    
    return render_template('add_location.html',org=org,org_uuid=session.get('org_uuid'))


@app_.route('/<uuid:org_uuid>/locations/<int:location_id>/edit', methods=['GET', 'POST'])
@admin_or_super_required
def edit_location(org_uuid, location_id):

    """Edit an existing location"""
    try:
        # Get the Organization object based on the URL's org_uuid.
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except Exception as e: # Catch broader exceptions for robustness
        flash('Invalid organization identifier.', 'danger')
        return redirect(url_for('inv.universal_login'))
    
    # Initialize location to None; it will be set if the user is authorized.
    location = None

    if current_user.is_super_admin:
        location = Location.query.filter_by(id=location_id, organization_id=org.id).first_or_404()
  
    elif current_user.is_org_admin:
        # Org Admins can only manage locations within THEIR OWN assigned organization.
        if current_user.organization_id == org.id:
            # If the Org Admin's organization matches the URL's organization, fetch the location.
            location = Location.query.filter_by(id=location_id, organization_id=org.id).first_or_404()
        else:
            # This user (org/location admin) is trying to access locations for an organization they don't belong to.
            flash('You do not have permission to edit locations for this organization.', 'danger')
            return redirect(url_for('inv.universal_login'))
    else:
        # Any other role (e.g., is_location_admin, or standard users) is not allowed to edit locations.
        flash('You do not have the required permissions to edit locations.', 'danger')
        return redirect(url_for('inv.universal_login'))
     
    if request.method == 'POST':
        try:
            location.name = request.form.get('name')
            location.description = request.form.get('description', '')
            location.address = request.form.get('address', '')
            location.latitude = float(request.form.get('latitude'))
            location.longitude = float(request.form.get('longitude'))
            location.radius = int(request.form.get('radius', 100))
            location.is_active = bool(request.form.get('is_active'))
            
            # Validation
            if not location.name:
                flash('Location name is required', 'danger')
                return redirect(request.url)
            
            if not (1 <= location.radius <= 100):
                flash('Invalid Radius. Must be between 1 to 100 meters', 'danger')
                return redirect(request.url)
            
            if not (-90 <= location.latitude <= 90):
                flash('Invalid latitude. Must be between -90 and 90', 'danger')
                return redirect(request.url)
            
            if not (-180 <= location.longitude <= 180):
                flash('Invalid longitude. Must be between -180 and 180', 'danger')
                return redirect(request.url)
            
            db.session.commit()
            flash(f'Location "{location.name}" updated successfully', 'success')
            return redirect(url_for('inv.manage_locations', org_uuid=org.uuid))
            
        except ValueError:
            flash('Invalid coordinates. Please enter valid numbers.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating location: {str(e)}', 'danger')

    return render_template('edit_location.html',org=org,location=location)


@app_.route('/<uuid:org_uuid>/locations/<int:location_id>/toggle', methods=['POST'])
# @org_admin_required
def toggle_location(org_uuid, location_id):
    """Toggle location active status"""

    # 1. Get the target Organization based on the URL's org_uuid.
    try:
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except Exception as e:
        # current_app.logger.error(f"Error fetching organization for UUID {org_uuid}: {e}")
        flash('Invalid organization identifier.', 'danger')
        return redirect(url_for('inv.universal_login'))

    # 2. Role-based Access Control
    if current_user.is_super_admin:
        pass
    elif current_user.is_org_admin and current_user.organization_id == org.id:
        pass # They are authorized to proceed.
    else:
        # Any other role (e.g., location_admin, standard user) or an Org Admin
        flash('You do not have the required permissions to toggle this location\'s status.', 'danger')
        # Redirect to a safe, universal page or their authorized dashboard.
        return redirect(url_for('inv.universal_login')) 

    # This must be inside the authorized path, after the permission checks.
    location = Location.query.filter_by(id=location_id, organization_id=org.id).first_or_404()
    
    try:
        location.is_active = not location.is_active
        db.session.commit()
        
        status = "activated" if location.is_active else "deactivated"
        flash(f'Location "{location.name}" {status} successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating location: {str(e)}', 'danger')
    
    return redirect(url_for('inv.manage_locations', org_uuid=org.uuid))

####################################

@app_.route('/<uuid:org_uuid>/locations/<int:location_id>/delete', methods=['POST', 'GET'])
def delete_location(org_uuid, location_id):
    """Delete a location"""
    # 1. Get the target Organization based on the URL's org_uuid.
    try:
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except Exception as e:
        # current_app.logger.error(f"Error fetching organization for UUID {org_uuid}: {e}")
        flash('Invalid organization identifier.', 'danger')
        return redirect(url_for('inv.universal_login'))

    # 2. Role-based Access Control
    if current_user.is_super_admin:
        pass
    elif current_user.is_org_admin and current_user.organization_id == org.id:
        pass # They are authorized to proceed.
    else:
        # Any other role (e.g., location_admin, standard user) or an Org Admin
        flash('You do not have the required permissions to toggle this location\'s status.', 'danger')
        # Redirect to a safe, universal page or their authorized dashboard.
        return redirect(url_for('inv.universal_login')) 

    # This must be inside the authorized path, after the permission checks.
    location = Location.query.filter_by(id=location_id, organization_id=org.id).first_or_404()
 
    try:
        location_name = location.name
        db.session.delete(location)
        db.session.commit()

        # If this is a fetch/AJAX request, return JSON instead of redirect
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': f'Location "{location_name}" deleted successfully'})

        flash(f'Location "{location_name}" deleted successfully', 'success')

    except Exception as e:
        db.session.rollback()
        error_msg = f'Error deleting location: {str(e)}'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': error_msg}), 500
        flash(error_msg, 'danger')

    return redirect(url_for('inv.manage_locations', org_uuid=org.uuid))




# ############ events ################################################
@app_.route('/<uuid:org_uuid>/events', methods=['GET'])
@admin_or_super_required
def view_event_detail(org_uuid):
    
    """Display all events for an organization with pagination"""
    
    # Get the organization
    try:
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except Exception as e:
        # current_app.logger.error(f"Error fetching organization for UUID {org_uuid}: {e}")
        flash('Invalid organization identifier.', 'danger')
        return redirect(url_for('inv.universal_login'))

    # Role-based Access Control
    if current_user.is_super_admin:
        pass
    elif current_user.is_org_admin and current_user.organization_id == org.id:
        pass  # They are authorized to proceed
    else:
        flash('You do not have the required permissions to view events for this organization.', 'danger')
        return redirect(url_for('inv.universal_login'))

    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of events per page
    
    # Get filter parameters (optional)
    status_filter = request.args.get('status', 'all')  # 'all', 'active', 'inactive'
    search_query = request.args.get('search', '').strip()

    # Build the query
    events_query = Event.query.filter_by(organization_id=org.id)
    
    # Apply status filter
    if status_filter == 'active':
        events_query = events_query.filter_by(is_active=True)
    elif status_filter == 'upcoming':
        events_query = events_query.filter(Event.start_time > datetime.utcnow()) # Example
    elif status_filter == 'past':
        events_query = events_query.filter(Event.end_time < datetime.utcnow()) # Example
    elif status_filter == 'inactive':
        events_query = events_query.filter_by(is_active=False)
    
    # Apply search filter (search in event name)
    if search_query:
        events_query = events_query.filter(Event.name.ilike(f'%{search_query}%'))
    
    # Join with Location for proper ordering and to avoid N+1 queries
    events_query = events_query.join(Location).options(db.joinedload(Event.location))
    
    # Order by start time (newest first)
    events_query = events_query.order_by(Event.start_time.desc())
    
    # Paginate the results
    try:
        events = events_query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
    except Exception as e:
        # current_app.logger.error(f"Error paginating events: {e}")
        flash('Error loading events. Please try again.', 'danger')
        events = events_query.paginate(page=1, per_page=per_page, error_out=False)

    """"new generate/retrieve  QR  links"""
    event_qr_map ={}
    attendance_qr_map = {}

    for event in events.items:
        try:
            qr_url = generate_event_qr(org_uuid, event.id)
            event_qr_map[event.id] = qr_url

            # Attendance QR (new)
            qr_url_att = generate_attendance_qr(org_uuid, event.id)
            attendance_qr_map[event.id] = qr_url_att

        except Exception as e:
            current_app.logger.error(f"QR generation fail: {e}")
            event_qr_map[event.id] = None
            attendance_qr_map[event.id] = None

    # Get summary statistics (optional)
    total_events = Event.query.filter_by(organization_id=org.id).count()
    active_events = Event.query.filter_by(organization_id=org.id, is_active=True).count()
    
    # Get upcoming events count (events that haven't ended yet)
     
    upcoming_events = Event.query.filter(
        Event.organization_id == org.id,
        Event.end_time > datetime.utcnow(),
        Event.is_active == True
    ).count()

    return render_template(
        'view_event.html',
        org=org,
        events=events,
        current_page=page,
        status_filter=status_filter,
        search_query=search_query,
        total_events=total_events,
        active_events=active_events,
        event_qr_map=event_qr_map,
        attendance_qr_map= attendance_qr_map,
        upcoming_events=upcoming_events
    )

# .....................edit and add event..........

@app_.route('/<uuid:org_uuid>/event', methods=['GET', 'POST'])
@app_.route('/<uuid:org_uuid>/event/<int:event_id>', methods=['GET', 'POST'])
@org_admin_or_super_required
def add_event(org_uuid, event_id=None):
    """Add or edit an event using the same form template (add_event.html)."""
    try:
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except Exception:
        flash('Invalid organization identifier.', 'danger')
        return redirect(url_for('inv.universal_login'))

    # Role-based access
    if not (current_user.is_super_admin or (current_user.is_org_admin and current_user.organization_id == org.id)):
        flash('You do not have permission to manage events for this organization.', 'danger')
        return redirect(url_for('inv.universal_login'))

    # If editing, fetch existing event
    event = None
    if event_id:
        event = Event.query.filter_by(id=event_id, organization_id=org.id).first_or_404()

    locations = Location.query.filter_by(organization_id=org.id, is_active=True).all()

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        location_id = request.form.get('location_id')
        description = request.form.get('description')
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')
        is_active = request.form.get('is_active') == 'on'
        image_file = request.files.get('event_logo')  # New upload field

        # --- Basic validation ---
        if not name or not location_id or not start_time_str or not end_time_str:
            flash("All fields are required.", "danger")
            return redirect(request.url)

        try:
            start_time = datetime.fromisoformat(start_time_str)
            end_time = datetime.fromisoformat(end_time_str)
        except ValueError:
            flash("Invalid date format provided.", "danger")
            return redirect(request.url)

        if end_time <= start_time:
            flash("End time must be after start time.", "danger")
            return redirect(request.url)

        try:
            location_id = int(location_id)
            location = Location.query.filter_by(id=location_id, organization_id=org.id).first()
            if not location:
                flash("Invalid location selected.", "danger")
                return redirect(request.url)
        except (ValueError, TypeError):
            flash("Invalid location selected.", "danger")
            return redirect(request.url)

        # --- Create or Update Event ---
        try:
            if event:  # Editing existing event
                event.name = name
                event.location_id = location_id
                event.description = description
                event.start_time = start_time
                event.end_time = end_time
                event.is_active = is_active

                # Handle image upload
                if image_file and image_file.filename != '':
                    # Delete old image if it exists
                    if event.event_logo_url:
                        Config.delete_uploaded_image(event.event_logo_url)

                    filename = Config.save_uploaded_image(image_file, prefix="event_")
                    if filename:
                        event.event_logo_url = filename

                db.session.commit()
                flash("Event updated successfully.", "success")
                return redirect(url_for('inv.view_event_detail', org_uuid=org.uuid))

            else:  # Creating a new event
                # Check for duplicates
                existing_event = Event.query.filter_by(
                    name=name, location_id=location_id, organization_id=org.id
                ).first()
                if existing_event:
                    flash("An event with this name already exists at the selected location.", "danger")
                    return redirect(request.url)

                filename = None
                if image_file and image_file.filename != '':
                    filename = Config.save_uploaded_image(image_file, prefix="event_")

                new_event = Event(
                    name=name,
                    location_id=location_id,
                    description=description,
                    organization_id=org.id,
                    start_time=start_time,
                    end_time=end_time,
                    is_active=is_active,
                    event_logo_url=filename if filename else None
                )

                db.session.add(new_event)
                db.session.commit()

                flash("Event created successfully.", "success")
                return redirect(url_for('inv.add_event', org_uuid=org.uuid))

        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {e}", "danger")
            return redirect(request.url)

    # --- GET Request ---
    return render_template(
        'add_event.html',
        org=org,
        event=event,
        locations=locations,
        mode='edit' if event_id else 'create'
    )


@app_.route('/<uuid:org_uuid>/events/<int:event_id>/delete', methods=['POST'])
@admin_or_super_required
def delete_event(org_uuid, event_id):
    """Delete an event"""
    
    # Get the organization
    try:
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except Exception as e:
        flash('Invalid organization identifier.', 'danger')
        return redirect(url_for('inv.universal_login'))

    # Get the event
    try:
        event = Event.query.filter_by(
            id=event_id, 
            organization_id=org.id
        ).first_or_404()
    except Exception as e:
        flash('Event not found.', 'danger')
        return redirect(url_for('inv.view_event_detail', org_uuid=org.uuid))

    # Role-based Access Control
    if current_user.is_super_admin:
        pass
    elif current_user.is_org_admin and current_user.organization_id == org.id:
        pass
    else:
        flash('You do not have the required permissions to delete this event.', 'danger')
        return redirect(url_for('inv.universal_login'))

    # Store event name for flash message
    event_name = event.name

    try:
        # Check if event has any related records (registrations, etc.)
        # Add your business logic here if needed
        # For example:
        # if event.registrations.count() > 0:
        #     flash("Cannot delete event with existing registrations.", "danger")
        #     return redirect(url_for('inv.view_events', org_uuid=org.uuid))
        
        db.session.delete(event)
        db.session.commit()
        
        flash(f'Event "{event_name}" has been deleted successfully.', 'success')
        
    except Exception as e:
        db.session.rollback()
        # current_app.logger.error(f"Error deleting event {event_id}: {e}")
        flash("An error occurred while deleting the event. Please try again.", "danger")

    return redirect(url_for('inv.view_event_detail', org_uuid=org.uuid))

###################################################################
#super admin dashboard

@app_.route('/<uuid:org_uuid>/locations/api')
# @admin_required
# @org_admin_required
def locations_api(org_uuid):
    """API endpoint to get locations as JSON for frontend use"""
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    locations = Location.query.filter_by(
        organization_id=org.id, 
        is_active=True
    ).all()
    
    locations_data = []
    for location in locations:
        locations_data.append({
            'id': location.id,
            'name': location.name,
            'address': location.address,
            'latitude': location.latitude,
            'longitude': location.longitude,
            'radius': location.radius
        })
    
    return jsonify(locations_data)


###########################################################

@app_.route('/get_lgas', methods=['GET'])
def get_lgas():
    state = request.args.get('state')
    state = state.title() if state else ""

    lga = fetch_lgas(state)
    
    if lga:
        return jsonify({'lga': lga})
    else:
        return jsonify({'error': 'State not found'}), 404
    


@app_.route('/<uuid:org_uuid>/forgot_password', methods=['GET', 'POST'])
def forgot_password_request(org_uuid):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    # If the user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('inv.universal_login', org_uuid=org.uuid))

    form = RequestResetForm()  # This form should just have an email field

    if form.validate_on_submit():
        # Find user
        admin = Admin.query.filter_by(email=form.email.data).first()
        invitee = Invitee.query.filter_by(email=form.email.data).first()
        user = admin or invitee

        if user:
            send_password_reset_email(user.email)
            flash('A password reset link has been sent to your email.', 'info')
        else:
            # Prevent email enumeration
            flash('If an account with that email exists, a password reset link has been sent.', 'info')

        return redirect(url_for('inv.forgot_password_request', org_uuid=org.uuid))

    return render_template('forgot_password_request.html', form=form, org=org)


###################################################

@app_.route('/<uuid:org_uuid>/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(org_uuid, token):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    if current_user.is_authenticated:
        return redirect(url_for('inv.universal_login', org_uuid=org.uuid))

    email = verify_reset_token(token)
    if email is None:
        flash('That is an invalid or expired token.', 'warning')
        return redirect(url_for('inv.forgot_password_request', org_uuid=org.uuid))

    # Get the user (Admin or Invitee)
    user = Admin.query.filter_by(email=email).first() \
           or Invitee.query.filter_by(email=email).first()

    if not user:
        flash('Account not found.', 'danger')
        return redirect(url_for('inv.forgot_password_request', org_uuid=org.uuid))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'info')
        return redirect(url_for('inv.login', org_uuid=org.uuid))

    return render_template('reset_password.html', form=form, token=token, org=org)



# def send_password_reset_email(user_email):

#     """Send a password reset email to Admin or Invitee."""
#     user = Admin.query.filter_by(email=user_email).first() \
#            or Invitee.query.filter_by(email=user_email).first()

#     if not user:
#         current_app.logger.error(f"User not found for email: {user_email}")
#         return False

#     # Determine the organization UUID
#     org_uuid = None
#     if hasattr(user, "organization") and user.organization:
#         org_uuid = user.organization.uuid
#     elif hasattr(user, "organization_id") and user.organization_id:
#         org = Organization.query.get(user.organization_id)
#         org_uuid = org.uuid if org else None

#     if not org_uuid:
#         current_app.logger.error(f"Invalid org_uuid for password reset: {user_email}")
#         return False

#     # Generate token
#     token = generate_reset_token(user_email)

#     # Generate password reset link
#     reset_link = url_for('inv.reset_password', org_uuid=org_uuid, token=token, _external=True)

#     try:
#         html_body = render_template('emails/password_reset.html', reset_link=reset_link)
#         send_async_email(
#             subject='Password Reset Request',
#             sender=current_app.config['MAIL_DEFAULT_SENDER'],
#             recipients=[user_email],
#             html_body=html_body
#         )

#         current_app.logger.info(f"Password reset email sent to {user_email}")
#         return True
#     except Exception as e:
#         current_app.logger.error(f"Failed to send password reset email to {user_email}: {e}")
#         return False

def send_password_reset_email(user_email):
    """Send a password reset email to Admin or Invitee."""
    user = Admin.query.filter_by(email=user_email).first() \
           or Invitee.query.filter_by(email=user_email).first()

    if not user:
        current_app.logger.error(f"User not found for email: {user_email}")
        return False

    # Determine organization
    org = None
    if hasattr(user, "organization") and user.organization:
        org = user.organization
    elif hasattr(user, "organization_id") and user.organization_id:
        org = Organization.query.get(user.organization_id)

    if not org:
        current_app.logger.error(f"Invalid org for password reset: {user_email}")
        return False

    org_uuid = org.uuid

    # Generate token
    token = generate_reset_token(user_email)

    # Generate password reset link
    reset_link = url_for('inv.reset_password', org_uuid=org_uuid, token=token, _external=True)

    try:
        html_body = render_template(
            'emails/password_reset.html',
            reset_link=reset_link,
            org=org
        )

        send_async_email(
            subject='Password Reset Request',
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=[user_email],
            html_body=html_body
        )

        current_app.logger.info(f"Password reset email sent to {user_email}")
        return True

    except Exception as e:
        current_app.logger.error(f"Failed to send password reset email to {user_email}: {e}")
        return False



# TOKEN FOR EMAIL  CONFIRM

@app_.route('/confirm/<token>', methods=['GET', 'POST'])
def invitation_confirm(token):
    """
    Handles the invitation confirmation page where invited users set their name and password.
    """
    invitation = Invitation.query.filter_by(token=token, status='pending').first()

    # --- Token Validation (GET request) ---
    if not invitation:
        flash('Invalid invitation link.', 'danger')
        current_app.logger.warning(f"Attempted invitation confirmation with invalid token: {token}")
        return redirect(url_for('inv.universal_login')) # Redirect to a suitable public page
    
    # --- CRUCIAL ADDITION: Define 'org' here ---
    org = invitation.organization 

    # you might need to handle this or ensure invitations always have an org.
    if not org:
        flash('Invitation is not linked to a specific organization. Please contact support.', 'danger')
        current_app.logger.error(f"Invitation {invitation.id} has no associated organization.")
        return redirect(url_for('inv.base_dashboard')) # Or a more appropriate error page

    if invitation.expires_at < datetime.utcnow():
        invitation.status = 'expired' # Mark as expired
        db.session.commit()
        flash('Expired invitation link. Please request a new invitation.', 'danger')
        current_app.logger.warning(f"Attempted invitation confirmation with expired token: {token}")
        return redirect(url_for('inv.base_dashboard'))

    # --- Handle Form Submission (POST request) ---
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Input validation
        if not name or not password or not confirm_password:
            flash('Name, Password, and Confirm Password are required.', 'danger')
            return render_template('emails/invitation_confirm.html', invitation=invitation, token=token,org=org)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('emails/invitation_confirm.html', invitation=invitation, token=token,org=org)

        # Check for existing user with this email (though send_invitation should prevent this)
        existing_admin = Admin.query.filter_by(email=invitation.email).first()
        if existing_admin:
            flash('An account with this email already exists. Please log in.', 'warning')
            invitation.status = 'used' # Mark invitation as used/redundant
            db.session.commit()
            return redirect(url_for('inv.universal_login')) # Assuming you have an 'auth.login' route

        try:
            # Create the new Admin user
            new_admin = Admin(
                email=invitation.email,
                name=name, # Set the name from the form
                role=invitation.role,
                organization=invitation.organization, # Link to organization from invitation
                invited_by_admin_id=invitation.invited_by_id  # Link to the admin id who sent the invite
                # is_super will be derived from role property or set explicitly based on invitation.role
            )
            # Set the password using the method you added to Admin model
            new_admin.set_password(password)

            db.session.add(new_admin)
            invitation.status = 'accepted' # Mark invitation as accepted
            db.session.commit()

            # Log the action of admin creation
            log_action('add', 'Admin', new_admin.id, associated_org_id=new_admin.organization_id)

            flash('Your account has been set up successfully! Please log in.', 'success')
            return redirect(url_for('inv.universal_login')) # Redirect to your login page

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error setting up admin account for {invitation.email}: {e}", exc_info=True)
            flash('An error occurred during account setup. Please try again.', 'danger')
            return render_template('emails/invitation_confirm.html', invitation=invitation, token=token,org=org)

    # --- Display Form (GET request for valid token) ---
    # If it's a GET request and the token is valid, show the form
    return render_template('emails/invitation_confirm.html', invitation=invitation, token=token,org=org)

