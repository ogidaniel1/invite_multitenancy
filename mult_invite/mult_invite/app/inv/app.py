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
from config import Config
# ,org_admin_required,super_required
import uuid
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import func
from flask_cors import CORS # For handling CORS if frontend is on a different origin
from datetime import datetime
from app import db
from app.models import LoginForm,ActionLog,DeleteInviteeForm,DeleteLog,OrganizationForm,Location,OrgIdentifierForm
from app.models import Organization,Admin,Invitation,Invitee,InviteeForm,super_required,SubmitField,Feedback,Event
from app.models import FeedbackForm,AttendanceForm,AdminForm,admin_or_super_required,fetch_lgas_all,org_admin_or_super_required
from config import Config
from app import csrf,mail
from flask import current_app

from app.inv.tokens import generate_reset_token, verify_reset_token,send_password_reset_email
from app.models  import RequestResetForm, ResetPasswordForm # Create these forms below

 
# from models import get_lgas,fetch_lgas


app_ = Blueprint('inv', __name__, template_folder='../templates')


load_dotenv()

#######################################################

# Configuration
DEFAULT_ADMIN_EMAIL = os.getenv('DEFAULT_ADMIN_EMAIL')
DEFAULT_ADMIN_PASSWORD = os.getenv('DEFAULT_ADMIN_PASSWORD')


#deadline date
registration_deadline = datetime(2024, 5, 26, 23, 59, 59)  # Example: May 26, 2025, 23:59:59



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

        existing_slug = Organization.query.filter_by(slug=form.slug.data).first()
        existing_name = Organization.query.filter_by(name=form.name.data).first()

        if existing_slug:
            flash('Organization slug already exists. Choose another one.', 'danger')
            return redirect(url_for('inv.register_organization'))

        if existing_name:
            flash('Organization name already exists. Choose another one.', 'danger')
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

@app_.route('/organization/<int:org_id>/view')
@super_required
def view_organization(org_id):
    """View a specific organization details"""
    organization = Organization.query.get_or_404(org_id)
    
    # Get additional stats if needed
    active_locations_count = len(organization.get_active_locations())
    
    return render_template('organizations.html', 
                         organization=organization,
                         active_locations_count=active_locations_count)


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
            Organization.slug == form.slug.data,
            Organization.id != org_id
        ).first()
        
        # Check if name already exists (excluding current organization)
        existing_name = Organization.query.filter(
            Organization.name == form.name.data,
            Organization.id != org_id
        ).first()
        
        if existing_slug:
            flash('Organization slug already exists. Choose another one.', 'danger')
            return render_template('organizations.html', form=form, organization=organization)
        
        if existing_name:
            flash('Organization name already exists. Choose another one.', 'danger')
            return render_template('organizations.html', form=form, organization=organization)
        
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

@app_.route('/login/', methods=['GET', 'POST']) # Renamed to /universal_login for clarity, but you can keep /login/
def universal_login():
    form = OrgIdentifierForm()

    # If the user is already authenticated, redirect them away from login page
    # (Optional, but generally good practice)

    if form.validate_on_submit():
        identifier = form.org_identifier.data.strip()

        # 1. Try to find an Organization by its exact slug or a partial name match
        org = Organization.query.filter(
            (Organization.slug == identifier.lower()) | # Use .lower() for slug comparison if slugs are lowercase
            (Organization.name.ilike(f"%{identifier}%")) # Case-insensitive partial name match
        ).first()

        if org:
            flash(f"Please log in to {org.name}.", "info")
            # Redirect to the organization's specific login page
            return redirect(url_for('inv.login', org_uuid=org.uuid))

        # 2. If not found by organization name/slug, check if the identifier is an email
        if "@" in identifier:
            # IMPORTANT: Filter by the exact email address
            admin = Admin.query.filter_by(email=identifier.lower()).first()

            if admin:
                # Admin account found by exact email
                if admin.organization:
                    # If the admin belongs to a specific organization, redirect to its login page
                    flash(f"Please log in to {admin.organization.name}.", "info")
                    return redirect(url_for('inv.login', org_uuid=admin.organization.uuid))
                elif admin.is_super_admin:
                    # If it's a super admin, they might not be tied to a specific organization UUID in the URL
             
                    first_available_org = Organization.query.first() # Or a specific 'main' org
                    if first_available_org:
                        flash("Super Admin account found. Please log in with your credentials.", "info")
                        return redirect(url_for('app_.login', org_uuid=first_available_org.uuid))
                    else:
                        flash("Super Admin account found, but no organizations exist to log into.", "danger")
                        return render_template("universal_login.html", form=form) # Stay on page

                else:
                    # Admin exists but has no associated organization and is not a super admin (unlikely given your role system)
                    flash("Admin account found, but no associated organization. Please contact support.", "danger")
            else:
                # Email format, but no admin found with that exact email
                flash("No admin account found with that email address.", "danger")
        else:
            # Identifier is not an email, and no organization was found by name/slug
            flash("Organization name/slug or admin email not found. Please try again.", "danger")

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
                session['admin_id'] = admin.id
                 # ✅ Update last login
                admin.last_login = datetime.utcnow()
                db.session.commit()
                flash('Login successful!', 'success')
                return redirect(url_for('admin.management_dashboard'))
            flash('Unauthorized access to this organization.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('super_login.html',form=form, org=org)


@app_.route('/<uuid:org_uuid>/login', methods=['GET', 'POST']) 
def login(org_uuid):
    form = LoginForm()
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    if form.validate_on_submit():
        admin = Admin.query.filter_by(email=form.email.data).first()

        if admin and admin.check_password(form.password.data):
            # Check for access to this specific organization or if it's a super admin
            if admin.is_super_admin or (admin.organization_id == org.id):
                # Pass form.remember_me.data to login_user()
                login_user(admin, remember=form.remember_me.data) # <-- CRUCIAL CHANGE
                session['org_uuid'] = str(org.uuid)
                flash('Login successful!', 'success')

                admin.last_login = datetime.utcnow()
                db.session.commit()

                if admin.is_super_admin:
                    # You can redirect to a super admin specific dashboard here
                    # For now, keeping your existing redirect
                    return redirect(url_for('admin.management_dashboard', org_uuid=org.uuid))
                else:
                    return redirect(url_for('inv.show_invitees', org_uuid=org.uuid))
            else:
                flash('Unauthorized access to this organization.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html', form=form, org=org)


@app_.route('/<uuid:org_uuid>/logout')
@login_required
def logout(org_uuid):
    logout_user()
    flash('You have been logged out!', 'success')
    return redirect(url_for('inv.login', org_uuid=org_uuid))


######################...helper...#########################
#Helper Function for Logging Actions

def log_action(action_type, user_id, record_type=None, record_id=None, associated_org_id=None):
    if user_id is None:
        user_id = "Anonymous"  # Or any default value
    
    try:
        # Log all actions to ActionLog
        action_log = ActionLog(
            action_type=action_type,
            user_id=user_id,
            record_type=record_type,
            record_id=record_id,
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

@app_.route('/<uuid:org_uuid>/del_invitee/<int:invitee_id>', methods=['POST','GET'])
@org_admin_or_super_required
def del_invitee(org_uuid,invitee_id):

   """deleting an existing invitee"""
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

   try:
        csrf_token = request.headers.get('X-CSRFToken')
        validate_csrf(csrf_token)

        # Extra security (not strictly necessary since already filtered above)
        if invitee.organization_id != org.id:
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        if current_user.is_super:
            db.session.delete(invitee)
            action = 'permanent_delete'

        elif current_user.is_org_admin and current_user.organization_id == org.id:
            invitee.deleted = True
            invitee.deleted_at = datetime.utcnow()
            invitee.deleted_by = current_user.id
            action = 'soft_delete'
        
        else:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

        db.session.commit()
        log_action(
            'delete',
            user_id=current_user.id if current_user.is_authenticated else None,
            record_type='invitee',
            record_id=invitee.id,
            associated_org_id=org.id
        )
        return jsonify({'status': 'success','message': 'Invitee deleted successfully'}), 200
   
   except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400
    

##################################################
# ............mark attendance function by Admins..................

@app_.route('/<uuid:org_uuid>/mark_invitee/<int:invitee_id>', methods=['POST'])
@admin_or_super_required
def mark_invitee(org_uuid, invitee_id):
    
    """Admins confirm or mark invitees attendance """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    
    is_authorized = False
    invitee = None # Initialize to None

    if current_user.is_super_admin:
    # Super Admins can mark attendance for any invitee in any organization.
        invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first_or_404()
        is_authorized = True
    elif current_user.is_org_admin and current_user.organization_id == org.id:
        # Org Admins can only mark attendance for invitees within THEIR OWN assigned organization.
        invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first_or_404()
        is_authorized = True
    elif current_user.is_location_admin and current_user.organization_id == org.id:
        invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first_or_404()
        is_authorized = True
    
    # If the user is not authorized by any of the above roles, deny access immediately.
    if not is_authorized:

        return jsonify({'status': 'error', 'message': 'You do not have permission to mark attendance for this organization or specific invitee.'}), 403 # Forbidden
    # At this point, 'invitee' is guaranteed to be a valid Invitee object that the
    # current user is authorized to modify.
    try:
        csrf_token = request.headers.get('X-CSRFToken')
        validate_csrf(csrf_token)
       
    except Exception as e:
         return jsonify({'status': 'error', 'message': 'CSRF token missing or invalid.'}), 403

    # Perform Attendance Marking Logic
    try:
       # Prevent re-marking if already 'Present'
        if invitee.confirmed == 'Present':
            return jsonify({'status': 'error', 'message': 'Invitee has already been marked as Present'}), 400

        invitee.confirmed = 'Present'
        invitee.confirmation_date = datetime.utcnow()

        db.session.add(invitee)
        db.session.commit()

        log_action('mark',user_id=current_user.id if current_user.is_authenticated else None,
            record_type='invitee',record_id=invitee.id,associated_org_id=org.id)
        
        return jsonify({'status': 'success', 'message': 'Invitee marked Present successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


###########################################################

@app_.route('/<uuid:org_uuid>/attendance/confirm', methods=['GET', 'POST'])
def confirm_attendance(org_uuid):

    """ opened to all invitees to self mark attendance """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    # org = Organization.query.filter_by(uuid=UUID(org_uuid)).first_or_404()
    
    now = datetime.utcnow()
    if now < registration_deadline:
        flash("You don't have access until 23rd May", "error")
        return redirect(url_for('inv.register', org_uuid=org.uuid))
    
    # Get the organization's location(s)
    org_locations = Location.query.filter_by(organization_id=org.id).all()
    
    if not org_locations:
        flash('Event location not set. Please contact the administrator.', 'error')
        return redirect(url_for('inv.register', org_uuid=org.uuid))
    
    form = AttendanceForm()
    
    if form.validate_on_submit():
        phone_number = form.phone_number.data
        user_latitude = form.latitude.data
        user_longitude = form.longitude.data
        
        # Find the invitee
        invitee = Invitee.query.filter_by(
            phone_number=phone_number, 
            organization_id=org.id
        ).first()
        
        if not invitee:
            flash('Records not found. Please register first.', 'danger')
            return redirect(url_for('inv.register', org_uuid=org.uuid))
        
        # Check if already confirmed
        if invitee.confirmed == 'Present':
            return render_template(
                'invitee_status.html',
                org_uuid=org.uuid,
                status='already_confirmed',
                invitee=invitee,
                message="Attendance already marked for this invitee."
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
                invitee=invitee,
                message=f"You are not within the event location. You are {min_distance:.0f}m away from the nearest venue.",
                distance=min_distance,
                closest_location=closest_location.name if closest_location else "Unknown"
            )
        
        # Update invitee with confirmation details
        invitee.latitude = user_latitude
        invitee.longitude = user_longitude
        invitee.confirmed = 'Present'
        invitee.status = 'confirmed'
        invitee.confirmation_date = datetime.utcnow()
        
        try:
            db.session.commit()
            
            # Log the action
            log_action(
                'Invitee Confirmed Attendance',
                user_id=current_user.id if current_user.is_authenticated else None,
                record_type='invitee',
                record_id=invitee.id,
                organization_id=org.id
            )
            
            return render_template(
                'invitee_status.html',
                org_uuid=org.uuid,
                status='confirmed',
                invitee=invitee,
                message="Attendance marked successfully.",
                location_name=closest_location.name if closest_location else "Event Location"
            )
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while confirming attendance. Please try again.', 'danger')
            return redirect(url_for('inv.confirm_attendance', org_uuid=org.uuid))
    
    return render_template(
        'confirm_attendance.html', 
        org_uuid=org.uuid,
        org=org,
        form=form,
        locations=org_locations  # Pass locations to template for display
    )

###############################################

def generate_qr_code(org_uuid, invitee_id):
    
    # Generate the URL for confirmation
    data = f"{request.host_url}{org_uuid}/confirm_qr_code_self/{invitee_id}"

#  # Generate the correct URL using Flask's url_for
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.
        constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )

    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    #if you dont want image saved on your server permanently
    byte_arr = io.BytesIO()
    img.save(byte_arr, format='PNG')
    byte_arr.seek(0)
    return base64.b64encode(byte_arr.getvalue()).decode('utf-8')


####################################################

@app_.route('/<uuid:org_uuid>/register', methods=['GET', 'POST'])
def register(org_uuid):
    now = datetime.now()
    
    # org = Organization.query.filter_by(uuid=UUID(org_uuid)).first_or_404()
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    if now < registration_deadline:
        flash("Registration is Closed.", "error")
        return redirect(url_for('inv.index', org_uuid=org.uuid))

    form = InviteeForm()

    # Populate LGA choices if state is selected
    if form.state.data:
        form.lga.choices = [(lga, lga) for lga in fetch_lgas(form.state.data)]
    
    if form.validate_on_submit():
        name = form.name.data.title()
        email = form.email.data.lower()
        phone_number = form.phone_number.data
        state = form.state.data
        gender = form.gender.data
        lga = form.lga.data
        address = form.address.data
        position = form.position.data.title()
        parish = form.parish.data
        area = form.area.data 
        
        existing_invitee = Invitee.query.filter(
            Invitee.organization_id == org.id,
            or_(Invitee.phone_number == phone_number, Invitee.email == email)
        ).first()
              
        
        if existing_invitee:
            flash("Member already exists.", "info")
            return redirect(url_for('inv.register', org_uuid=org.uuid))
        
        if "@" not in form.email.data:
            flash("Invalid email address.", "error")
            return redirect(url_for('inv.register', org_uuid=org.uuid))
        
        try:
            register_date = datetime.utcnow()
            new_invitee = Invitee(name=name,phone_number=phone_number,gender=gender, state=state,
                email=email,  area=area,address=address,parish=parish,position=position,
                lga=lga,register_date=register_date, organization_id=org.id 
            )
            db.session.add(new_invitee)
            db.session.commit()
            
            log_action(
                'add',
                user_id=current_user.id if current_user.is_authenticated else None,
                record_type='invitee', record_id=new_invitee.id, associated_org_id=org.id
            )

            # Generate QR code URL using org_uuid
            qr_code_path = url_for('inv.confirm_qr_code_self', org_uuid=org.uuid, invitee_id=new_invitee.id, _external=True)

            new_invitee.qr_code_path = qr_code_path
            db.session.commit()

            send_qr_code_email(new_invitee, qr_code_path)

            flash("Registration successful! A confirmation email has been sent!", "success")
            return redirect(url_for('inv.success', org_uuid=org.uuid, invitee_id=new_invitee.id))

        except smtplib.SMTPException as e:
            db.session.rollback()
            flash(f"Registration successful, but an error occurred while sending the email: {str(e)}", "error")
            return redirect(url_for('inv.register', org_uuid=org.uuid))

        except Exception as e:
            db.session.rollback()
            flash(f"Error saving to database: {str(e)}", "error")
            return redirect(url_for('inv.register', org_uuid=org.uuid))

    return render_template('register.html', form=form, org=org, org_uuid=org.uuid)


##########################################################
@app_.route('/<uuid:org_uuid>/edit_invitee/<int:id>', methods=['GET', 'POST'])
@admin_or_super_required
def edit_invitee(org_uuid, id):
    
    """Edit an existing invitee"""
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    
    
    state_lgas = fetch_lgas_all()

    now = datetime.utcnow() # Use UTC for consistency
    if now < registration_deadline:
        flash("Editing invitees is not allowed until the specified deadline.", "danger")
        # Consider redirecting to a page that explains the timeline
        return redirect(url_for('inv.show_invitees', org_uuid=org.uuid)) # Use org.uuid consistently
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

    invitee = Invitee.query.filter_by(id=id, organization_id=org.id).first_or_404()

    if request.method == 'POST':
        new_name = request.form['name']
        new_position = request.form['position']
        new_phone_number = request.form['phone_number']
        new_state = request.form['state']
        new_lga = request.form['lga']

        existing_invitee = Invitee.query.filter_by(phone_number=new_phone_number).first()
        if existing_invitee and existing_invitee.id != id:
            flash('Invitee already exists.', 'danger')
            return redirect(url_for('inv.edit_invitee', org_uuid=org.uuid, id=id))

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

        return redirect(url_for('inv.show_invitees', org_uuid=org.uuid))

    return render_template('edit_invitee.html', org=org, invitee=invitee,state_lgas=state_lgas, org_uuid=org.uuid)


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
@app_.route('/<uuid:org_uuid>/success/<int:invitee_id>')
def success(org_uuid, invitee_id):
    """
    Displays success page with QR code after invitee registration using secure UUID in URL.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first()
    if not invitee:
        return "Invitee not found", 404

    qr_code_path = generate_qr_code(org.uuid, invitee_id)  # Ensure it uses UUID now

    return render_template(
        'success.html',
        org=org,
        org_uuid=org.uuid,
        invitee=invitee,
        invitee_id=invitee.id,
        qr_code_path=qr_code_path
    )

############## admin scans invitee (him/herself) #############
@app_.route('/<uuid:org_uuid>/confirm_qr_code_self/<int:invitee_id>', methods=['GET'])
# @org_admin_required
@csrf.exempt
def confirm_qr_code_self(org_uuid, invitee_id):
    """
    Allows admin to confirm an invitee’s presence using secure UUID-based URL.
    """
    now = datetime.now()
    if now < registration_deadline:
        flash("Access restricted until 23rd May", "error")
        return redirect(url_for('inv.manage_invitee', org_uuid=org_uuid))

    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first()
    if not invitee:
        flash('Invitee not found.', 'danger')
        return redirect(url_for('inv.index', org_uuid=org_uuid))

    if invitee.deleted:
        return render_template(
            'login.html',
            org_uuid=org_uuid,
            status='deleted',
            invitee=invitee,
            message="This invitee has been removed from the list."
        )

    if invitee.confirmed == 'Present':
        return render_template(
            'invitee_status.html',
            org_uuid=org_uuid,
            status='already_confirmed',
            invitee=invitee,
            message="Invitee already confirmed."
        )

    try:
        invitee.confirmed = 'Present'
        invitee.confirmation_date = datetime.utcnow()
        db.session.commit()

        # log_action(
        log_action('self confirm invitee via QR',user_id=current_user.id if current_user.is_authenticated else None,
            record_type='invitee',record_id=invitee.id,associated_org_id=org.id)

        send_confirm_email(invitee)

        return render_template(
            'invitee_status.html',
            org_uuid=org_uuid,
            status='confirmed',
            invitee=invitee,
            message="Invitee confirmed successfully."
        )

    except Exception as e:
        db.session.rollback()
        flash(f'An unexpected error occurred: {str(e)}', 'danger')
        return redirect(url_for('inv.index', org_uuid=org_uuid))
  

#confirm email attendees

def send_confirm_email(invitee):
    try:
         
        msg = Message(
            "WELCOME TO RCCG YAYA 2025",
            sender="fac@fac.scrollintl.com",
            recipients=[invitee.email]
        )
        msg.html = f"""
                <p>Dear {invitee.name},</p>
                <p>Your Attendance is confirmed!</p>
                <p>Thank you for attending FAC 2025!<br></br>
                <p>God bless you!</p>

                <p>Thank you.</p>
                <p>FAC Team.</p>
                """
        mail.send(msg)
        print("Email sent successfully!")

    except smtplib.SMTPException as e:
        print(f"Error sending email: {e}")
        raise e


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
@app_.route('/<uuid:org_uuid>/get_qr_code/<int:invitee_id>')
def get_qr_code(org_uuid, invitee_id):
    """
    Returns the QR code path for the invitee using org UUID for security.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    qr_code_path = generate_qr_code(org.uuid, invitee_id)  # Make sure your function supports UUID
    return jsonify({'qr_code_path': qr_code_path})


####################################

@app_.route('/<uuid:org_uuid>/invitees')
@admin_or_super_required # This decorator already ensures one of the 3 admin types is logged in
def show_invitees(org_uuid):
    """
    Displays invitees for a specific organization,
    filtered by user role and optional search query.
    """

    try:
        # Use str(org_uuid) to ensure consistency with string-based UUIDs from filter_by
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except ValueError: # This ValueError catch is for if org_uuid couldn't be converted to UUID type
        flash('Invalid organization identifier.', 'danger')
        return redirect(url_for('inv.universal_login')) # Redirect to universal login if UUID is invalid

    # --- Role-based access control (Refined) ---
    invitees_query = None # Initialize to None

    if current_user.is_super_admin: # Use the correct property name
        # Super Admins can see all invitees for any organization
        invitees_query = Invitee.query.filter_by(organization_id=org.id)
    elif current_user.is_org_admin and current_user.organization_id == org.id:
        # Org Admins can only see invitees for their own organization
        invitees_query = Invitee.query.filter_by(organization_id=org.id)
    elif current_user.is_location_admin and current_user.organization_id == org.id:
        # Location Admins can see invitees for their specific organization
        # Optionally, add further filtering if they should only see invitees for their specific location
        # For now, let's assume they see all for their org, but you can refine:
        invitees_query = Invitee.query.filter_by(organization_id=org.id)
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
    pagination = invitees_query.order_by(Invitee.id.desc()).paginate(page=page, per_page=per_page, error_out=False)
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
        absent_female=absent_female,
        is_super=current_user.is_super_admin # Pass the correct property to the template
    )

# ######################################...............
@app_.route('/<uuid:org_uuid>/manage_invitee', methods=['GET', 'POST'])
@admin_or_super_required
def manage_invitee(org_uuid):
    """
    Allows super admins or org admins to search and manage invitees.
    Super admins can manage any organization's invitees.
    Org admins can only manage their own organization's invitees.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    # Role-based access control
    if not current_user.is_super_admin:
        if not (current_user.is_location_admin or current_user.is_org_admin) or current_user.organization_id != org.id:
            flash("You do not have permission to manage invitees for this organization.", "danger")
            return redirect(url_for('inv.login',org_uuid=org.uuid))

    # Base query
    invitees_query = Invitee.query.filter_by(deleted=False, organization_id=org.id)

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
        org=org,org_uuid=org.uuid,invitees=invitees,pagination=pagination,
        search=search, is_super=current_user.is_super)

#dummy testing........for offline..........................

def send_qr_code_email(invitee, qr_code_path):
    try:
        msg = Message(
            "Your Invite QR Code",
            sender="invite@fac.com",  # Replace with your sender email
            recipients=[invitee.email])
        
        msg.html = f"""
        <p>Dear {invitee.name},</p>
        <p>Thank you for registering. Below is your QR code:</p>
        <img src="data:image/png;base64,{qr_code_path}" alt="QR Code">
        <br></br>
        <p>Please this QR code will be needed to confirm your attendance.</p>
        <p>Thank you.</p>
        <p>FAC Team.</p>
        """
        mail.send(msg)
        print("Email sent successfully!")

    except smtplib.SMTPException as e:
        print(f"Error sending email: {e}")
        raise e

######################################################
@app_.route('/<uuid:org_uuid>/export_invitees', methods=['GET'])
@login_required
def export_invitees(org_uuid):
    if not current_user.can_export_invitees:
        flash('Access denied. You are not authorized to export invitees.', 'danger')
        return redirect(url_for('inv.login'))

    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    invitees = []
    pagination = None  # <-- define it here

    try:
        invitees_query = Invitee.query.filter_by(
            organization_id=org.id)

        page = request.args.get('page', 1, type=int)
        pagination = invitees_query.paginate(page=page, per_page=10)
        invitees = pagination.items

        if not invitees:
            flash('Records not found yet..', 'warning')
            return redirect(url_for('inv.show_invitees', org_uuid=org.uuid))

        data = [{
            'Name': i.name or '',
            'Phone': i.phone_number or '',
            'Gender': i.gender or '',
            'Email': i.email or '',
            'Parish': i.parish or '',
            'Area': i.area or '',
            'State': i.state or '',
            'LGA': i.lga or '',
            'Position': i.position or '',
            'Register Date': i.register_date.strftime('%Y-%m-%d') if i.register_date else '',
            'Confirmed': i.confirmed if i.confirmed is not None else ''
        } for i in invitees]

        df = pd.DataFrame(data)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Invitees')

        output.seek(0)
        return send_file(
            output,
            download_name="invitees_rccg.xlsx",
            as_attachment=True,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

    except Exception as e:
        flash(f'An error occurred while exporting data: {str(e)}', 'danger')
        return render_template(
            'invitees.html',
            org=org,
        org_uuid=org.uuid,
        invitees=invitees,
        pagination=pagination
    )



######################################################
@app_.route('/<uuid:org_uuid>/register_admin', methods=['GET', 'POST'])
@org_admin_or_super_required
# @super_required # Re-enable your super_required or org_admin_required decorator here
def register_admin(org_uuid):
    form = AdminForm()

    # Get the organization by UUID
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    if form.validate_on_submit():
        name = form.name.data.title()
        gender = form.gender.data
        email = form.email.data.lower()
        address = form.address.data.title()
        role = form.role.data
        phone_number = form.phone_number.data
        password = form.password.data 

        # Check for duplicates within the same org
        # IMPORTANT: Consider if phone_number should be unique *per organization* or globally.
        # The current query checks for uniqueness within the organization scope for email and phone.
        existing_admin = Admin.query.filter(
            Admin.organization_id == org.id,
            or_(Admin.phone_number == phone_number, Admin.email == email)
        ).first()

        if existing_admin:
            flash("An Admin with this phone number or email already exists in this organization.", "error")
            return redirect(url_for('inv.register_admin', org_uuid=org.uuid))

        try:
            # hashed_password = generate_password_hash(DEFAULT_PASSWORD, method='pbkdf2:sha256') # REMOVE OR MODIFY

            new_admin = Admin(name=name,gender=gender,phone_number=phone_number,
                address=address,created_at =datetime.utcnow(), # Keep for legacy if needed, or use 'created_at'
                email=email,
                role=role,
                # is_admin=True, # No longer strictly needed if 'role' is primary
                organization_id=org.id
            )
            
            # --- CRUCIAL CHANGE: Use new_admin.set_password() ---
            new_admin.set_password(password) 
         
            db.session.add(new_admin)
            db.session.commit()

            # Log the action (ensure current_user is available via @login_required)
            log_action('add', user_id=current_user.id, record_type='Admin', record_id=new_admin.id, associated_org_id=org.id)

            # --- UPDATED FLASH MESSAGE ---
            flash(f"Admin '{new_admin.name}' registered successfully. They can now log in with their chosen password.", "success")
                  
            # Assuming 'admin.management_dashboard' is now 'app_.management_dashboard'
            return redirect(url_for('admin.management_dashboard', org_uuid=org.uuid))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error registering admin: {str(e)}", exc_info=True)
            flash(f"Error saving to database: {str(e)}", "error")
            return render_template('register_admin.html', org=org, org_uuid=org.uuid, form=form) # Re-render form on error

    # For GET requests or validation failures, render the template
    return render_template('register_admin.html', org=org, org_uuid=org.uuid, form=form)


#............edit function....................

@app_.route('/<uuid:org_uuid>/edit_admin/<int:id>', methods=['GET', 'POST'])
@super_required
def edit_admin(org_uuid, id):

    # Get the organization using UUID
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    # Find the admin within this organization
    admin = Admin.query.filter_by(id=id, organization_id=org.id).first_or_404()

    if request.method == 'POST':
        # Get form data and strip whitespace
        new_name = request.form['name'].strip()
        new_email = request.form.get('email', '').strip()
        new_password = request.form['password'].strip()

        # Check for duplicate email in another admin
        existing_admin = Admin.query.filter_by(email=new_email).first()
        if existing_admin and existing_admin.id != id:
            flash('An admin with this email already exists.', 'danger')
            return redirect(url_for('inv.edit_admin', id=admin.id, org_uuid=org.uuid))
        
                # Password validation (if provided)
        if new_password:
            if len(new_password) < 6: # Example minimum length
                flash('Password must be at least 6 characters long.', 'danger')
                return redirect(url_for('inv.edit_admin', id=admin.id, org_uuid=org.uuid))
            admin.password = generate_password_hash(new_password)

        # Update admin fields
        admin.name = new_name
        admin.email = new_email
        if new_password:
            admin.password = generate_password_hash(new_password)

        admin.updated_at = datetime.utcnow()

        try:
            db.session.commit()
            log_action('edit',user_id=current_user.id if current_user.is_authenticated else None,
            record_type='Admin',record_id=admin.id,associated_org_id=org.id)
            flash('Admin updated successfully!', 'success')
            return redirect(url_for('inv.manage_admin',org_uuid=org.uuid))
                       
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')

        return render_template('edit_admin.html',admin=admin,org=org)

    return render_template('edit_admin.html',admin=admin,org=org)

  


# ............delete function..................

@app_.route('/<uuid:org_uuid>/del_admin/<int:admin_id>', methods=['POST'])
@super_required
def del_admin(org_uuid, admin_id):

    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    admin = Admin.query.filter_by(id=admin_id, organization_id=org.id).first_or_404()

    try:
        csrf_token = request.headers.get('X-CSRFToken')
        validate_csrf(csrf_token)

        if not admin:
            return jsonify({'status': 'error', 'message': 'Admin not found'}), 400

        if admin.organization.uuid != org_uuid:
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        # Delete permanently
        db.session.delete(admin)
        db.session.commit()
      
        log_action('delete',user_id=current_user.id if current_user.is_authenticated else None,
            record_type='Admin',record_id=admin.id,associated_org_id=org.id)
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

    pagination = admins_query.filter(Admin.is_super == False).order_by(Admin.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
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


@app_.route('/<uuid:org_uuid>/all_feedbacks')
# @org_admin_required
def all_feedback(org_uuid):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    all_feedback = Feedback.query.filter_by(organization_id=org.id).all()

    return render_template('all_feedbacks.html', org=org, org_uuid=org.uuid, all_feedback=all_feedback)

###################################################

# ....................................#

@app_.route('/<uuid:org_uuid>/locations')
@admin_or_super_required # This decorator is key for initial permission and org_uuid validation
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
            # description = request.form.get('description', '')
            address = request.form.get('address', '')
            latitude = float(request.form.get('latitude'))
            longitude = float(request.form.get('longitude'))
            radius = int(request.form.get('radius', 100))
            
            # Validation
            if not name:
                flash('Location name is required', 'danger')
                return redirect(request.url)
            
            if not (-90 <= latitude <= 90):
                flash('Invalid latitude. Must be between -90 and 90', 'danger')
                return redirect(request.url)
            
            if not (-180 <= longitude <= 180):
                flash('Invalid longitude. Must be between -180 and 180', 'danger')
                return redirect(request.url)
            
            # Create new location
            location = Location(name=name,address=address,latitude=latitude, longitude=longitude,
                radius=radius, organization_id=org.id, created_at=datetime.utcnow()
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
            # location.description = request.form.get('description', '')
            location.address = request.form.get('address', '')
            location.latitude = float(request.form.get('latitude'))
            location.longitude = float(request.form.get('longitude'))
            location.radius = int(request.form.get('radius', 100))
            location.is_active = bool(request.form.get('is_active'))
            
            # Validation
            if not location.name:
                flash('Location name is required', 'danger')
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
@app_.route('/<uuid:org_uuid>/add_event', methods=['GET', 'POST'])
@org_admin_or_super_required # Your custom decorator to restrict to org admins
def add_event(org_uuid):
    
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
        flash('You do not have the required permissions to add events for this organization.', 'danger')
        # Redirect to a safe, universal page or their authorized dashboard.
        return redirect(url_for('inv.universal_login'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        location_id = request.form.get('location_id')
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')
        is_active = request.form.get('is_active') == 'on'  # Checkbox handling

        # Validation
        if not name or not location_id or not start_time_str or not end_time_str:
            flash("All fields are required.", "danger")
            return redirect(url_for('inv.add_event', org_uuid=org.uuid))

        try:
            # Convert string dates to datetime objects
            start_time = datetime.fromisoformat(start_time_str)
            end_time = datetime.fromisoformat(end_time_str)
        except ValueError:
            flash("Invalid date format provided.", "danger")
            return redirect(url_for('inv.add_event', org_uuid=org.uuid))

        # Basic validation - check if end time is after start time
        if end_time <= start_time:
            flash("End time must be after start time.", "danger")
            return redirect(url_for('inv.add_event', org_uuid=org.uuid))

        # Convert location_id to integer and verify location belongs to this org
        try:
            location_id = int(location_id)
            location = Location.query.filter_by(id=location_id, organization_id=org.id).first()
            if not location:
                flash("Invalid location selected.", "danger")
                return redirect(url_for('inv.add_event', org_uuid=org.uuid))
        except (ValueError, TypeError):
            flash("Invalid location selected.", "danger")
            return redirect(url_for('inv.add_event', org_uuid=org.uuid))

        # Check if event with same name and location already exists for this organization
        existing_event = Event.query.filter_by(
            name=name, 
            location_id=location_id, 
            organization_id=org.id
        ).first()
        
        if existing_event:
            flash("An event with this name already exists at the selected location.", "danger")
            return redirect(url_for('inv.add_event', org_uuid=org.uuid))

        # Create event
        try:
            new_event = Event(
                name=name,
                location_id=location.id,
                organization_id=org.id,
                is_active=is_active,
                start_time=start_time,
                end_time=end_time
                # created_by=current_user.id
                # status='incoming'
            )
            db.session.add(new_event)
            db.session.commit()

            flash("Event created successfully.", "success")
            return redirect(url_for('inv.add_event', org_uuid=org.uuid))
            
        except Exception as e:
            db.session.rollback()
            # current_app.logger.error(f"Error creating event: {e}")
            flash("An error occurred while creating the event. Please try again.", "danger")
            return redirect(url_for('inv.add_event', org_uuid=org.uuid))

    # GET: Show form 
    locations = Location.query.filter_by(organization_id=org.id, is_active=True).all()
    return render_template('add_event.html', org=org, locations=locations)


@app_.route('/<uuid:org_uuid>/events', methods=['GET'])
@admin_or_super_required
def view_event(org_uuid):
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

    # Get summary statistics (optional)
    total_events = Event.query.filter_by(organization_id=org.id).count()
    active_events = Event.query.filter_by(organization_id=org.id, is_active=True).count()
    
    # Get upcoming events count (events that haven't ended yet)
    from datetime import datetime
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
        upcoming_events=upcoming_events
    )


@app_.route('/<uuid:org_uuid>/events/<int:event_id>/edit', methods=['GET', 'POST'])
@admin_or_super_required
def edit_event(org_uuid, event_id):
    """Edit an existing event"""
    
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
        return redirect(url_for('inv.view_event', org_uuid=org.uuid))

    # Role-based Access Control
    if current_user.is_super_admin:
        pass
    elif current_user.is_org_admin and current_user.organization_id == org.id:
        pass
    else:
        flash('You do not have the required permissions to edit this event.', 'danger')
        return redirect(url_for('inv.universal_login'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        location_id = request.form.get('location_id')
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')
        is_active = request.form.get('is_active') == 'on'

        # Validation
        if not name or not location_id or not start_time_str or not end_time_str:
            flash("All fields are required.", "danger")
            return redirect(url_for('inv.edit_event', org_uuid=org.uuid, event_id=event_id))

        try:
            # Convert string dates to datetime objects
            start_time = datetime.fromisoformat(start_time_str)
            end_time = datetime.fromisoformat(end_time_str)
        except ValueError:
            flash("Invalid date format provided.", "danger")
            return redirect(url_for('inv.edit_event', org_uuid=org.uuid, event_id=event_id))

        # Validate time range
        if end_time <= start_time:
            flash("End time must be after start time.", "danger")
            return redirect(url_for('inv.edit_event', org_uuid=org.uuid, event_id=event_id))

        # Verify location
        try:
            location_id = int(location_id)
            location = Location.query.filter_by(id=location_id, organization_id=org.id).first()
            if not location:
                flash("Invalid location selected.", "danger")
                return redirect(url_for('inv.edit_event', org_uuid=org.uuid, event_id=event_id))
        except (ValueError, TypeError):
            flash("Invalid location selected.", "danger")
            return redirect(url_for('inv.edit_event', org_uuid=org.uuid, event_id=event_id))

        # Check for duplicate events (excluding current event)
        existing_event = Event.query.filter(
            Event.name == name,
            Event.location_id == location_id,
            Event.organization_id == org.id,
            Event.id != event_id
        ).first()
        
        if existing_event:
            flash("An event with this name already exists at the selected location.", "danger")
            return redirect(url_for('inv.edit_event', org_uuid=org.uuid, event_id=event_id))

        # Update the event
        try:
            event.name = name
            event.location_id = location_id
            event.start_time = start_time
            event.end_time = end_time
            event.is_active = is_active
            
            db.session.commit()
            flash("Event updated successfully.", "success")
            return redirect(url_for('inv.view_event', org_uuid=org.uuid))
            
        except Exception as e:
            db.session.rollback()
            # current_app.logger.error(f"Error updating event: {e}")
            flash("An error occurred while updating the event. Please try again.", "danger")
            return redirect(url_for('inv.edit_event', org_uuid=org.uuid, event_id=event_id))

    # GET: Show edit form
    locations = Location.query.filter_by(organization_id=org.id, is_active=True).all()
    return render_template('edit_event.html', org=org, event=event, locations=locations)


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
        return redirect(url_for('inv.view_event', org_uuid=org.uuid))

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

    return redirect(url_for('inv.view_event', org_uuid=org.uuid))

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



def fetch_lgas(state):
    # Mock LGA data for each state
    state_lgas = {
    'Abia': ['Aba North', 'Aba South', 'Arochukwu', 'Bende', 'Ikwuano', 'Isiala Ngwa North', 'Isiala Ngwa South', 'Isuikwuato', 'Obi Ngwa', 'Ohafia', 'Osisioma', 'Ugwunagbo', 'Ukwa East', 'Ukwa West', 'Umuahia North', 'Umuahia South', 'Umu Nneochi'],
    'Adamawa': ['Demsa', 'Fufore', 'Ganye', 'Gayuk', 'Gombi', 'Grie', 'Hong', 'Jada', 'Lamurde', 'Madagali', 'Maiha', 'Mayo-Belwa', 'Michika', 'Mubi North', 'Mubi South', 'Numan', 'Shelleng', 'Song', 'Toungo', 'Yola North', 'Yola South'],
    'Akwa Ibom': ['Abak', 'Eastern Obolo', 'Eket', 'Esit Eket', 'Essien Udim', 'Etim Ekpo', 'Etinan', 'Ibeno', 'Ibesikpo Asutan', 'Ibiono Ibom', 'Ika', 'Ikono', 'Ikot Abasi', 'Ikot Ekpene', 'Ini', 'Itu', 'Mbo', 'Mkpat-Enin', 'Nsit-Atai', 'Nsit-Ibom', 'Nsit-Ubium', 'Obot Akara', 'Okobo', 'Onna', 'Oron', 'Oruk Anam', 'Udung-Uko', 'Ukanafun', 'Uruan', 'Urue-Offong/Oruko', 'Uyo'],
    'Anambra': ['Aguata', 'Anambra East', 'Anambra West', 'Anaocha', 'Awka North', 'Awka South', 'Ayamelum', 'Dunukofia', 'Ekwusigo', 'Idemili North', 'Idemili South', 'Ihiala', 'Njikoka', 'Nnewi North', 'Nnewi South', 'Ogbaru', 'Onitsha North', 'Onitsha South', 'Orumba North', 'Orumba South', 'Oyi'],
    'Bauchi': ['Alkaleri', 'Bauchi', 'Bogoro', 'Damban', 'Darazo', 'Dass', 'Gamawa', 'Ganjuwa', 'Giade', 'Itas/Gadau', 'Jama\'are', 'Katagum', 'Kirfi', 'Misau', 'Ningi', 'Shira', 'Tafawa Balewa', 'Toro', 'Warji', 'Zaki'],
    'Bayelsa': ['Brass', 'Ekeremor', 'Kolokuma/Opokuma', 'Nembe', 'Ogbia', 'Sagbama', 'Southern Ijaw', 'Yenagoa'],
    'Benue': ['Ado', 'Agatu', 'Apa', 'Buruku', 'Gboko', 'Guma', 'Gwer East', 'Gwer West', 'Katsina-Ala', 'Konshisha', 'Kwande', 'Logo', 'Makurdi', 'Obi', 'Ogbadibo', 'Ohimini', 'Oju', 'Okpokwu', 'Otukpo', 'Tarka', 'Ukum', 'Ushongo', 'Vandeikya'],
    'Borno': ['Abadam', 'Askira/Uba', 'Bama', 'Bayo', 'Biu', 'Chibok', 'Damboa', 'Dikwa', 'Gubio', 'Guzamala', 'Gwoza', 'Hawul', 'Jere', 'Kaga', 'Kala/Balge', 'Konduga', 'Kukawa', 'Kwaya Kusar', 'Mafa', 'Magumeri', 'Maiduguri', 'Marte', 'Mobbar', 'Monguno', 'Ngala', 'Nganzai', 'Shani'],
    'Cross River': ['Abi', 'Akamkpa', 'Akpabuyo', 'Bakassi', 'Bekwarra', 'Biase', 'Boki', 'Calabar Municipal', 'Calabar South', 'Etung', 'Ikom', 'Obanliku', 'Obubra', 'Obudu', 'Odukpani', 'Ogoja', 'Yakuur', 'Yala'],
    'Delta': ['Aniocha North', 'Aniocha South', 'Bomadi', 'Burutu', 'Ethiope East', 'Ethiope West', 'Ika North East', 'Ika South', 'Isoko North', 'Isoko South', 'Ndokwa East', 'Ndokwa West', 'Okpe', 'Oshimili North', 'Oshimili South', 'Patani', 'Sapele', 'Udu', 'Ughelli North', 'Ughelli South', 'Ukwuani', 'Uvwie', 'Warri North', 'Warri South', 'Warri South West'],
    'Ebonyi': ['Abakaliki', 'Afikpo North', 'Afikpo South (Edda)', 'Ebonyi', 'Ezza North', 'Ezza South', 'Ikwo', 'Ishielu', 'Ivo', 'Izzi', 'Ohaozara', 'Ohaukwu', 'Onicha'],
    'Edo': ['Akoko-Edo', 'Egor', 'Esan Central', 'Esan North-East', 'Esan South-East', 'Esan West', 'Etsako Central', 'Etsako East', 'Etsako West', 'Igueben', 'Ikpoba-Okha', 'Oredo', 'Orhionmwon', 'Ovia North-East', 'Ovia South-West', 'Owan East', 'Owan West', 'Uhunmwonde'],
    'Ekiti': ['Ado Ekiti', 'Efon', 'Ekiti East', 'Ekiti South-West', 'Ekiti West', 'Emure', 'Gbonyin', 'Ido Osi', 'Ijero', 'Ikere', 'Ikole', 'Ilejemeje', 'Irepodun/Ifelodun', 'Ise/Orun', 'Moba', 'Oye'],
    'Enugu': ['Aninri', 'Awgu', 'Enugu East', 'Enugu North', 'Enugu South', 'Ezeagu', 'Igbo Etiti', 'Igbo Eze North', 'Igbo Eze South', 'Isi Uzo', 'Nkanu East', 'Nkanu West', 'Nsukka', 'Oji River', 'Udenu', 'Udi', 'Uzo Uwani'],
    'Gombe': ['Akko', 'Balanga', 'Billiri', 'Dukku', 'Funakaye', 'Gombe', 'Kaltungo', 'Kwami', 'Nafada', 'Shongom', 'Yamaltu/Deba'],
    'Imo': ['Aboh Mbaise', 'Ahiazu Mbaise', 'Ehime Mbano', 'Ezinihitte', 'Ideato North', 'Ideato South', 'Ihitte/Uboma', 'Ikeduru', 'Isiala Mbano', 'Isu', 'Mbaitoli', 'Ngor Okpala', 'Njaba', 'Nkwerre', 'Nwangele', 'Obowo', 'Oguta', 'Ohaji/Egbema', 'Okigwe', 'Onuimo', 'Orlu', 'Orsu', 'Oru East', 'Oru West', 'Owerri Municipal', 'Owerri North', 'Owerri West'],
    'Jigawa': ['Auyo', 'Babura', 'Biriniwa', 'Birnin Kudu', 'Buji', 'Dutse', 'Gagarawa', 'Garki', 'Gumel', 'Guri', 'Gwaram', 'Gwiwa', 'Hadejia', 'Jahun', 'Kafin Hausa', 'Kaugama', 'Kazaure', 'Kiri Kasama', 'Kiyawa', 'Maigatari', 'Malam Madori', 'Miga', 'Ringim', 'Roni', 'Sule Tankarkar', 'Taura', 'Yankwashi'],
    'Kaduna': ['Birnin Gwari', 'Chikun', 'Giwa', 'Igabi', 'Ikara', 'Jaba', 'Jema\'a', 'Kachia', 'Kaduna North', 'Kaduna South', 'Kagarko', 'Kajuru', 'Kaura', 'Kauru', 'Kubau', 'Kudan', 'Lere', 'Makarfi', 'Sabon Gari', 'Sanga', 'Soba', 'Zangon Kataf', 'Zaria'],
    'Kano': ['Ajingi', 'Albasu', 'Bagwai', 'Bebeji', 'Bichi', 'Bunkure', 'Dala', 'Dambatta', 'Dawakin Kudu', 'Dawakin Tofa', 'Doguwa', 'Fagge', 'Gabasawa', 'Garko', 'Garun Mallam', 'Gaya', 'Gezawa', 'Gwale', 'Gwarzo', 'Kabo', 'Kano Municipal', 'Karaye', 'Kibiya', 'Kiru', 'Kumbotso', 'Kunchi', 'Kura', 'Madobi', 'Makoda', 'Minjibir', 'Nasarawa', 'Rano', 'Rimin Gado', 'Rogo', 'Shanono', 'Sumaila', 'Takai', 'Tarauni', 'Tofa', 'Tsanyawa', 'Tudun Wada', 'Ungogo', 'Warawa', 'Wudil'],
    'Katsina': ['Bakori', 'Batagarawa', 'Batsari', 'Baure', 'Bindawa', 'Charanchi', 'Dandume', 'Danja', 'Dan Musa', 'Daura', 'Dutsi', 'Dutsin Ma', 'Faskari', 'Funtua', 'Ingawa', 'Jibia', 'Kafur', 'Kaita', 'Kankara', 'Kankia', 'Katsina', 'Kurfi', 'Kusada', 'Mai\'Adua', 'Malumfashi', 'Mani', 'Mashi', 'Matazu', 'Musawa', 'Rimi', 'Sabuwa', 'Safana', 'Sandamu', 'Zango'],
    'Kebbi': ['Aleiro', 'Arewa Dandi', 'Argungu', 'Augie', 'Bagudo', 'Birnin Kebbi', 'Bunza', 'Dandi', 'Fakai', 'Gwandu', 'Jega', 'Kalgo', 'Koko/Besse', 'Maiyama', 'Ngaski', 'Sakaba', 'Shanga', 'Suru', 'Danko/Wasagu', 'Yauri', 'Zuru'],
    'Kogi': ['Adavi', 'Ajaokuta', 'Ankpa', 'Bassa', 'Dekina', 'Ibaji', 'Idah', 'Igalamela Odolu', 'Ijumu', 'Kabba/Bunu', 'Kogi', 'Lokoja', 'Mopa-Muro', 'Ofu', 'Ogori/Magongo', 'Okehi', 'Okene', 'Olamaboro', 'Omala', 'Yagba East', 'Yagba West'],
    'Kwara': ['Asa', 'Baruten', 'Edu', 'Ekiti', 'Ifelodun', 'Ilorin East', 'Ilorin South', 'Ilorin West', 'Irepodun', 'Isin', 'Kaiama', 'Moro', 'Offa', 'Oke Ero', 'Oyun', 'Pategi'],
    'Lagos': ['Agege', 'Ajeromi-Ifelodun', 'Alimosho', 'Amuwo-Odofin', 'Apapa', 'Badagry', 'Epe', 'Eti-Osa', 'Ibeju-Lekki', 'Ifako-Ijaiye', 'Ikeja', 'Ikorodu', 'Kosofe', 'Lagos Island', 'Lagos Mainland', 'Mushin', 'Ojo', 'Oshodi-Isolo', 'Shomolu', 'Surulere'],
    'Nasarawa': ['Akwanga', 'Awe', 'Doma', 'Karu', 'Keana', 'Keffi', 'Kokona', 'Lafia', 'Nasarawa', 'Nasarawa Egon', 'Obi', 'Toto', 'Wamba'],
    'Niger': ['Agaie', 'Agwara', 'Bida', 'Borgu', 'Bosso', 'Chanchaga', 'Edati', 'Gbako', 'Gurara', 'Katcha', 'Kontagora', 'Lapai', 'Lavun', 'Magama', 'Mariga', 'Mashegu', 'Mokwa', 'Muya', 'Paikoro', 'Rafi', 'Rijau', 'Shiroro', 'Suleja', 'Tafa', 'Wushishi'],
    'Ogun': ['Abeokuta North', 'Abeokuta South', 'Ado-Odo/Ota', 'Ewekoro', 'Ifo', 'Ijebu East', 'Ijebu North', 'Ijebu North East', 'Ijebu Ode', 'Ikenne', 'Imeko Afon', 'Ipokia', 'Obafemi Owode', 'Odeda', 'Odogbolu', 'Ogun Waterside', 'Remo North', 'Shagamu', 'Yewa North', 'Yewa South'],
    'Ondo': ['Akoko North-East', 'Akoko North-West', 'Akoko South-East', 'Akoko South-West', 'Akure North', 'Akure South', 'Ese Odo', 'Idanre', 'Ifedore', 'Ilaje', 'Ile Oluji/Okeigbo', 'Irele', 'Odigbo', 'Okitipupa', 'Ondo East', 'Ondo West', 'Ose', 'Owo'],
    'Osun': ['Aiyedaade', 'Aiyedire', 'Atakunmosa East', 'Atakunmosa West', 'Boluwaduro', 'Boripe', 'Ede North', 'Ede South', 'Egbedore', 'Ejigbo', 'Ife Central', 'Ife East', 'Ife North', 'Ife South', 'Ifedayo', 'Ifelodun', 'Ila', 'Ilesha East', 'Ilesha West', 'Irepodun', 'Irewole', 'Isokan', 'Iwo', 'Obokun', 'Odo Otin', 'Ola Oluwa', 'Olorunda', 'Oriade', 'Orolu', 'Osogbo'],
    'Oyo': ['Afijio', 'Akinyele', 'Atiba', 'Atisbo', 'Egbeda', 'Ibadan North', 'Ibadan North-East', 'Ibadan North-West', 'Ibadan South-East', 'Ibadan South-West', 'Ibarapa Central', 'Ibarapa East', 'Ibarapa North', 'Ido', 'Irepo', 'Iseyin', 'Itesiwaju', 'Iwajowa', 'Kajola', 'Lagelu', 'Ogo Oluwa', 'Ogbomosho North', 'Ogbomosho South', 'Olorunsogo', 'Oluyole', 'Ona Ara', 'Orelope', 'Ori Ire', 'Oyo East', 'Oyo West', 'Saki East', 'Saki West', 'Surulere'],
    'Plateau': ['Barkin Ladi', 'Bassa', 'Bokkos', 'Jos East', 'Jos North', 'Jos South', 'Kanam', 'Kanke', 'Langtang North', 'Langtang South', 'Mangu', 'Mikang', 'Pankshin', 'Qua\'an Pan', 'Riyom', 'Shendam', 'Wase'],
    'Rivers': ['Abua/Odual', 'Ahoada East', 'Ahoada West', 'Akuku Toru', 'Andoni', 'Asari-Toru', 'Bonny', 'Degema', 'Eleme', 'Emohua', 'Etche', 'Gokana', 'Ikwerre', 'Khana', 'Obio-Akpor', 'Ogba/Egbema/Ndoni', 'Ogu/Bolo', 'Okrika', 'Omuma', 'Opobo/Nkoro', 'Oyigbo', 'Port Harcourt', 'Tai'],
    'Sokoto': ['Binji', 'Bodinga', 'Dange Shuni', 'Gada', 'Goronyo', 'Gudu', 'Gwadabawa', 'Illela', 'Isa', 'Kebbe', 'Kware', 'Rabah', 'Sabon Birni', 'Shagari', 'Silame', 'Sokoto North', 'Sokoto South', 'Tambuwal', 'Tangaza', 'Tureta', 'Wamako', 'Wurno', 'Yabo'],
    'Taraba': ['Ardo Kola', 'Bali', 'Donga', 'Gashaka', 'Gassol', 'Ibi', 'Jalingo', 'Karim Lamido', 'Kurmi', 'Lau', 'Sardauna', 'Takum', 'Ussa', 'Wukari', 'Yorro', 'Zing'],
    'Yobe': ['Bade', 'Bursari', 'Damaturu', 'Fika', 'Fune', 'Geidam', 'Gujba', 'Gulani', 'Jakusko', 'Karasuwa', 'Machina', 'Nangere', 'Nguru', 'Potiskum', 'Tarmuwa', 'Yunusari', 'Yusufari'],
    'Zamfara': ['Anka', 'Bakura', 'Birnin Magaji/Kiyaw', 'Bukkuyum', 'Bungudu', 'Chafe', 'Gummi', 'Gusau', 'Kaura Namoda', 'Maradun', 'Maru', 'Shinkafi', 'Talata Mafara', 'Zurmi'],
    'Fct': ['Abaji', 'Bwari', 'Gwagwalada', 'Kuje', 'Kwali', 'Municipal Area Council (AMAC)'],
    'Intl': ['Diaspora'],
   
}
    
    return state_lgas.get(state, [])

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
    
    # If the user is already logged in, no need to reset password
    if current_user.is_authenticated:
        return redirect(url_for('inv.login'))  # Replace with your default logged-in page

    form = RequestResetForm() # This form will just have an email field

    if form.validate_on_submit():
        admin = Admin.query.filter_by(email=form.email.data).first()
        if admin:
            token = generate_reset_token(admin.email)
            send_password_reset_email(admin.email, token)
            flash('A password reset link has been sent to your email.', 'info')
        else:
            # Send a generic message to prevent email enumeration
            flash('If an account with that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('inv.login',org_uuid=org.uuid)) # Redirect to login or a static info page

    return render_template('forgot_password_request.html', form=form,org=org)


@app_.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):

    # org = Organization.query.filter_by(uuid=org.uuid).first_or_404()
    org = Organization.query.all()
    # If the user is already logged in, no need to reset password
    if current_user.is_authenticated:
        return redirect(url_for('inv.login'))

    email = verify_reset_token(token)
    if email is None:
        flash('That is an invalid or expired token.', 'warning')
        return redirect(url_for('inv.forgot_password_request'))

    admin = Admin.query.filter_by(email=email).first()
    if not admin: # Should not happen if token verification worked, but as a safeguard
        flash('Account not found.', 'danger')
        return redirect(url_for('inv.forgot_password_request'))

    form = ResetPasswordForm() # This form will have password and confirm_password fields

    if form.validate_on_submit():
        admin.set_password(form.password.data) # Use the set_password method
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('inv.universal_login')) # Redirect to login

    return render_template('reset_password.html', form=form, token=token,org=org)






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
            return render_template('emails/invitation_confirm.html', invitation=invitation, token=token)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('emails/invitation_confirm.html', invitation=invitation, token=token)

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



# def send_qr_code_email(invitee, invite_id):
#     try:
#         success_page_url = f"https://fac.scrollintl.com/success/{invitee.id}"
        
#         msg = Message(
#             "Your RCCG QR Code",
#             sender="fac@fac.scrollintl.com",
#             recipients=[invitee.email]
#         )
#         msg.html = f"""
#         <p>Dear {invitee.name},</p>
#         <p>Thank you for registering. Click the button below to view your QR code:</p>
#           <br></br>
        
#           <p><a href="{success_page_url}"></a></p>
        
#          <p><a href="{success_page_url}" style="padding: 10px 20px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px;">View Your QR Code</a></p>
#         <br></br>
#         <p>Please this QR code will be needed to confirm your attendance, or you can scan QR shared with you at Living Stone Parish, Behind 5 Fingers,Tunga Minna.</p>
#         <p>Thank you.</p>
#         <p>NIGER 1 RCCG Team.</p>
#         """
#         mail.send(msg)
#         print("Email sent successfully!")

#     except smtplib.SMTPException as e:
#         print(f"Error sending email: {e}")
#         raise e
