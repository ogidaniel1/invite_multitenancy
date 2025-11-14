import os
from flask_wtf import FlaskForm
from functools import wraps
from datetime import datetime, timezone
from flask import request, redirect, url_for, flash,jsonify
from datetime import datetime
from wtforms import SubmitField
from wtforms import StringField, SubmitField,SelectField,HiddenField, FloatField,PasswordField,BooleanField
from wtforms.validators import DataRequired, Email, EqualTo,Length,ValidationError,Optional,Regexp
# from utils import load_config, generate_db_uri
from flask_wtf.file import FileAllowed, FileRequired, FileField,FileSize
from dotenv import load_dotenv
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

import pymysql
pymysql.install_as_MySQLdb()  #install mysql

import re 
from io import BytesIO
from config import Config
# ,org_admin_required,super_required
import uuid
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import func
from datetime import datetime
from app import db

from flask import current_app
from datetime import datetime
from time import time
from app import db, login_manager
from flask_login import UserMixin
from config import Config
from flask import Blueprint,session

# Load environment variables
load_dotenv()


# Configuration
DEFAULT_ADMIN_EMAIL = os.getenv('DEFAULT_ADMIN_EMAIL')
DEFAULT_ADMIN_PASSWORD = os.getenv('DEFAULT_ADMIN_PASSWORD')
 

# login_manager = LoginManager()
# # login_manager.init_app(app)

# @login_manager.user_loader
# def load_user(admin_id):
#     return Admin.query.get(int(admin_id))


@login_manager.user_loader
def load_user(user_id):
    """
    Dynamically load either an Admin or an Invitee based on session.
    """
    role = session.get("user_role")  # check who logged in

    if role == "admin":
        return Admin.query.get(int(user_id))
    elif role == "invitee":
        return Invitee.query.get(int(user_id))

    # fallback — check both if no role found in session
    user = Admin.query.get(int(user_id))
    if not user:
        user = Invitee.query.get(int(user_id))
    return user


def create_default_admin():
    # Attempt to get an existing organization, or create a 'System' one if none exists
    # Or, if you know a specific org ID for the default admin, use that.
    organization = Organization.query.first()
    if not organization:
        # Create one if none exists, or a specific 'System' org
        organization = Organization(name="System", slug="system-org") # Changed name to 'System' for clarity
        db.session.add(organization)
        db.session.flush()  # Ensure the ID is available for new_admin

    default_admin = Admin.query.filter_by(email=DEFAULT_ADMIN_EMAIL).first()
    if not default_admin:
        new_admin = Admin(
        email=DEFAULT_ADMIN_EMAIL,
        gender='Unknown',
        name='Default Admin',
        phone_number='+23490-ask-Admin',
        
        # is_super=True, # No longer needed if 'role' is the primary source of truth
        role='super_admin', # Explicitly set the role string
        organization=organization # Link to the organization object directly
        )

        new_admin.set_password(DEFAULT_ADMIN_PASSWORD) # This hashes and assigns to password_hash

        db.session.add(new_admin)
        db.session.flush()  # Ensures data integrity before committing
        db.session.commit()
        print("Default super admin created successfully!")
        # If you have a logger, use it:
        # current_app.logger.info("Default super admin created successfully!")
    else:
        print("Default super admin already exists.")
        # current_app.logger.info("Default super admin already exists.")


#######################################################


# decorators..................
# ------------------- Admin or Super Required -------------------
def admin_or_super_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please log in first to access this page.", "warning")
            return redirect(url_for('inv.universal_login'))

        # Explicitly disallow non-admin roles (invitee, farmer, etc.)
        if getattr(current_user, "role", "") in ["invitee", "farmer", "guest"]:
            flash("You are not authorized to access this section.", "danger")
            return redirect(url_for('inv.universal_login'))

        if not (current_user.is_super_admin or current_user.is_org_admin or current_user.is_location_admin):
            flash("Insufficient permissions to access this page.", "danger")
            return redirect(url_for('inv.universal_login'))

        return f(*args, **kwargs)
    return decorated_function


# ------------------- Org Admin or Super Required -------------------
def org_admin_or_super_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please log in first to access this page.", "warning")
            return redirect(url_for('inv.universal_login'))

        if getattr(current_user, "role", "") in ["invitee", "farmer", "guest"]:
            flash("You are not authorized to access this section.", "danger")
            return redirect(url_for('inv.universal_login'))

        if not (current_user.is_super_admin or current_user.is_org_admin):
            flash("You do not have sufficient permissions.", "danger")
            return redirect(url_for('inv.universal_login'))

        return f(*args, **kwargs)
    return decorated_function


# ------------------- Super Admin Only -------------------
def super_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please log in to access this page.", "info")
            return redirect(url_for('inv.login', org_uuid=''))

        if not current_user.is_super_admin:
            flash("Super admin access required.", "danger")
            return redirect(url_for('inv.login', org_uuid=''))

        return f(*args, **kwargs)
    return decorated_function


def invitee_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (current_user.is_authenticated and current_user.is_invitee):
            flash("Access restricted to invitees only.", "danger")
            return redirect(url_for('inv.universal_login'))
        return f(*args, **kwargs)
    return decorated_function



# -------------authorised users not decorators------#

def is_authorized_user(current_user, org, event=None):

    # Handle anonymous (not logged in)
    if not getattr(current_user, "is_authenticated", False):
        return False, "anonymous"

    # Super Admins → full access
    if getattr(current_user, "is_super_admin", False):
        return True, "super_admin"

    # Organization Admins → access within their org
    if getattr(current_user, "is_org_admin", False) and current_user.organization_id == org.id:
        return True, "org_admin"

    # Location Admins → access only if event matches their location
    if getattr(current_user, "is_location_admin", False) and current_user.organization_id == org.id:
        if getattr(current_user, "location_id", None) and getattr(event, "location_id", None):
            if str(current_user.location_id) == str(event.location_id):
                return True, "location_admin"

    # Logged-in Invitee → can self-check-in within their org
    if getattr(current_user, "role", "") == "invitee" and current_user.organization_id == org.id:
        return True, "invitee"

    # Default → not authorized
    return False, "unauthorized"

# ........................................
class RoleSafetyMixin:
    """Provides safe defaults for role-based checks so Invitees won't break decorators."""

    @property
    def is_super_admin(self):
        return getattr(self, "role", "") == "super_admin"

    @property
    def is_org_admin(self):
        return getattr(self, "role", "") == "org_admin"

    @property
    def is_location_admin(self):
        return getattr(self, "role", "") == "location_admin"

    @property
    def is_invitee(self):
        return getattr(self, "role", "") == "invitee"
    
 
# Models
class Admin(UserMixin,RoleSafetyMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=True)
    address = db.Column(db.String(200))
    
    # Keep your existing fields
    name = db.Column(db.String(120), nullable=True)  # Your original field
    phone_number = db.Column(db.String(15), unique=True, nullable=True)  #it is not required to invite admins
    gender = db.Column(db.String(100), nullable=True)
    
    # Keep your existing boolean flags AND add role field
    is_admin = db.Column(db.Boolean, default=False)  # Your original field
    is_super = db.Column(db.Boolean, default=False)  # Your original field
    role = db.Column(db.String(50), nullable=False) # Changed to nullable=False as it's required during invitation
    
    is_active = db.Column(db.Boolean, default=True)  # New field for views
    last_login = db.Column(db.DateTime, nullable=True)  # New field for views
    
    # Keep your existing timestamp fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow) # Added onupdate

    # self referncing of who does what 
    invited_by_admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True) # Make it nullable=True if super admins aren't invited
    # This relationship allows you to access the Admin object of the inviter
    invited_by_admin = db.relationship('Admin', remote_side=[id], backref='invited_admins_list')
        
     #creating relationship between location and admin, location and organization 
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=True)

    organization = db.relationship('Organization', backref='admins')
    location = db.relationship('Location', backref=db.backref('admins', lazy=True))
    

    @property
    def can_export_invitees(self):
        return Config.can_export_invitees(self)
      # Add property to sync role with boolean flags

    @property
    def is_super_admin(self): # New property name for clarity
        return self.role == 'super_admin'

    @property
    def is_org_admin(self): # New property name for clarity
        return self.role == 'org_admin'
    
    @property
    def is_location_admin(self):
        return self.role == 'location_admin'

    
    def set_password(self, password):
        """Hashes the given password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the given password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'organization': self.organization.name if self.organization else None,
            'organization_id': self.organization_id,
            'role': self.role,
            'is_active': self.is_active,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat()
        }   


class Invitee(UserMixin,RoleSafetyMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(15), nullable=False)
    state = db.Column(db.String(100), nullable=True)
    lga = db.Column(db.String(100), nullable=True)
    address = db.Column(db.String(200))
    gender = db.Column(db.String(100), nullable=True)
    position = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(120), nullable=True) #reguired null=false
    is_active = db.Column(db.Boolean, default=True)  # New field for views
    
    register_date = db.Column(db.DateTime, nullable=True)
    deleted = db.Column(db.Boolean, default=False)
    confirmed = db.Column(db.String(20), default='Absent')  # New field to track confirmation
    confirmation_date = db.Column(db.DateTime, nullable=True)  # New field to store confirmation timestamp
    latitude = db.Column(db.Float, nullable=True)  # Corrected the definition
    longitude = db.Column(db.Float, nullable=True)  # Corrected the definition
    status = db.Column(db.String(50)) #"confirmed", "out of range"
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    organization = db.relationship('Organization', backref='invitees')

    event_links = db.relationship("EventInvitee", back_populates="invitee", cascade='all, delete-orphan', lazy = "select")
   
    @property
    def events(self):
        return [link.event for link in self.event_links]


    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'address': self.address,
            'password': self.password_hash,
            'phone_number': self.phone_number,
            'state': self.state,
            'lga': self.lga,
            'gender': self.gender,
            'position': self.position,
            'register_date': self.register_date.isoformat() if self.register_date else None,
            'deleted': self.deleted,
            'confirmed': self.confirmed,
            'confirmation_date': self.confirmation_date.isoformat() if self.confirmation_date else None,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'status': self.status, # This 'status' field is separate from 'confirmed' as per schema
            'organization': {
                'id': self.organization.id,
                'name': self.organization.name
            } if self.organization else None,
            'organization_id': self.organization_id
        }
    
       
    # password for invitee
    
    def set_password(self, password):
        """Hashes the given password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the given password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    @property
    def is_invitee(self):
        return True
    

    def get_id(self):
        return str(self.id)
    


class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    # uuid = db.Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, nullable=False)
    uuid = db.Column(UUID(as_uuid=True), unique=True, default=lambda: uuid.uuid4(), nullable=False)

    slug = db.Column(db.String(50), unique=True, nullable=False)  # Used in URLs
    logo_url = db.Column(db.String(255), nullable=True)  # Optional logo
    address = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'address': self.address,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat()
        }

    def get_active_locations(self):
        """Get all active locations for this organization"""
        return Location.query.filter_by(organization_id=self.id,is_active=True).all()
    
    def __repr__(self):
        return f'<Organization {self.id}: {self.name}>'
   
    @property
    def is_org_admin(self):
        return self.role == 'admin'
    

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)  # Name of the location/venue
    slug = db.Column(db.String(100), unique=True, nullable=True)  # New field
    description = db.Column(db.String(500), nullable=True)  # New field
    address = db.Column(db.String(500), nullable=True)  # New field
    created_at = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    latitude = db.Column(db.Float, nullable=False)  # Required for location verification
    longitude = db.Column(db.Float, nullable=False)  # Required for location verification
    radius = db.Column(db.Integer, default=100)  # Acceptable radius in meters (default 100m)
    is_active = db.Column(db.Boolean, default=True)  # Allow admin to enable/disable locations
    
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    organization = db.relationship('Organization', backref='locations')
    
    def __repr__(self):
        return f'<Location {self.name} ({self.latitude}, {self.longitude})>'
    
    def is_within_range(self, user_lat, user_lng):
        """Check if user coordinates are within this location's acceptable range"""
        from geopy.distance import geodesic
        
        venue_location = (self.latitude, self.longitude)
        user_location = (user_lat, user_lng)
        distance = geodesic(venue_location, user_location).meters
        
        return distance <= self.radius, distance

    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'address': self.address,
            'organization': self.organization.name if self.organization else None,
            'organization_id': self.organization_id,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat()
             }
    

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    organization = db.relationship('Organization', backref=db.backref('events', lazy=True))
    description = db.Column(db.Text, nullable=True)  # Additional description
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    location = db.relationship('Location', backref=db.backref('events', lazy=True))
    event_logo_url = db.Column(db.String(255), nullable=True)  # Optional logo
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)  # New field for views
    status = db.Column(db.String(50), default='upcoming') # upcoming, active, past
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # invitees =db.relationship("Invitee", secondary=event_invitees, 
    #                         backref=db.backref('events', lazy="dynamics"))
    invitee_links = db.relationship("EventInvitee", back_populates="event",cascade ='all, delete-orphan', lazy="dynamic")

    @property
    def computed_status(self):
        now = datetime.utcnow()
        if self.end_time and self.end_time < now:
            return "Past"
        elif self.start_time and self.start_time > now:
            return "Upcoming"
        else:
            return "Ongoing"
    @property
    def invitees(self):
        return [link.invitee for link in self.invitee_links]


    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'organization': self.organization.name if self.organization else None,
            'organization_id': self.organization_id,
            'location': self.location.name if self.location else None,
            'location_id': self.location_id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'is_active': self.is_active,
            'status': self.status,
            'created_at': self.created_at.isoformat()
        }

class Invitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')
    token = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())) # UUID is 36 chars
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    invited_by_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    organization = db.relationship('Organization', backref='invitations')
    invited_by = db.relationship('Admin', backref='sent_invitations')

    def __repr__(self):
        return f"<Invitation {self.email} ({self.status})>"

    # You might also want methods to check expiry or generate a new token
    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def generate_new_token(self):
        self.token = str(uuid.uuid4())


class EventInvitee(db.Model):
    __tablename__ = 'event_invitees'
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), primary_key=True)
    invitee_id = db.Column(db.Integer, db.ForeignKey('invitee.id'), primary_key=True)

    # extra columns
    status = db.Column(db.String(20), default="pending")
    responded_at = db.Column(db.DateTime)
    confirmed_lat = db.Column(db.Numeric(9,6))
    confirmed_lng = db.Column(db.Numeric(9,6))
    attended = db.Column(db.Boolean, default=False)
    # qrcode stored per invitee - events
    qr_code_path = db.Column(db.String(200), nullable=True)

    event = db.relationship("Event", back_populates="invitee_links")
    invitee = db.relationship("Invitee", back_populates="event_links")


    # event.invitees -> means list of invitees
    # invitee.events -> means list of events they are invited to

    # query for upcoming events
    # upcoming_events.filter(Event.start_time>=datetime.utcnow(),Event.is_active == True).all())

class Feedback(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(100), nullable=False)
    comments = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)  # Adjust based on requirements
    gender = db.Column(db.String(100), nullable=True)
    deleted = db.Column(db.Boolean, default=False)
    qr_code_path = db.Column(db.String(200), nullable=True) #optional
    submit_feedback_date = db.Column(db.DateTime, nullable=True)  # New field to store confirmation timestamp
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    organization = db.relationship('Organization', backref='feedbacks')

    # linking eventInvitee to feedbacks for stats.
    event_id = db.Column(db.Integer,db.ForeignKey('event.id'), nullable=True)
    event = db.relationship('Event', backref='feedbacks')

# query on the route like this
# stats (db.session.query(Event.name, func.count(EventInvitee.invitee_id)).join(EventInvitee, Event.id ==EventInvitee.event_id)
# .filter(EventInvitee.attended == True).group_by(Event.name).all())



class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer,db.ForeignKey('event.id'), nullable=True)
    invitee_id = db.Column(db.Integer,db.ForeignKey('invitee.id'), nullable=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    attendance_date = db.Column(db.Date, nullable = False)
    check_in_time = db.Column(db.DateTime, default=datetime.utcnow)
    check_out_time = db.Column(db.DateTime, nullable=True)
    status= db.Column(db.Boolean, default=True)
     
    #relationships
    invitee = db.relationship('Invitee', backref='attendances')
    event = db.relationship('Event', backref='attendances')
    organization = db.relationship('Organization', backref='attendances')

    #prevent duplicate check in per event/day/invitee
    __table_args__ = ( db.UniqueConstraint("event_id", "invitee_id", "attendance_date", name="uq_event_invitee_date"),)


class DeleteLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    record_type = db.Column(db.String(50), nullable=False)  # e.g., 'Member', 'Invitee'
    record_id = db.Column(db.Integer, nullable=False)       # ID of the deleted record
    deleted_by = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    deleted_at = db.Column(db.DateTime, default=datetime.utcnow)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)


class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(50), nullable=False)  # e.g., 'create', 'edit', 'delete'
    user_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)  # Admin who performed the action
    record_type = db.Column(db.String(50), nullable=True)   # E.g., 'invitee', 'member'
    record_id = db.Column(db.Integer, nullable=True)        # ID of the affected record
    deleted_at = db.Column(db.DateTime, default=datetime.utcnow)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)  #allow super admin perform several actions

    # Relationship to Admin
    admin = db.relationship('Admin', backref='action_logs')

    def __repr__(self):
        return f'<ActionLog {self.action_type} by {self.user_id} on {self.record_type} {self.record_id}>'


#############################################


#####################################################################

POSITION = [('', 'Select Position'),('Attendee', 'Attendee'),('Volunteer', 'Volunteer'),( 'Guest','Guest Minister')]
GENDER_CHOICES = [('', 'Select Gender'), ('Male', 'Male'), ('Female', 'Female')]
ADMIN_ROLES = [('', 'Select Role'), ('Org Admin', 'Org Admin'), ('Normal Admin', 'Normal Admin')]


class InviteeForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email(message="Invalid email address")])
    address = StringField('Residential Address', validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired(message="Phone number is required."), 
                    Length(min=11, max=15), Regexp(regex=r'^(\+?[1-9]\d{7,14}|0\d{7,14})$', message="Phone number must be valid")])

    password = PasswordField('Password', validators=[
        Optional(),
        Length(min=8, message='Password must be at least 8 characters long.')
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        Optional(),
        EqualTo('password', message='Passwords must match.')
    ])
    # State SelectField
    state = SelectField('State of Residence', choices=[ ('', 'Select State'),
        ('Abia', 'Abia'), ('Adamawa', 'Adamawa'), ('Akwa Ibom', 'Akwa Ibom'),
        ('Anambra', 'Anambra'), ('Bauchi', 'Bauchi'), ('Bayelsa', 'Bayelsa'),
        ('Benue', 'Benue'), ('Borno', 'Borno'), ('Cross River', 'Cross River'),
        ('Delta', 'Delta'), ('Ebonyi', 'Ebonyi'), ('Edo', 'Edo'), ('Ekiti', 'Ekiti'),
        ('Enugu', 'Enugu'), ('Gombe', 'Gombe'), ('Imo', 'Imo'), ('Jigawa', 'Jigawa'),
        ('Kaduna', 'Kaduna'), ('Kano', 'Kano'), ('Katsina', 'Katsina'), ('Kebbi', 'Kebbi'),
        ('Kogi', 'Kogi'), ('Kwara', 'Kwara'), ('Lagos', 'Lagos'), ('Nasarawa', 'Nasarawa'),
        ('Niger', 'Niger'), ('Ogun', 'Ogun'), ('Ondo', 'Ondo'), ('Osun', 'Osun'),
        ('Oyo', 'Oyo'), ('Plateau', 'Plateau'), ('Rivers', 'Rivers'), ('Sokoto', 'Sokoto'),
        ('Taraba', 'Taraba'), ('Yobe', 'Yobe'), ('Zamfara', 'Zamfara'), ('Fct', 'FCT'), ('Intl', 'Others'),
    ], validators=[DataRequired()])

    # LGA SelectField (empty initially, will be populated dynamically)
    lga = SelectField('LGA of Residence', choices=[],  validators=[DataRequired()])
       
    gender = SelectField('Gender', choices= GENDER_CHOICES, validators=[DataRequired()])
    position = SelectField('Position', choices = POSITION, validators=[DataRequired(), Length(min=2, max=100)])
    latitude = HiddenField('Latitude')
    longitude = HiddenField('Longitude')
    submit = SubmitField('Register')

 
class OrganizationForm(FlaskForm):
    name = StringField('Location Name', validators=[DataRequired(), Length(min=2, max=255)])
    slug = StringField('Slug (URL Friendly Name)', validators=[DataRequired(), Length(min=2, max=255)])
    logo_url = FileField('Upload Image', validators=[DataRequired(),
        FileAllowed(['jpg', 'jpeg','png', 'gif'], 'Only .jpeg, .jpg, .png, and .gif formats are allowed'), 
        FileSize(max_size=0.5 * 1024 * 1024, message='File size exceeds 500kb')])
    submit = SubmitField('Register Organization')


# location based
class locationForm(FlaskForm):
    name = StringField('Organization Name', validators=[DataRequired(), Length(min=2, max=255)])
    latitude = FloatField('Latitude', validators=[DataRequired()])
    longitude = FloatField('Longitude', validators=[DataRequired()])
    submit = SubmitField('Save')


#today...
class FeedbackForm(FlaskForm):

    source = SelectField('Source', choices=[
        ('Social Media', 'Social Media'), ('Website', 'Website'), ('Friends or Family', 'Friends or Family'),
        ('Email', 'Email'), ('Flyers/Posters', 'Flyers/Posters'), ('Others', 'Others'),
         ], validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    comments = StringField('Enter any additional feedback...', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email(message="Invalid email address")])
    gender = SelectField('Gender', choices=[('Male', 'Male'),  ('Female', 'Female') ], validators=[DataRequired()])
    submit = SubmitField('Register')



class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    # phone_number = StringField('Phone Number', validators=[DataRequired(message="Phone number is required."), 
    #                 Length(min=11, max=15), Regexp(regex=r'^(\+?[1-9]\d{7,14}|0\d{7,14})$', message="Phone number must be valid")])

    submit = SubmitField('Login')

#######################################################

class OrgIdentifierForm(FlaskForm):
    org_identifier = StringField("Organization Name or Email", validators=[DataRequired()])
    submit = SubmitField("Continue")

#######################################################
class DeleteInviteeForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Delete Invitee')


class AdminForm(FlaskForm):
    name = StringField('Admin Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email(message="Invalid email address")])
    role = SelectField('Role', choices=[ ('org_admin', 'Organization Admin'),('location_admin', 'Location Admin') # Include location admin
    ], validators=[DataRequired()])

    location_id = SelectField('Assign location',coerce=int, choices=[],validators=[Optional()]) # Include location admin

    phone_number = StringField('Phone Number', validators=[DataRequired(message="Phone number is required."), 
                    Length(min=11, max=15), Regexp(regex=r'^(\+?[1-9]\d{7,14}|0\d{7,14})$', message="Phone number must be valid")])

    address = StringField('Residential Address', validators=[DataRequired(), Length(min=2, max=500)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    gender = SelectField('Gender',choices=[ ('Female', 'Female'),('Male', 'Male')] , validators=[DataRequired()])
    submit = SubmitField('Register')


# --- Flask-WTF Form ---
class AttendanceForm(FlaskForm):
    # csrf_token = HiddenField('CSRF Token')  #  CSRF token field
    phone_number = StringField('Phone Number', validators=[DataRequired(message="Phone number is required."), 
                    Length(min=11, max=15), Regexp(regex=r'^(\+?[1-9]\d{7,14}|0\d{7,14})$', message="Phone number must be valid")])


    latitude = HiddenField('Latitude')
    longitude = HiddenField('Longitude')
    submit = SubmitField('Confirm')



class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long.')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Reset Password')



    # for edit functionality and js



def fetch_lgas_all():
    # Mock LGA data for each state
    return {
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
