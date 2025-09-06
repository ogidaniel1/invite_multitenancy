import os
from flask_wtf import CSRFProtect, FlaskForm
from werkzeug.utils import secure_filename
from functools import wraps
from flask_wtf.csrf import generate_csrf, validate_csrf,CSRFError
from flask_paginate import Pagination, get_page_parameter
from flask import Flask, render_template, request, redirect, url_for, flash,jsonify, abort,Response, session
from flask_sqlalchemy import SQLAlchemy
from Crypto.Hash import SHA256
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from alembic import op
from datetime import datetime, timezone
import json
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




# Load environment variables
load_dotenv()

# Configuration
DEFAULT_ADMIN_EMAIL = os.getenv('DEFAULT_ADMIN_EMAIL')
DEFAULT_ADMIN_PASSWORD = os.getenv('DEFAULT_ADMIN_PASSWORD')





app = Flask(__name__)


# app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Get the key from .env
# app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('SECRET_KEY')  # For Flask-WTF

#assigning environment variables here for mysql database config in .env

# #creating connection engine (pymysql db on server)
# app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_password}@{host}:{port}/{db_name}'


# local connections 

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fac_invitees.db'
app.config['SQLALCHEMY_POOL_RECYCLE'] = 3600  # Recycle connections every hour
app.config['SQLALCHEMY_POOL_PRE_PING'] = True  # Pre-ping connections to verify they're still valid
app.config['UPLOAD_FOLDER'] = 'static/qr_codes'



#for
#assigning environment variables here for database config in .env

# from urllib.parse import quote  

# db_user = os.getenv('db_user')
# db_password = quote(os.getenv('db_password'))  # Escaping special characters
# host = os.getenv('host')
# db_name = os.getenv('db_name')
# port = os.getenv('port')



# # #creating connection engine pymysql
# app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_password}@{host}:{port}/{db_name}'


# config.py or app setup (delete this on live server)
# to send emails in production? Check out our Email API/SMTP product! mailtrap
app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '2d210b819d0f12'
app.config['MAIL_PASSWORD'] = '804323d6c92a70'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False


 
# Initialize extensions without binding them to an app yet
db = SQLAlchemy(app)
login_manager = LoginManager()
CORS(app) # Enable CORS for all routes
# db = SQLAlchemy()
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)
migrate=Migrate(app, db) # For database migrations



logging.basicConfig(level=logging.INFO)
logger=logging.getLogger(__name__)

application = app

mail = Mail(app)
#####################################################################

from admin.admin_management_views import admin_bp
app.register_blueprint(admin_bp)

#deadline date

registration_deadline = datetime(2024, 5, 26, 23, 59, 59)  # Example: May 26, 2025, 23:59:59


# Models
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(200))
    
    # Keep your existing fields
    name = db.Column(db.String(120), nullable=True)  # Your original field
    phone_number = db.Column(db.String(15), unique=True, nullable=False)
    gender = db.Column(db.String(100), nullable=True)
    
    # Keep your existing boolean flags AND add role field
    is_admin = db.Column(db.Boolean, default=False)  # Your original field
    is_super = db.Column(db.Boolean, default=False)  # Your original field
    role = db.Column(db.String(50), nullable=True)  # Add for view compatibility
    
    is_active = db.Column(db.Boolean, default=True)  # New field for views
    last_login = db.Column(db.DateTime, nullable=True)  # New field for views
    
    # Keep your existing timestamp fields
    date_added = db.Column(db.DateTime, nullable=True)  # Your original field
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Add for view compatibility
    updated_at = db.Column(db.DateTime, nullable=True)
    
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    organization = db.relationship('Organization', backref='admins')

    @property
    def can_export_invitees(self):
        return Config.can_export_invitees(self)
      # Add property to sync role with boolean flags
    @property
    def role_from_flags(self):
        if self.is_super:
            return 'super_admin'
        elif self.is_admin:
            return 'org_admin'
        return 'location_admin'
    
    # Add property to sync name fields
    # @property
    # def display_name(self):
    #     return self.name or self.name
    
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

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    uuid = db.Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, nullable=False)
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
    


class Invitee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    # for rccg jesus house
    parish = db.Column(db.String(100))
    area = db.Column(db.String(100))
    phone_number = db.Column(db.String(15), unique=True, nullable=False)
    state = db.Column(db.String(100), nullable=True)
    lga = db.Column(db.String(100), nullable=True)
    address = db.Column(db.String(200))
    gender = db.Column(db.String(100), nullable=True)
    position = db.Column(db.String(50), nullable=False)
    register_date = db.Column(db.DateTime, nullable=True)
    deleted = db.Column(db.Boolean, default=False)
    qr_code_path = db.Column(db.String(200), nullable=True)
    confirmed = db.Column(db.String(20), default='Absent')  # New field to track confirmation
    confirmation_date = db.Column(db.DateTime, nullable=True)  # New field to store confirmation timestamp
    latitude = db.Column(db.Float, nullable=True)  # Corrected the definition
    longitude = db.Column(db.Float, nullable=True)  # Corrected the definition
    status = db.Column(db.String(50)) #"confirmed", "out of range"
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    organization = db.relationship('Organization', backref='invitees')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'parish': self.parish,
            'area': self.area,
            'address': self.address,
            'phone_number': self.phone_number,
            'state': self.state,
            'lga': self.lga,
            'gender': self.gender,
            'position': self.position,
            'register_date': self.register_date.isoformat() if self.register_date else None,
            'deleted': self.deleted,
            'qr_code_path': self.qr_code_path,
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


class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)  # Name of the location/venue
    slug = db.Column(db.String(100), unique=True, nullable=True)  # New field
    description = db.Column(db.Text, nullable=True)  # Additional description
    address = db.Column(db.String(500), nullable=True)  # New field
    add_date = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
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
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    location = db.relationship('Location', backref=db.backref('events', lazy=True))
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50), default='upcoming') # upcoming, active, past
    created_at = db.Column(db.DateTime, default=datetime.now)

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
            'status': self.status,
            'created_at': self.created_at.isoformat()
        }

class Invitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    invited_by_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    organization = db.relationship('Organization', backref='invitations')
    invited_by = db.relationship('Admin', backref='sent_invitations')


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


class DeleteLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    record_type = db.Column(db.String(50), nullable=False)  # e.g., 'Member', 'Invitee'
    record_id = db.Column(db.Integer, nullable=False)       # ID of the deleted record
    deleted_by = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    deleted_at = db.Column(db.DateTime, default=datetime.utcnow)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)


class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(50), nullable=False)  # e.g., 'create', 'edit', 'delete'
    user_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)  # Admin who performed the action
    record_type = db.Column(db.String(50), nullable=True)   # E.g., 'invitee', 'member'
    record_id = db.Column(db.Integer, nullable=True)        # ID of the affected record
    deleted_at = db.Column(db.DateTime, default=datetime.utcnow)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)

    # Relationship to Admin
    admin = db.relationship('Admin', backref='action_logs')

    def __repr__(self):
        return f'<ActionLog {self.action_type} by {self.user_id} on {self.record_type} {self.record_id}>'

#############################################

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

@app.route('/get_lgas', methods=['GET'])
def get_lgas():
    state = request.args.get('state')
    state = state.title() if state else ""

    lga = fetch_lgas(state)
    
    if lga:
        return jsonify({'lga': lga})
    else:
        return jsonify({'error': 'State not found'}), 404


#####################################################################

POSITION = [('', 'Select Position'),('Attendee', 'Attendee'),('Volunteer', 'Volunteer'),( 'Guest','Guest Minister')]
GENDER_CHOICES = [('', 'Select Gender'), ('Male', 'Male'), ('Female', 'Female')]
ADMIN_ROLES= [('', 'Select Role'), ('Org Admin', 'Org Admin')]


class InviteeForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email(message="Invalid email address")])
    # for rccg jesus house
    area = StringField('Area', validators=[DataRequired(), Length(min=2, max=100)])
    address = StringField('Residential Address', validators=[DataRequired()])

    parish = StringField('Parish', validators=[DataRequired(), Length(min=2, max=100)])
  
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(min=11, max=15), Regexp(regex=r'^\+?\d{11,15}$', message="Phone number must contain only digits")
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
        ('Taraba', 'Taraba'), ('Yobe', 'Yobe'), ('Zamfara', 'Zamfara'), ('FCT', 'FCT'), ('Intl', 'Others'),
    ], validators=[DataRequired()])
     
    # LGA SelectField (empty initially, will be populated dynamically)
    lga = SelectField('LGA of Residence', choices=[],  validators=[DataRequired()])
    gender = SelectField('Gender', choices= GENDER_CHOICES, validators=[DataRequired()])
    position = SelectField('Position', choices = POSITION, validators=[DataRequired(), Length(min=2, max=100)])
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
    role = SelectField('Role', choices = ADMIN_ROLES, validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(min=11, max=15), Regexp(regex=r'^\+?\d{11,15}$', message="Phone number must contain only digits")])  
    gender = StringField('Gender', validators=[DataRequired()])
    submit = SubmitField('Register')


# --- Flask-WTF Form ---
class AttendanceForm(FlaskForm):
    # csrf_token = HiddenField('CSRF Token')  #  CSRF token field
    phone_number = StringField('', validators=[
        DataRequired(message="Phone number is required."),
        Length(min=11, message="Phone number must be at least 11 digits."),
        Regexp(r'^\+?\d{11,15}$', message="Phone number must contain only digits.")
    ])
    latitude = HiddenField('Latitude')
    longitude = HiddenField('Longitude')
    submit = SubmitField('Confirm')
    
######################################################

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(admin_id):
    return Admin.query.get(int(admin_id))


def create_default_admin():

    organization = Organization.query.first()  # Get an existing organization
     
    # organization = Organization.query.filter_by(uuid=org_uuid).first_or_404()
      
    if not organization:
        # Create one if none exists
        organization = Organization(name="DANWEB IT", slug="danwebit")
        db.session.add(organization)
        db.session.flush()  # Ensure the ID is available

    default_admin = Admin.query.filter_by(email=DEFAULT_ADMIN_EMAIL).first()
    if not default_admin:
        hashed_password = generate_password_hash(DEFAULT_ADMIN_PASSWORD, method='pbkdf2:sha256')
        new_admin = Admin(
            email=DEFAULT_ADMIN_EMAIL,
            password=hashed_password,
            gender='Unknown',
            name='Default Admin',
            phone_number='+23490-ask-Admin',
            is_admin=True,
            is_super=True,
            role='super_admin',
            organization_id=organization.id
        )
        db.session.add(new_admin)
        db.session.flush()  # Ensures data integrity before committing
        db.session.commit()
        print("Default admin created")
    else:
        print("Default admin already exists")

#######################################################

def admin_or_super_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please log in first.", "warning")
            return redirect(url_for('login'))

        if not (current_user.is_admin or current_user.is_super):
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function


def super_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First, check if the user is authenticated at all.
        if not current_user.is_authenticated:
            flash("Please log in to access this page.", "info")
            return redirect(url_for('login',org_uuid=''))
        if not current_user.is_super:
            # If not a super admin, deny access.
            flash("You do not have permission to access this page. Super admin access required.", "danger")
            # You can redirect to login, a dashboard, or simply abort with a 403 Forbidden.
            return redirect(url_for('login',org_uuid=''))
        # If all checks pass, execute the original function.
        return f(*args, **kwargs)
    return decorated_function

#######################################################

# general home page
@app.route('/')
def home():
    return render_template('base_dashboard.html')


@app.route('/register_organization', methods=['GET', 'POST'])
@super_required
def register_organization():
    form = OrganizationForm()

    if form.validate_on_submit():
        file = form.logo_url.data

        existing_slug = Organization.query.filter_by(slug=form.slug.data).first()
        existing_name = Organization.query.filter_by(name=form.name.data).first()

        if existing_slug:
            flash('Organization slug already exists. Choose another one.', 'danger')
            return redirect(url_for('register_organization'))

        if existing_name:
            flash('Organization name already exists. Choose another one.', 'danger')
            return redirect(url_for('register_organization'))

        filename = Config.save_uploaded_image(file, prefix=form.slug.data + "_") if file else None

        if filename is None:
            flash("Invalid file format, please upload PNG, JPEG, GIF, or JPG!", "danger")
            return redirect(url_for('register_organization'))

        try:
            new_org = Organization(
                name=form.name.data,
                slug=form.slug.data,
                logo_url=filename
            )
            db.session.add(new_org)
            db.session.commit()

            flash('Organization registered successfully.', 'info')
            return redirect(url_for('login', org_uuid=new_org.uuid))

        except smtplib.SMTPException as e:
            db.session.rollback()
            flash(f"Registration successful, but email error: {str(e)}", "error")
            return redirect(url_for('login', org_uuid=new_org.uuid))

        except Exception as e:
            db.session.rollback()
            flash(f"Error saving to database: {str(e)}", "error")
            return redirect(url_for('register_organization'))

    return render_template('register_organization.html', form=form)

# ##############################################


# Enhanced all_org route with search and pagination
@app.route('/all_organizations', methods=['GET', 'POST'])
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

@app.route('/organization/<int:org_id>/view')
@super_required
def view_organization(org_id):
    """View a specific organization details"""
    organization = Organization.query.get_or_404(org_id)
    
    # Get additional stats if needed
    active_locations_count = len(organization.get_active_locations())
    
    return render_template('organizations.html', 
                         organization=organization,
                         active_locations_count=active_locations_count)


@app.route('/organization/<int:org_id>/edit', methods=['GET', 'POST'])
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
                    old_logo_path = os.path.join(app.config['UPLOAD_FOLDER'], organization.logo_url)
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
            return redirect(url_for('view_organization', org_id=organization.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating organization: {str(e)}", "error")
            return render_template('organization.html', form=form, organization=organization)
    
    return render_template('organizations.html', form=form, organization=organization)


@app.route('/organization/<int:org_id>/delete', methods=['POST'])
@super_required
def delete_organization(org_id):
    """Delete an organization"""
    organization = Organization.query.get_or_404(org_id)
    
    try:
        # Store name for flash message
        org_name = organization.name
        
        # Remove logo file if it exists
        if organization.logo_url:
            logo_path = os.path.join(app.config['UPLOAD_FOLDER'], organization.logo_url)
            if os.path.exists(logo_path):
                try:
                    os.remove(logo_path)
                except OSError:
                    pass  # Continue even if file removal fails
        
        # Check if organization has related data (locations, users, etc.)
        active_locations = organization.get_active_locations()
        if active_locations:
            flash(f'Cannot delete "{org_name}". Organization has {len(active_locations)} active locations. Please remove all locations first.', 'danger')
            return redirect(url_for('view_organization', org_id=org_id))
        
        # Additional checks for related data
        # Add checks for users, bookings, etc. if they exist in your model
        # Example:
        # if organization.users.count() > 0:
        #     flash(f'Cannot delete "{org_name}". Organization has associated users.', 'danger')
        #     return redirect(url_for('view_organization', org_id=org_id))
        
        db.session.delete(organization)
        db.session.commit()
        
        flash(f'Organization "{org_name}" deleted successfully!', 'success')
        return redirect(url_for('all_org'))
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting organization: {str(e)}", "error")
        return redirect(url_for('view_organization', org_id=org_id))


@app.route('/organization/<int:org_id>/toggle_status', methods=['POST'])
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
            
        return redirect(url_for('view_organization', org_id=org_id))
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating organization status: {str(e)}", "error")
        
        if request.is_json:
            return jsonify({'success': False, 'message': str(e)}), 500
            
        return redirect(url_for('view_organization', org_id=org_id))


# API Routes for AJAX operations
@app.route('/api/organizations')
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


@app.route('/api/organization/<int:org_id>')
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

@app.route('/api/organization/<int:org_id>/delete', methods=['DELETE'])
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
            logo_path = os.path.join(app.config['UPLOAD_FOLDER'], organization.logo_url)
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

# Bulk operations route
@app.route('/organizations/bulk_action', methods=['POST'])
@super_required
def bulk_organization_action():
    """Handle bulk actions on organizations"""
    action = request.form.get('action')
    org_ids = request.form.getlist('org_ids')
    
    if not action or not org_ids:
        flash('Please select an action and at least one organization.', 'warning')
        return redirect(url_for('all_org'))
    
    try:
        organizations = Organization.query.filter(Organization.id.in_(org_ids)).all()
        
        if action == 'delete':
            count = 0
            for org in organizations:
                # Check for related data
                if not org.get_active_locations():
                    # Remove logo file
                    if org.logo_url:
                        logo_path = os.path.join(app.config['UPLOAD_FOLDER'], org.logo_url)
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
    
    return redirect(url_for('all_org'))


# #####.........routes.py...

@app.route('/login/', methods=['GET', 'POST'])
def universal_login():
    form = OrgIdentifierForm()
    org = Organization.query.first_or_404()
    if form.validate_on_submit():
        identifier = form.org_identifier.data.strip()

        # Case: Email login
        if "@" in identifier:
            email_domain = identifier.split("@")[-1]
            admin = Admin.query.filter(Admin.email.ilike(f"%@{email_domain}")).first()
            
            if admin:
                if admin.is_super:
                    # Redirect to a superadmin dashboard or route
                    return redirect(url_for('super_login',org_uuid=org.uuid))

                if admin.organization:
                    return redirect(url_for('login', org_uuid=admin.organization.uuid))

        # Case: Name or slug
        org = Organization.query.filter(
            (Organization.slug == identifier) | 
            (Organization.name.ilike(f"%{identifier}%"))
        ).first()

        if org:
            return redirect(url_for('login', org_uuid=org.uuid))

        flash("Organization not found.", "danger")

    return render_template("universal_login.html", form=form)


# # Routes

@app.route('/super/login', methods=['GET', 'POST'])
def super_login():
    form = LoginForm()

    org = Organization.query.all()

    if form.validate_on_submit():
        admin = Admin.query.filter_by(email=form.email.data).first()

        if admin and check_password_hash(admin.password, form.password.data):
            if admin.is_super:
                login_user(admin)
                session['admin_id'] = admin.id
                flash('Login successful!', 'success')
                return redirect(url_for('admin.management_dashboard'))
            flash('Unauthorized access to this organization.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('super_login.html',form=form, org=org)



@app.route('/<uuid:org_uuid>/login', methods=['GET', 'POST'])
def login(org_uuid):
    form = LoginForm()

    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    if form.validate_on_submit():
        admin = Admin.query.filter_by(email=form.email.data).first()

        if admin and check_password_hash(admin.password, form.password.data):
            if admin.is_super or admin.organization_id == org.id:
                login_user(admin)
                session['org_uuid'] = str(org.uuid)
                flash('Login successful!', 'success')
                return redirect(url_for('show_invitees', org_uuid=org.uuid))
            flash('Unauthorized access to this organization.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html', form=form, org=org)


@app.route('/<uuid:org_uuid>/logout')
@login_required
def logout(org_uuid):
    logout_user()
    flash('You have been logged out!', 'success')
    return redirect(url_for('login', org_uuid=org_uuid))


######################...helper...#########################
#Helper Function for Logging Actions

def log_action(action_type, user_id, record_type=None, record_id=None, organization_id=None):
    if user_id is None:
        user_id = "Anonymous"  # Or any default value
    
    try:
        # Log all actions to ActionLog
        action_log = ActionLog(
            action_type=action_type,
            user_id=user_id,
            record_type=record_type,
            record_id=record_id,
            organization_id=organization_id  # 
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

@app.route('/<uuid:org_uuid>/del_invitee/<int:invitee_id>', methods=['POST'])
# @org_admin_required
def del_invitee(org_uuid, invitee_id):

    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    # org = Organization.query.filter_by(uuid=UUID(org_uuid)).first_or_404()

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
        elif current_user.organization_id == org.id:
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
            organization_id=org.id
        )
        return jsonify({'status': 'success', 'message': 'Invitee deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400
    

##################################################
# ............mark attendance function by Admins..................

@app.route('/<uuid:org_uuid>/mark_invitee/<int:invitee_id>', methods=['POST'])
# @org_admin_required
def mark_invitee(org_uuid, invitee_id):
    # org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    if not current_user.is_authenticated or not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'You do not have access to this action'}), 403

    try:
        csrf_token = request.headers.get('X-CSRFToken')
        validate_csrf(csrf_token)

        invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first_or_404()

        if invitee.confirmed == 'Present':
            return jsonify({'status': 'error', 'message': 'Invitee has already been marked as Present'}), 400

        invitee.confirmed = 'Present'
        invitee.confirmation_date = datetime.utcnow()

        db.session.add(invitee)
        db.session.commit()
        log_action('mark',user_id=current_user.id if current_user.is_authenticated else None,
            record_type='invitee',record_id=invitee.id,organization_id=org.id)
        
        return jsonify({'status': 'success', 'message': 'Invitee marked Present successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


###########################################################


@app.route('/<uuid:org_uuid>/attendance/confirm', methods=['GET', 'POST'])
def confirm_attendance(org_uuid):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    # org = Organization.query.filter_by(uuid=UUID(org_uuid)).first_or_404()
    
    now = datetime.utcnow()
    if now < registration_deadline:
        flash("You don't have access until 23rd May", "error")
        return redirect(url_for('register', org_uuid=org.uuid))
    
    # Get the organization's location(s)
    org_locations = Location.query.filter_by(organization_id=org.id).all()
    
    if not org_locations:
        flash('Event location not set. Please contact the administrator.', 'error')
        return redirect(url_for('register', org_uuid=org.uuid))
    
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
            return redirect(url_for('register', org_uuid=org.uuid))
        
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
            return redirect(url_for('confirm_attendance', org_uuid=org.uuid))
    
    return render_template(
        'confirm_attendance.html', 
        org_uuid=org.uuid, 
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


###############################################
@app.route('/<uuid:org_uuid>/register', methods=['GET', 'POST'])
def register(org_uuid):
    now = datetime.now()
    
    # org = Organization.query.filter_by(uuid=UUID(org_uuid)).first_or_404()
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    if now < registration_deadline:
        flash("Registration is Closed.", "error")
        return redirect(url_for('index', org_uuid=org.uuid))

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
            return redirect(url_for('register', org_uuid=org.uuid))
        
        if "@" not in form.email.data:
            flash("Invalid email address.", "error")
            return redirect(url_for('register', org_uuid=org.uuid))
        
        try:
            register_date = datetime.utcnow()
            new_invitee = Invitee(
                name=name,
                phone_number=phone_number,
                gender=gender,
                state=state,
                email=email,
                area=area,
                address=address,
                parish=parish,
                position=position,
                lga=lga,
                register_date=register_date,
                organization_id=org.id
            )
            db.session.add(new_invitee)
            db.session.commit()
            
            log_action(
                'add',
                user_id=current_user.id if current_user.is_authenticated else None,
                record_type='invitee',
                record_id=new_invitee.id,
                organization_id=org.id
            )

            # Generate QR code URL using org_uuid
            qr_code_path = url_for('confirm_qr_code_self', org_uuid=org.uuid, invitee_id=new_invitee.id, _external=True)

            new_invitee.qr_code_path = qr_code_path
            db.session.commit()

            send_qr_code_email(new_invitee, qr_code_path)

            flash("Registration successful! A confirmation email has been sent!", "success")
            return redirect(url_for('success', org_uuid=org.uuid, invitee_id=new_invitee.id))

        except smtplib.SMTPException as e:
            db.session.rollback()
            flash(f"Registration successful, but an error occurred while sending the email: {str(e)}", "error")
            return redirect(url_for('register', org_uuid=org.uuid))

        except Exception as e:
            db.session.rollback()
            flash(f"Error saving to database: {str(e)}", "error")
            return redirect(url_for('register', org_uuid=org.uuid))

    return render_template('register.html', form=form, org=org, org_uuid=org.uuid)


##########################################################
@app.route('/<uuid:org_uuid>/edit_invitee/<int:id>', methods=['GET', 'POST'])
# @org_admin_required
def edit_invitee(org_uuid, id):
    # org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    now = datetime.now()
    if now < registration_deadline:
        flash("You don't have access until 23rd May", "error")
        return redirect(url_for('show_invitees',org=org, org_uuid=org.slug))

    invitee = Invitee.query.filter_by(id=id, organization_id=org.id).first_or_404()

    if not current_user.is_authenticated or (
        not current_user.is_super and current_user.organization_id != org.id
    ):
        flash('You do not have access to this action.', 'danger')
        return redirect(url_for('login', org_uuid=org.slug))

    if request.method == 'POST':
        new_name = request.form['name']
        new_position = request.form['position']
        new_phone_number = request.form['phone_number']
        new_state = request.form['state']
        new_lga = request.form['lga']

        existing_invitee = Invitee.query.filter_by(phone_number=new_phone_number).first()
        if existing_invitee and existing_invitee.id != id:
            flash('Invitee already exists.', 'danger')
            return redirect(url_for('edit_invitee', org_uuid=org.uuid, id=id))

        invitee.name = new_name
        invitee.position = new_position
        invitee.phone_number = new_phone_number
        invitee.state = new_state
        invitee.lga = new_lga
        invitee.updated_at = datetime.utcnow()

        try:
            db.session.commit()
            log_action('edit',user_id=current_user.id if current_user.is_authenticated else None,
            record_type='invitee',record_id=invitee.id,organization_id=org.id)
            flash('Invitee updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {e}', 'danger')

        return redirect(url_for('show_invitees', org_uuid=org.uuid))

    return render_template('edit_invitee.html', org=org, invitee=invitee, org_uuid=org.uuid)


@app.route('/<uuid:org_uuid>/feedback-chart', methods=['GET', 'POST'])
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
@app.route('/<uuid:org_uuid>/submit-feedback', methods=['GET', 'POST'])
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
            return redirect(url_for('submit_feedback',org_uuid=org_uuid))
        
        if "@" not in form.email.data:
            flash("Invalid email address.", "error")
            return redirect(url_for('submit_feedback',org_uuid=org_uuid))

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
            return redirect(url_for('submit_feedback',org_uuid=org.slug))

        except Exception as e:
            db.session.rollback()
            flash(f"Error saving to database: {str(e)}", "error")
            return redirect(url_for('submit_feedback',org_uuid=org.slug))

    return render_template('feedback.html',org=org,org_uuid=org_uuid,form=form)


##########################################################
@app.route('/<uuid:org_uuid>/success/<int:invitee_id>')
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
@app.route('/<uuid:org_uuid>/confirm_qr_code_self/<int:invitee_id>', methods=['GET'])
# @org_admin_required
@csrf.exempt
def confirm_qr_code_self(org_uuid, invitee_id):
    """
    Allows admin to confirm an invitee’s presence using secure UUID-based URL.
    """
    now = datetime.now()
    if now < registration_deadline:
        flash("Access restricted until 23rd May", "error")
        return redirect(url_for('manage_invitee', org_uuid=org_uuid))

    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first()
    if not invitee:
        flash('Invitee not found.', 'danger')
        return redirect(url_for('index', org_uuid=org_uuid))

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
            record_type='invitee',record_id=invitee.id,organization_id=org.id)

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
        return redirect(url_for('index', org_uuid=org_uuid))
  

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
@app.route('/<uuid:org_uuid>/status/<int:invitee_id>')
def invitee_status(org_uuid, invitee_id):
    """
    Displays the status page for an invitee using org UUID for better security.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    invitee = Invitee.query.filter_by(id=invitee_id, organization_id=org.id).first_or_404()

    return render_template('invitee_status.html', org_uuid=org.uuid, invitee=invitee)

###############################################
@app.route('/<uuid:org_uuid>/get_qr_code/<int:invitee_id>')
def get_qr_code(org_uuid, invitee_id):
    """
    Returns the QR code path for the invitee using org UUID for security.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    qr_code_path = generate_qr_code(org.uuid, invitee_id)  # Make sure your function supports UUID
    return jsonify({'qr_code_path': qr_code_path})


####################################

@app.route('/<uuid:org_uuid>/invitees')
@admin_or_super_required
def show_invitees(org_uuid):
    """
    Displays invitees for a specific organization, 
    filtered by user role and optional search query.
    """
    try:
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except ValueError:
        flash('Invalid organization identifier.', 'danger')
        return redirect(url_for('login'))

    # --- Role-based access control ---
    if current_user.is_super:
        invitees_query = Invitee.query.filter_by(organization_id=org.id)
    elif current_user.is_admin and current_user.organization_id == org.id:
        invitees_query = Invitee.query.filter_by(organization_id=org.id)
    else:
        flash('Access denied to this organization’s invitees.', 'danger')
        return redirect(url_for('login'))

    # --- Search & filtering ---
    search = request.args.get('search', '', type=str)
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if search:
        invitees_query = invitees_query.filter(
            (Invitee.name.ilike(f'%{search}%')) |
            (Invitee.phone_number.ilike(f'%{search}%')) |
            (Invitee.id.ilike(f'%{search}%'))
        )
        if invitees_query.count() == 0:
            flash('No invitees matched your search.', 'info')

    # --- Statistics ---
    no_invitee_present = invitees_query.filter(Invitee.confirmed == 'Present').count()
    no_invitee_absent = invitees_query.filter(Invitee.confirmed == 'Absent').count()
    no_invitees = invitees_query.count()

    # --- Pagination ---
    pagination = invitees_query.order_by(Invitee.id.desc()).paginate(page=page, per_page=per_page, error_out=False)
    invitees = pagination.items

    return render_template('invitees.html',
        org=org,org_uuid=org.uuid, invitees=invitees,
        pagination=pagination, no_invitee_present=no_invitee_present,
        no_invitee_absent=no_invitee_absent,
        no_invitees=no_invitees,is_super=current_user.is_super)


# ######################################...............
@app.route('/<uuid:org_uuid>/manage_invitee', methods=['GET', 'POST'])
@admin_or_super_required
def manage_invitee(org_uuid):
    """
    Allows super admins or org admins to search and manage invitees.
    Super admins can manage any organization's invitees.
    Org admins can only manage their own organization's invitees.
    """
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    # Role-based access control
    if not current_user.is_super:
        if not current_user.is_admin or current_user.organization_id != org.id:
            flash("You do not have permission to manage invitees for this organization.", "danger")
            return redirect(url_for('login'))

    # Base query
    invitees_query = Invitee.query.filter_by(organization_id=org.id)

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

@app.route('/<uuid:org_uuid>/export_invitees', methods=['GET'])
@login_required
def export_invitees(org_uuid):
    # Check if user is authorized to export
    if not current_user.can_export_invitees:
        flash('Access denied. You are not authorized to export invitees.', 'danger')
        return redirect(url_for('login'))

    # Get the organization object by UUID
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    try:
        # Get all invitees from the specified category
        invitees_query = Invitee.query.filter_by(
            organization_id=org.id,
            category="RCCG province"
        )

        page = request.args.get('page', 1, type=int)
        pagination = invitees_query.paginate(page=page, per_page=10)
        invitees = pagination.items

        # Handle case where no invitees are found
        if not invitees:
            flash('Records not found yet..', 'warning')
            return redirect(url_for('show_invitees', org_uuid=org.uuid))

        # Extract specific columns
        data = [{
            'Name': i.name,
            'Phone': i.phone_number,
            'Gender': i.gender,
            'Email': i.email,
            'Parish': i.parish,
            'Area': i.area,
            'State': i.state,
            'LGA': i.lga,
            'Position': i.position,
            'Register Date': i.register_date,
            'Confirmed': i.confirmed
        } for i in invitees]

        # Create DataFrame
        df = pd.DataFrame(data)

        # Write to Excel
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Invitees')

        output.seek(0)
        return send_file(output, download_name="invitees_rccg.xlsx", as_attachment=True)

    except Exception as e:
        flash('An error occurred while exporting data.', 'danger')
        return render_template(
            'invitees.html',
            org=org,
            org_uuid=org.uuid,
            invitees=invitees,
            pagination=pagination
        )


######################################################

@app.route('/<uuid:org_uuid>/register_admin', methods=['GET', 'POST'])
# @super_required
def register_admin(org_uuid):
    form = AdminForm()
    DEFAULT_PASSWORD = 'rccg2025'

    # Get the organization by UUID
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    if form.validate_on_submit():
        name = form.name.data.title()
        gender = form.gender.data.title()
        email = form.email.data.lower()
        role = form.role.data
        phone_number = form.phone_number.data

        # Check for duplicates within the same org
        existing_admin = Admin.query.filter(
            Admin.organization_id == org.id,
            or_(Admin.phone_number == phone_number, Admin.email == email)
        ).first()

        if existing_admin:
            flash("An Admin with this phone number or email already exists.", "error")
            return redirect(url_for('register_admin', org_uuid=org.uuid))

        if "@" not in email:
            flash("Invalid email address.", "error")
            return redirect(url_for('register_admin', org_uuid=org.uuid))

        try:
            hashed_password = generate_password_hash(DEFAULT_PASSWORD, method='pbkdf2:sha256')

            new_admin = Admin(
                name=name,
                gender=gender,
                phone_number=phone_number,
                password=hashed_password,
                date_added=datetime.utcnow(),
                email=email,
                role=role,
                is_admin=True,
                organization_id=org.id
            )

            db.session.add(new_admin)
            db.session.commit()

            log_action('add', user_id=current_user.id, record_type='Admin', record_id=new_admin.id)

            flash(f"Admin registration successful. Default password: {DEFAULT_PASSWORD}", "info")
            return redirect(url_for('admin.management_dashboard', org_uuid=org.uuid))

        except Exception as e:
            db.session.rollback()
            flash(f"Error saving to database: {str(e)}", "error")
            return redirect(url_for('register_admin', org_uuid=org.uuid))

    return render_template('register_admin.html', org=org, org_uuid=org.uuid, form=form)


#............edit function....................
@app.route('/<uuid:org_uuid>/edit_admin/<int:id>', methods=['GET', 'POST'])
# @super_required
def edit_admin(org_uuid, id):
    # Get the organization using UUID
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    # Find the admin within this organization
    admin = Admin.query.filter_by(id=id, organization_id=org.id).first_or_404()

    if request.method == 'POST':
        # Get form data and strip whitespace
        new_name = request.form['name'].strip()
        new_email = request.form['email'].strip()
        new_password = request.form['password'].strip()

        # Check for duplicate email in another admin
        existing_admin = Admin.query.filter_by(email=new_email).first()
        if existing_admin and existing_admin.id != id:
            flash('An admin with this email already exists.', 'danger')
            return redirect(url_for('edit_admin', org_uuid=org.uuid, id=id))

        # Update admin fields
        admin.name = new_name
        admin.email = new_email
        if new_password:
            admin.password = generate_password_hash(new_password)

        admin.updated_at = datetime.utcnow()

        try:
            db.session.commit()
            log_action('edit',user_id=current_user.id if current_user.is_authenticated else None,
            record_type='Admin',record_id=admin.id,organization_id=org.id)
            flash('Admin updated successfully!', 'success')

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')

        return redirect(url_for('edit_admin', org_uuid=org.uuid, id=admin.id))

    return render_template('edit_admin.html', org=org, org_uuid=org.uuid, admin=admin)


# ............delete function..................

@app.route('/<uuid:org_uuid>/del_admin/<int:admin_id>', methods=['POST'])
# @super_required
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
            record_type='Admin',record_id=admin.id,organization_id=org.id)
        return jsonify({'status': 'success', 'message': 'Admin deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/<uuid:org_uuid>/manage_admin', methods=['GET', 'POST'])
@super_required
def manage_admin(org_uuid):
    
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()

    if not current_user.is_super and current_user.organization_id != org.id:
        flash("Unauthorized access to this organization's admins.", 'danger')
        return redirect(url_for('login', org_uuid=org.uuid))

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

    return render_template('del_admin.html', org=org, org_uuid=org.uuid, admins=admins,
                           pagination=pagination, search=search)


@app.route('/<uuid:org_uuid>/action_logs', methods=['GET'])
# @super_required
def action_logs(org_uuid):
    try:
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
        action_logs = ActionLog.query.filter_by(organization_id=org.id).order_by(ActionLog.id.desc()).all()

        if not action_logs:
            return render_template('action_logs.html', message="No logs found.")

        return render_template('action_logs.html', org=org, org_uuid=org.uuid, action_logs=action_logs)

    except Exception as e:
        return render_template('action_logs.html', message=f"An error occurred: {e}")


@app.route('/<uuid:org_uuid>/all_feedbacks')
# @org_admin_required
def all_feedback(org_uuid):
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    all_feedback = Feedback.query.filter_by(organization_id=org.id).all()

    return render_template('all_feedbacks.html', org=org, org_uuid=org.uuid, all_feedback=all_feedback)

###################################################

# ....................................#

@app.route('/<uuid:org_uuid>/locations')
@admin_or_super_required # This decorator is key for initial permission and org_uuid validation
def manage_locations(org_uuid):
    

    try:
        # Get the Organization object based on the URL's org_uuid.
        org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    except ValueError:
        flash('Invalid organization identifier.', 'danger')
        # Redirect to a default page or login if the UUID in the URL is malformed
        return redirect(url_for('login')) # Adjust this to your default dashboard/safe page

    # Initialize the query for locations
    locations_query = Location.query

    # --- Centralized Filtering Logic ---
    if current_user.is_super:
         # For this route, adhering to the URL's org_uuid makes sense for all users.
        locations_query = locations_query.filter_by(organization_id=org.id)
        
    elif current_user.is_admin: # This implies current_user is admin but NOT super
     # This check is a final safeguard. The decorator should have already handled
        # ensuring `current_user.organization_id == org.id` for non-super admins.
        if current_user.organization_id != org.id:
            flash('You do not have permission to view locations for this organization.', 'danger')
            # Redirect to their own organization's page if they try to access another
            return redirect(url_for('manage_locations', org_uuid=current_user.org.uuid)) # Assuming current_user.org is a relationship
            # OR just redirect to login: return redirect(url_for('login'))

        # Organization admin can only see locations for their assigned organization
        locations_query = locations_query.filter_by(organization_id=current_user.organization_id)
        
    else:
          # This part might actually never be reached if decorator works as expected.
        flash('You do not have sufficient permissions to view this page.', 'danger')
        return redirect(url_for('login'))

    # Execute the query
    locations = locations_query.all()
            
    return render_template('manage_locations.html',org=org, locations=locations)


@app.route('/<uuid:org_uuid>/locations/add', methods=['GET', 'POST'])
# @org_admin_required
def add_location(org_uuid):
    """Add a new location for the organization"""
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            description = request.form.get('description', '')
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
            location = Location(name=name,description=description,latitude=latitude, longitude=longitude,
                radius=radius, organization_id=org.id, add_date=datetime.utcnow()
            )
            
            db.session.add(location)
            db.session.commit()
            
            flash(f'Location "{name}" added successfully', 'success')
            return redirect(url_for('manage_locations', org_uuid=org.uuid))
            
        except ValueError:
            flash('Invalid coordinates. Please enter valid numbers.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding location: {str(e)}', 'danger')
    
    return render_template('add_location.html',org=org,org_uuid=session.get('org_uuid'))


@app.route('/<uuid:org_uuid>/locations/<int:location_id>/edit', methods=['GET', 'POST'])
# @org_admin_required
def edit_location(org_uuid, location_id):
    """Edit an existing location"""
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    location = Location.query.filter_by(
        id=location_id,organization_id=org.id).first_or_404()
    
    if request.method == 'POST':
        try:
            location.name = request.form.get('name')
            location.description = request.form.get('description', '')
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
            return redirect(url_for('manage_locations', org_uuid=org.uuid))
            
        except ValueError:
            flash('Invalid coordinates. Please enter valid numbers.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating location: {str(e)}', 'danger')
    
    return render_template(
        'edit_location.html',
        org=org,
        location=location)


@app.route('/<uuid:org_uuid>/locations/<int:location_id>/toggle', methods=['POST'])
# @org_admin_required
def toggle_location(org_uuid, location_id):
    """Toggle location active status"""
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
    location = Location.query.filter_by(
        id=location_id, organization_id=org.id).first_or_404()
    
    try:
        location.is_active = not location.is_active
        db.session.commit()
        
        status = "activated" if location.is_active else "deactivated"
        flash(f'Location "{location.name}" {status} successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating location: {str(e)}', 'danger')
    
    return redirect(url_for('manage_locations', org_uuid=org.uuid))

####################################

@app.route('/<uuid:org_uuid>/locations/<int:location_id>/delete', methods=['POST', 'GET'])
def delete_location(org_uuid, location_id):
    """Delete a location"""
    org = Organization.query.filter_by(uuid=org_uuid).first_or_404()
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

    return redirect(url_for('manage_locations', org_uuid=org.uuid))


####################################################################
#super admin dashboard

@app.route('/<uuid:org_uuid>/locations/api')
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
            'description': location.description,
            'latitude': location.latitude,
            'longitude': location.longitude,
            'radius': location.radius
        })
    
    return jsonify(locations_data)


############################################################
if __name__ == '__main__':
        
    # Ensure that the application context is active
    with app.app_context():
        if not os.path.exists('static/qr_codes'):
            os.makedirs('static/qr_codes')
        db.create_all()
        #create default admin
        create_default_admin()
#host='0.0.0.0', enables the app run locally or remotely on a local network
    app.run(host='0.0.0.0',debug=True)