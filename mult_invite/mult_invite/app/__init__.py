from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail,Message
from flask_migrate import Migrate
from flask_cors import CORS
from flask_wtf import CSRFProtect
import logging
from threading import Thread
import os
from flask import current_app 
from flask_dance.contrib.google import make_google_blueprint, google


# Initialize extensions without passing app yet
db = SQLAlchemy()
mail = Mail()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()


# Helper function for async email sending - MOVED HERE
def _send_async_email(app, msg):
    
    with app.app_context():
        mail.send(msg)
        
       
def send_async_email(subject, recipients, html_body, sender=None):
    app= current_app._get_current_object()
    msg=Message(subject=subject, recipients=recipients, sender=sender)
    msg.html =html_body
    threading = Thread(target=_send_async_email, args=(app,msg)).start()


def create_app():
    app = Flask(__name__)
    # app = Flask(__name__, static_folder='static')

    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///multi_invitees_event.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['QR_UPLOAD_FOLDER'] = 'app/static/qr_codes'
    app.config['IMAGE_UPLOAD_FOLDER'] = 'app/static/images'
     
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
     # Mailtrap configuration (for development/testing)
    app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
    app.config['MAIL_PORT'] = 2525
    app.config['MAIL_USERNAME'] = '2d210b819d0f12'
    app.config['MAIL_PASSWORD'] = '804323d6c92a70'
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['ADMINS'] = ['your-email@example.com'] # Example admin email
    app.config['MAIL_DEFAULT_SENDER'] = ('Your App Name', app.config['MAIL_USERNAME']) # Example default sender tuple

 
    # Initialize extensions with app
    db.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    CORS(app)

    # Google OAuth Blueprint
    google_bp = make_google_blueprint(
        client_id="YOUR_GOOGLE_CLIENT_ID",
        client_secret="YOUR_GOOGLE_CLIENT_SECRET",
        scope=["profile", "email"],
        redirect_url="/invitee/google/authorized"
    )

    # Logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # Register Blueprints
    from app.admin.admin_management_views import admin_bp
    from app.inv.app import app_
     

    app_.register_blueprint(google_bp, url_prefix="/invitee/google")
    app.register_blueprint(app_)
    app.register_blueprint(admin_bp)
     




    return app


