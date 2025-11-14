from app import create_app
import os
from app import db
from app.models import create_default_admin 
# from app.inv.app import generate_event_qr  # adjust import path

app = create_app()


if __name__ == '__main__':
        
    # Ensure that the application context is active
    with app.app_context():
        if not os.path.exists('app/static/qrcodes'):
            os.makedirs('static/qrcodes')
       
        db.create_all()
        #create default admin
        create_default_admin()

       
#host='0.0.0.0', enables the app run locally or remotely on a local network
    app.run(host='0.0.0.0',debug=True)