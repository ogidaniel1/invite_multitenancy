from app import create_app, db  # Import your app factory and db instance

# Create the Flask app instance
app = create_app()

# Run in app context to access database operations
with app.app_context():
    try:
        # Drop all tables
        db.drop_all()
        print("✅ All tables dropped successfully.")

        # Create all tables
        db.create_all()
        print("✅ Database initialized successfully.")
    
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
