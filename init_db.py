from app import create_app
from models import db
import os

# Ensure we're using PostgreSQL
os.environ['FLASK_ENV'] = 'production'
if 'DATABASE_URL' not in os.environ:
    os.environ['DATABASE_URL'] = "postgresql://newuser:123456@localhost/operant"

app = create_app('production')

def init_db():
    with app.app_context():
        # Drop all tables if they exist
        db.drop_all()
        # Create all tables
        db.create_all()
        print("Database tables created successfully!")

if __name__ == '__main__':
    init_db()
