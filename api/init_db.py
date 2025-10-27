"""Database initialization script"""
import time
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://sectestops:securepassword123@postgres:5432/sectestops_db"
)

def wait_for_db(max_retries=30, retry_interval=2):
    """Wait for database to be ready"""
    print("Waiting for database to be ready...")
    
    for attempt in range(max_retries):
        try:
            engine = create_engine(DATABASE_URL)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("✓ Database is ready!")
            return True
        except OperationalError as e:
            print(f"Attempt {attempt + 1}/{max_retries}: Database not ready yet...")
            time.sleep(retry_interval)
    
    print("✗ Database connection failed after maximum retries!")
    return False

def init_db():
    """Initialize database tables"""
    try:
        from database import engine, Base
        from models import Target, Scan, Finding
        
        print("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        print("✓ Database tables created successfully!")
        return True
    except Exception as e:
        print(f"✗ Error creating tables: {e}")
        return False

if __name__ == "__main__":
    if wait_for_db():
        if init_db():
            print("✓ Database initialization complete!")
            sys.exit(0)
        else:
            print("✗ Database initialization failed!")
            sys.exit(1)
    else:
        print("✗ Could not connect to database!")
        sys.exit(1)

