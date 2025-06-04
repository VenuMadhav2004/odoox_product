import os

# Configuration settings
DEBUG = True
SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key-for-development')
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///ecofinds.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False
UPLOAD_FOLDER = 'static/images/uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}