import os
from config import ALLOWED_EXTENSIONS

def allowed_file(filename):
    """Check if a file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_image_url(image_filename):
    """Get the URL for an image file"""
    if not image_filename or image_filename == 'placeholder.png':
        return '/static/images/placeholder.png'
    return f'/static/images/uploads/{image_filename}'

def format_price(value):
    """Format price as a currency string"""
    return f"${value:.2f}"

def format_date(date):
    """Format date to a readable string"""
    return date.strftime('%B %d, %Y')

def truncate_text(text, length=100):
    """Truncate text to a specified length"""
    if len(text) <= length:
        return text
    return text[:length] + '...'