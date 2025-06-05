import os
import random
import string
from datetime import datetime, timedelta
import logging
from flask import current_app, url_for
from flask_mail import Message as MailMessage
from werkzeug.security import generate_password_hash, check_password_hash
import textwrap
from sqlalchemy import or_, and_, func, desc, asc
#from config import ALLOWED_EXTENSIONS
from extensions import mail, db
from models import OTPRecord, Bid, Auction, Conversation, Message, Product, User, CartItem,Category,Rating
from flask_login import current_user
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# File handling
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_image_url(image_filename):
    if not image_filename or image_filename == 'placeholder.png':
        return '/static/images/placeholder.png'
    return f'/static/images/uploads/{image_filename}'

# Formatters
def format_price(value):
    return f"${value:.2f}"

def format_date(date):
    return date.strftime('%B %d, %Y')

def format_datetime(dt, fmt='%B %d, %Y %H:%M'):
    return dt.strftime(fmt) if dt else ''

def truncate_text(text, length=100):
    return textwrap.shorten(text, width=length, placeholder="...")

def human_readable_timedelta(dt):
    diff = datetime.now() - dt
    seconds = diff.total_seconds()
    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        return f"{int(seconds//60)} minutes ago"
    elif seconds < 86400:
        return f"{int(seconds//3600)} hours ago"
    else:
        return f"{int(seconds//86400)} days ago"

def display_stars(rating, max_stars=5):
    filled = int(rating)
    empty = max_stars - filled
    return '★' * filled + '☆' * empty

# OTP generation & verification
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def create_otp_record(user_id, otp_type='registration', expiry_minutes=10):
    OTPRecord.query.filter_by(user_id=user_id, otp_type=otp_type, is_used=False).delete()
    otp_code = generate_otp()
    expires_at = datetime.now() + timedelta(minutes=expiry_minutes)
    otp_record = OTPRecord(user_id=user_id, otp_code=otp_code, otp_type=otp_type, expires_at=expires_at)
    db.session.add(otp_record)
    db.session.commit()
    return otp_code

def verify_otp(user_id, otp_code, otp_type='registration'):
    otp_record = OTPRecord.query.filter_by(user_id=user_id, otp_code=otp_code, otp_type=otp_type, is_used=False).first()
    if not otp_record:
        return False, "Invalid OTP code"
    if otp_record.expires_at < datetime.now():
        return False, "OTP has expired"
    otp_record.is_used = True
    db.session.commit()
    return True, "OTP verified successfully"

def mark_otp_as_used(otp_record):
    otp_record.is_used = True
    db.session.commit()

def cleanup_expired_otps():
    try:
        expired = OTPRecord.query.filter(OTPRecord.expires_at < datetime.now()).all()
        for otp in expired:
            db.session.delete(otp)
        db.session.commit()
        return len(expired)
    except Exception as e:
        logging.error(f"Error cleaning up expired OTPs: {e}")
        return 0

# Email functions
def send_otp_email(user_email, username, otp_code, otp_type='registration'):
    try:
        if otp_type == 'registration':
            subject = 'Verify Your EcoFinds Account'
            template = f"""
            <html><body>
            <h2>Welcome to EcoFinds!</h2>
            <p>Hi {username},</p>
            <p>To complete your registration, use the following verification code:</p>
            <div style="padding: 20px; background-color: #f5f5f5; text-align: center;">
                <h1 style="color: #007bff;">{otp_code}</h1>
            </div>
            <p>This code expires in 10 minutes.</p>
            </body></html>
            """
        elif otp_type == 'login':
            subject = 'Your EcoFinds Login Code'
            template = f"""
            <html><body>
            <h2>EcoFinds Login</h2>
            <p>Hi {username},</p>
            <p>Use this code to complete your login:</p>
            <div style="padding: 20px; background-color: #f5f5f5; text-align: center;">
                <h1 style="color: #007bff;">{otp_code}</h1>
            </div>
            <p>This code expires in 10 minutes.</p>
            </body></html>
            """
        else:
            subject = 'Your EcoFinds Verification Code'
            template = f"<p>Your code: <strong>{otp_code}</strong></p>"

        msg = MailMessage(subject=subject, recipients=[user_email], html=template)
        mail.send(msg)
        return True, "OTP sent successfully"
    except Exception as e:
        logging.error(f"Error sending OTP email: {e}")
        return False, f"Failed to send OTP: {str(e)}"

def send_generic_email(subject, recipients, html_body):
    try:
        msg = MailMessage(subject=subject, recipients=recipients, html=html_body)
        mail.send(msg)
        return True, "Email sent successfully"
    except Exception as e:
        logging.error(f"Error sending email: {e}")
        return False, str(e)

# Password handling
def hash_password(password):
    return generate_password_hash(password)

def verify_password(hashed_password, password):
    return check_password_hash(hashed_password, password)

# Product / cart helpers
def calculate_cart_total(cart_items):
    return sum(item.product.price for item in cart_items)

def mark_product_as_sold(product):
    product.is_sold = True
    db.session.commit()

def remove_cart_item(cart_item):
    db.session.delete(cart_item)
    db.session.commit()

# Auction system
def is_auction_active(auction):
    return datetime.now() < auction.end_time

def get_highest_bid(auction):
    if not auction.bids:
        return None
    return max(bid.amount for bid in auction.bids)

def place_bid(auction, user, amount):
    highest = get_highest_bid(auction)
    if highest and amount <= highest:
        return False, "Bid must be higher than current highest bid."
    if not is_auction_active(auction):
        return False, "Auction has ended."
    new_bid = Bid(user_id=user.id, auction_id=auction.id, amount=amount, bid_time=datetime.now())
    db.session.add(new_bid)
    db.session.commit()
    return True, "Bid placed successfully"

# Messaging system
def get_or_create_conversation(user1_id, user2_id):
    conversation = Conversation.query.filter(
        ((Conversation.user1_id == user1_id) & (Conversation.user2_id == user2_id)) |
        ((Conversation.user1_id == user2_id) & (Conversation.user2_id == user1_id))
    ).first()
    if not conversation:
        conversation = Conversation(user1_id=user1_id, user2_id=user2_id)
        db.session.add(conversation)
        db.session.commit()
    return conversation

def send_message(conversation_id, sender_id, content):
    message = Message(conversation_id=conversation_id, sender_id=sender_id, content=content, sent_at=datetime.now())
    db.session.add(message)
    db.session.commit()
    return message

def get_messages(conversation_id):
    return Message.query.filter_by(conversation_id=conversation_id).order_by(Message.sent_at.asc()).all()

def start_chat_with_seller(product_id):
    product = Product.query.get(product_id)
    if not product:
        return None, "Product not found."
    if product.seller_id == current_user.id:
        return None, "You cannot chat with yourself."
    conversation = get_or_create_conversation(current_user.id, product.seller_id)
    return conversation, None

def get_user_conversations(user_id):
    return Conversation.query.filter(
        (Conversation.user1_id == user_id) | (Conversation.user2_id == user_id)
    ).order_by(Conversation.created_at.desc()).all()

# URL generators
def get_user_profile_url(user_id):
    return url_for('user_profile', user_id=user_id)

def get_product_url(product_id):
    return url_for('product_detail', product_id=product_id)

# General utility
def generate_random_string(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def handle_db_commit():
    try:
        db.session.commit()
        return True, "Success"
    except Exception as e:
        db.session.rollback()
        logging.error(f"Database commit failed: {e}")
        return False, str(e)

def apply_advanced_filters(query, filters):
    """Apply advanced filters to product query"""
    
    # Price range filter
    if filters.get('min_price') and filters['min_price'].replace('.', '').isdigit():
        query = query.filter(Product.price >= float(filters['min_price']))
    
    if filters.get('max_price') and filters['max_price'].replace('.', '').isdigit():
        query = query.filter(Product.price <= float(filters['max_price']))
    
    # Condition filter
    if filters.get('condition') and filters['condition'] != 'all':
        query = query.filter(Product.condition == filters['condition'])
    
    # Location filter
    if filters.get('location'):
        location_term = f"%{filters['location']}%"
        query = query.filter(Product.location.ilike(location_term))
    
    # Date range filter
    if filters.get('date_range'):
        if filters['date_range'] == 'today':
            today = datetime.now().date()
            query = query.filter(func.date(Product.created_at) == today)
        elif filters['date_range'] == 'week':
            week_ago = datetime.now() - timedelta(days=7)
            query = query.filter(Product.created_at >= week_ago)
        elif filters['date_range'] == 'month':
            month_ago = datetime.now() - timedelta(days=30)
            query = query.filter(Product.created_at >= month_ago)
        elif filters['date_range'] == 'custom':
            if filters.get('start_date'):
                try:
                    start_date = datetime.strptime(filters['start_date'], '%Y-%m-%d')
                    query = query.filter(Product.created_at >= start_date)
                except ValueError:
                    pass
            if filters.get('end_date'):
                try:
                    end_date = datetime.strptime(filters['end_date'], '%Y-%m-%d')
                    # Add 1 day to include the entire end date
                    end_date = end_date + timedelta(days=1)
                    query = query.filter(Product.created_at < end_date)
                except ValueError:
                    pass
    
    return query

def apply_search_query(query, search_term):
    """Apply full-text search with better query matching"""
    if not search_term:
        return query
    
    # Split search term into individual words
    search_words = search_term.strip().split()
    
    if len(search_words) == 1:
        # Single word search - search in title, description, and category
        word = f"%{search_words[0]}%"
        query = query.join(Category).filter(
            or_(
                Product.title.ilike(word),
                Product.description.ilike(word),
                Category.name.ilike(word)
            )
        )
    else:
        # Multiple words - create flexible matching
        search_conditions = []
        
        for word in search_words:
            word_pattern = f"%{word}%"
            search_conditions.extend([
                Product.title.ilike(word_pattern),
                Product.description.ilike(word_pattern),
                Category.name.ilike(word_pattern)
            ])
        
        # Join with Category for category name search
        query = query.join(Category).filter(or_(*search_conditions))
    
    return query

def apply_sorting(query, sort_by):
    """Apply sorting to product query"""
    if sort_by == 'price_low':
        return query.order_by(asc(Product.price))
    elif sort_by == 'price_high':
        return query.order_by(desc(Product.price))
    elif sort_by == 'popularity':
        return query.order_by(desc(Product.view_count), desc(Product.created_at))
    elif sort_by == 'oldest':
        return query.order_by(asc(Product.created_at))
    else:  # Default: newest first
        return query.order_by(desc(Product.created_at))
def get_price_statistics():
    """Get price statistics for better filtering UX"""
    result = db.session.query(
        func.min(Product.price).label('min_price'),
        func.max(Product.price).label('max_price'),
        func.avg(Product.price).label('avg_price')
    ).filter(Product.is_sold == False).first()
    
    return {
        'min_price': float(result.min_price or 0),
        'max_price': float(result.max_price or 0),
        'avg_price': float(result.avg_price or 0)
    }
def calculate_average_rating(user_id=None, product_id=None):
    """Calculate average rating for a user or product"""
    query = Rating.query.filter_by(is_approved=True)
    
    if user_id:
        query = query.filter_by(ratee_id=user_id)
    elif product_id:
        query = query.filter_by(product_id=product_id)
    
    avg_rating = query.with_entities(func.avg(Rating.stars)).scalar()
    return round(avg_rating, 1) if avg_rating else None

def get_rating_count(user_id=None, product_id=None):
    """Get count of ratings for a user or product"""
    query = Rating.query.filter_by(is_approved=True)
    
    if user_id:
        query = query.filter_by(ratee_id=user_id)
    elif product_id:
        query = query.filter_by(product_id=product_id)
    
    return query.count()

def get_recent_reviews(user_id=None, product_id=None, limit=5):
    """Get recent reviews for a user or product"""
    query = Rating.query.filter_by(is_approved=True).order_by(Rating.created_at.desc())
    
    if user_id:
        query = query.filter_by(ratee_id=user_id)
    elif product_id:
        query = query.filter_by(product_id=product_id)
    
    return query.limit(limit).all()