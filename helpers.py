import os
import random
import string
from datetime import datetime, timedelta
from flask import current_app
from flask_mail import Message
from extensions import mail, db
from models import OTPRecord

def allowed_file(filename):
    """Check if a file has an allowed extension"""
    allowed_ext = current_app.config.get('ALLOWED_EXTENSIONS', set())
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_ext

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

def generate_otp(length=6):
    """Generate a random OTP of specified length"""
    return ''.join(random.choices(string.digits, k=length))

def create_otp_record(user_id, otp_type='registration', expiry_minutes=10):
    """Create a new OTP record for a user"""
    # Delete any existing unused OTPs for this user and type
    OTPRecord.query.filter_by(
        user_id=user_id, 
        otp_type=otp_type, 
        is_used=False
    ).delete()
    
    # Generate new OTP
    otp_code = generate_otp(length=current_app.config.get('OTP_LENGTH', 6))
    expires_at = datetime.now() + timedelta(minutes=expiry_minutes)
    
    # Create new OTP record
    otp_record = OTPRecord(
        user_id=user_id,
        otp_code=otp_code,
        otp_type=otp_type,
        expires_at=expires_at
    )
    
    db.session.add(otp_record)
    db.session.commit()
    
    return otp_code

def verify_otp(user_id, otp_code, otp_type='registration'):
    """Verify an OTP code for a user"""
    otp_record = OTPRecord.query.filter_by(
        user_id=user_id,
        otp_code=otp_code,
        otp_type=otp_type,
        is_used=False
    ).first()
    
    if not otp_record:
        return False, "Invalid OTP code"
    
    if otp_record.is_expired():
        return False, "OTP has expired"
    
    # Mark OTP as used
    otp_record.is_used = True
    db.session.commit()
    
    return True, "OTP verified successfully"

def send_otp_email(user_email, username, otp_code, otp_type='registration'):
    """Send OTP via email"""
    try:
        # Determine email subject and content based on OTP type
        if otp_type == 'registration':
            subject = 'Verify Your EcoFinds Account'
            template = f"""
            <html>
            <body>
                <h2>Welcome to EcoFinds!</h2>
                <p>Hi {username},</p>
                <p>Thank you for registering with EcoFinds. To complete your registration, please use the following verification code:</p>
                <div style="background-color: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0;">
                    <h1 style="color: #007bff; font-size: 32px; margin: 0;">{otp_code}</h1>
                </div>
                <p>This code will expire in {current_app.config.get('OTP_EXPIRY_MINUTES', 10)} minutes.</p>
                <p>If you didn't create an account with EcoFinds, please ignore this email.</p>
                <br>
                <p>Best regards,<br>The EcoFinds Team</p>
            </body>
            </html>
            """
        elif otp_type == 'login':
            subject = 'Your EcoFinds Login Code'
            template = f"""
            <html>
            <body>
                <h2>EcoFinds Login Verification</h2>
                <p>Hi {username},</p>
                <p>Use this code to complete your login:</p>
                <div style="background-color: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0;">
                    <h1 style="color: #007bff; font-size: 32px; margin: 0;">{otp_code}</h1>
                </div>
                <p>This code will expire in {current_app.config.get('OTP_EXPIRY_MINUTES', 10)} minutes.</p>
                <p>If you didn't try to log in, please secure your account immediately.</p>
                <br>
                <p>Best regards,<br>The EcoFinds Team</p>
            </body>
            </html>
            """
        else:
            subject = 'Your EcoFinds Verification Code'
            template = f"""
            <html>
            <body>
                <h2>EcoFinds Verification</h2>
                <p>Hi {username},</p>
                <p>Your verification code is:</p>
                <div style="background-color: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0;">
                    <h1 style="color: #007bff; font-size: 32px; margin: 0;">{otp_code}</h1>
                </div>
                <p>This code will expire in {current_app.config.get('OTP_EXPIRY_MINUTES', 10)} minutes.</p>
                <br>
                <p>Best regards,<br>The EcoFinds Team</p>
            </body>
            </html>
            """
        
        # Create and send email
        msg = Message(
            subject=subject,
            recipients=[user_email],
            html=template
        )
        
        mail.send(msg)
        return True, "OTP sent successfully"
        
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False, f"Failed to send OTP: {str(e)}"

def cleanup_expired_otps():
    """Clean up expired OTP records"""
    try:
        expired_otps = OTPRecord.query.filter(
            OTPRecord.expires_at < datetime.now()
        ).all()
        
        for otp in expired_otps:
            db.session.delete(otp)
        
        db.session.commit()
        return len(expired_otps)
    except Exception as e:
        print(f"Error cleaning up expired OTPs: {str(e)}")
        return 0
