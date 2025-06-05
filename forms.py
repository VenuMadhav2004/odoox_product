from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, TextAreaField, FloatField,
    SelectField, FileField, SubmitField
)
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo,
    NumberRange, Optional, Regexp
)
from flask_wtf.file import FileAllowed

# Allowed image extensions for uploads
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message='Enter a valid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired()
    ])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=50)
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    role = SelectField('Account Type', 
                      choices=[('buyer', 'Buyer'), ('seller', 'Seller'), ('both', 'Both')],
                      default='both',
                      validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6)
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Sign Up')

class OTPVerificationForm(FlaskForm):
    otp_code = StringField('Enter 6-digit OTP', validators=[
        DataRequired(),
        Length(min=6, max=6),
        Regexp('^[0-9]+$', message='OTP must contain only digits')
    ])
    submit = SubmitField('Verify')

class ResendOTPForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    submit = SubmitField('Resend OTP')

class UserProfileForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=50)
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    phone = StringField('Phone Number', validators=[
        Optional(),
        Length(max=20)
    ])
    address = StringField('Address', validators=[
        Optional(),
        Length(max=200)
    ])
    bio = TextAreaField('Bio', validators=[Length(max=500)]) 
    submit = SubmitField('Update Profile')

class ProductForm(FlaskForm):
    title = StringField('Product Title', validators=[
        DataRequired(),
        Length(min=3, max=100)
    ])
    description = TextAreaField('Description', validators=[
        DataRequired(),
        Length(min=10)
    ])
    price = FloatField('Price ($)', validators=[
        DataRequired(),
        NumberRange(min=0.01)
    ])
    
    category = SelectField('Category', coerce=int, validators=[Optional()], choices=[])
    
    condition = SelectField('Condition', choices=[
        ('new', 'New'),
        ('used', 'Used'),
        ('refurbished', 'Refurbished')
    ], validators=[DataRequired()])
    
    location = StringField('Location', validators=[DataRequired()])
    
    image = FileField('Product Image', validators=[
        FileAllowed(ALLOWED_EXTENSIONS, 'Only image files are allowed!')
    ])
    submit = SubmitField('Submit Product')
