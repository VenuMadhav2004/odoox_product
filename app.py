from datetime import datetime,UTC
from forms import LoginForm, SignupForm, ProductForm, UserProfileForm, OTPVerificationForm, ResendOTPForm
import secrets
from helpers import allowed_file, create_otp_record, verify_otp, send_otp_email, cleanup_expired_otps, apply_search_query, apply_advanced_filters, apply_sorting,human_readable_timedelta, calculate_average_rating
from flask import Flask, session, request, redirect, url_for, flash, render_template,jsonify,current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from extensions import db, mail
from config import DevelopmentConfig
from sqlalchemy import or_, and_, func, desc, asc
from datetime import datetime, timedelta
from functools import wraps
#from models import Dispute,Rating,Auction,Bid,User, Product, Category, CartItem, Purchase, OTPRecord
from sqlalchemy import select
from flask_login import current_user
from forms import UserProfileForm
# Initialize Flask app
app = Flask(__name__)
app.config.from_object(DevelopmentConfig)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecofinds.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/images/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)
mail.init_app(app)

# Import models after initializing db to avoid circular imports
from models import User, Product, Category, CartItem, Purchase, OTPRecord, Dispute,Rating,Auction,Bid,WishlistItem,Conversation, Message

def init_db():
    """Initialize database tables and create default categories"""
    with app.app_context():
        db.create_all()
        
        # Create default categories if they don't exist
        if Category.query.count() == 0:
            categories = [
                "Clothing", "Electronics", "Furniture", "Books", 
                "Home & Garden", "Sports & Outdoors", "Toys & Games", "Other"
            ]
            for category_name in categories:
                category = Category(name=category_name)
                db.session.add(category)
            db.session.commit()

# Authentication check decorator
from functools import wraps
from flask import abort, flash, redirect, url_for

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page', 'warning')
                return redirect(url_for('login'))
            
            user = User.query.get(session['user_id'])
            if not user or user.role != role:
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    return role_required('admin')(f)

def seller_required(f):
    return role_required('seller')(f)

# Verification required decorator
def verification_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user.is_verified:
            flash('Please verify your email first', 'warning')
            return redirect(url_for('verify_email'))
        
        return f(*args, **kwargs)
    return decorated_function
@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return dict(current_user=user)
    return dict(current_user=None)

@app.context_processor
def inject_categories():
    categories = Category.query.all()
    return dict(categories=categories)

@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        # Calculate total unread messages
        unread_count = 0
        if user:
            unread_count = db.session.query(func.count(Message.id)).join(Conversation).filter(
                or_(
                    Conversation.user1_id == user.id,
                    Conversation.user2_id == user.id
                ),
                Message.sender_id != user.id,
                Message.is_read == False
            ).scalar()
        return dict(current_user=user, unread_messages=unread_count)
    return dict(current_user=None, unread_messages=0)


# Route for home page
@app.route('/')
def index():
    # Get all filter parameters
    search_query = request.args.get('search', '').strip()
    category_id = request.args.get('category')
    min_price = request.args.get('min_price', '')
    max_price = request.args.get('max_price', '')
    condition = request.args.get('condition', 'all')
    location = request.args.get('location', '').strip()
    date_range = request.args.get('date_range', 'all')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    sort_by = request.args.get('sort', 'newest')
    
    # Start with base query (only unsold products)
    query = Product.query.filter_by(is_sold=False)
    
    # Apply search query
    if search_query:
        query = apply_search_query(query, search_query)
    else:
        # If no search query, we still need to join Category for other operations
        query = query.join(Category)
    
    # Apply category filter
    if category_id and category_id.isdigit() and category_id != '0':
        query = query.filter(Product.category_id == int(category_id))
    
    # Apply advanced filters
    filters = {
        'min_price': min_price,
        'max_price': max_price,
        'condition': condition,
        'location': location,
        'date_range': date_range,
        'start_date': start_date,
        'end_date': end_date
    }
    query = apply_advanced_filters(query, filters)
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.can_sell():
            query = query.filter(Product.seller_id != session['user_id'])
    
    # Apply sorting
    query = apply_sorting(query, sort_by)
    
    # Execute query
    products = query.all()
    
    # Get all categories for dropdown
    categories = Category.query.all()
    
    # Get unique conditions and locations for filter dropdowns
    conditions = ['New', 'Like New', 'Good', 'Fair', 'Used']
    locations = db.session.query(Product.location).filter(
        Product.location.isnot(None),
        Product.location != ''
    ).distinct().all()
    locations = [loc[0] for loc in locations if loc[0]]
    
    # Prepare filter data for template
    filter_data = {
        'search_query': search_query,
        'category_id': category_id,
        'min_price': min_price,
        'max_price': max_price,
        'condition': condition,
        'location': location,
        'date_range': date_range,
        'start_date': start_date,
        'end_date': end_date,
        'sort_by': sort_by
    }
    
    return render_template('index.html', 
                          products=products, 
                          categories=categories,
                          conditions=conditions,
                          locations=locations,
                          filters=filter_data,
                          total_results=len(products))

# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Please verify your email before logging in', 'warning')
                return redirect(url_for('verify_email', email=email))
            
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True  # Keep user logged in
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html', form=form)

# Route for signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    form.role.choices = [('buyer', 'Buyer'), ('seller', 'Seller'), ('both', 'Both')]
    
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('signup'))
            
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('signup'))
            
        user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        # Send verification email
        otp_code = create_otp_record(user.id, 'registration')
        success, message = send_otp_email(user.email, user.username, otp_code, 'registration')
        
        if success:
            flash('Account created! Please check your email for verification.', 'success')
            return redirect(url_for('verify_email', email=user.email))
        else:
            flash(f'Account created but email failed: {message}', 'warning')
            return redirect(url_for('verify_email', email=user.email))
    
    return render_template('signup.html', form=form)

# Route for email verification
@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    email = request.args.get('email') or request.form.get('email')
    form = OTPVerificationForm()
    
    if not email:
        flash('Email not provided', 'danger')
        return redirect(url_for('signup'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('signup'))
    
    if user.is_verified:
        flash('Email already verified', 'info')
        return redirect(url_for('login'))
    
    if form.validate_on_submit():
        otp_code = form.otp_code.data
        
        success, message = verify_otp(user.id, otp_code, 'registration')
        
        if success:
            user.is_verified = True
            db.session.commit()
            flash('Email verified successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'danger')
    
    return render_template('verify_email.html', form=form, email=email)

# Route for resending OTP
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    email = request.form.get('email')
    
    if not email:
        flash('Email not provided', 'danger')
        return redirect(url_for('signup'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('signup'))
    
    if user.is_verified:
        flash('Email already verified', 'info')
        return redirect(url_for('login'))
    
    # Generate new OTP
    otp_code = create_otp_record(user.id, 'registration')
    success, message = send_otp_email(user.email, user.username, otp_code, 'registration')
    
    if success:
        flash('New verification code sent to your email', 'success')
    else:
        flash(f'Failed to send verification code: {message}', 'danger')
    
    return redirect(url_for('verify_email', email=email))
@app.route('/upgrade-account', methods=['GET', 'POST'])
@verification_required
def upgrade_account():
    if request.method == 'POST':
        current_user.role = request.form.get('role', 'both')  # Get selected role or default to 'both'
        db.session.commit()
        session['role'] = current_user.role  # Update role in session
        flash('Account upgraded successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('upgrade_account.html')

# Route for logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Admin statistics
    total_users = User.query.count()
    total_products = Product.query.count()
    total_sales = Purchase.query.count()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_products=total_products,
                         total_sales=total_sales,
                         recent_users=recent_users)

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f'User {user.username} has been {"activated" if user.is_active else "deactivated"}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/promote', methods=['POST'])
@admin_required
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'buyer':
        user.role = 'seller'
    elif user.role == 'seller':
        user.role = 'admin'
    db.session.commit()
    flash(f'User {user.username} has been promoted to {user.role}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/disputes')
@admin_required
def admin_disputes():
    disputes = Dispute.query.order_by(Dispute.created_at.desc()).all()
    return render_template('admin/disputes.html', disputes=disputes)

@app.route('/admin/dispute/<int:dispute_id>/resolve', methods=['POST'])
@admin_required
def resolve_dispute(dispute_id):
    dispute = Dispute.query.get_or_404(dispute_id)
    dispute.status = 'resolved'
    db.session.commit()
    flash('Dispute has been resolved', 'success')
    return redirect(url_for('admin_disputes'))
@app.route('/seller/dashboard')
@verification_required
def seller_dashboard():
    user = User.query.get(session['user_id'])
    if not user.can_sell():
        flash('You need to be a seller to access this page', 'danger')
        return redirect(url_for('index'))
    
    # Seller statistics
    total_products = Product.query.filter_by(seller_id=user.id).count()
    total_sales = Purchase.query.join(Product).filter(Product.seller_id == user.id).count()
    total_earnings = db.session.query(func.sum(Purchase.price)).join(Product).filter(
        Product.seller_id == user.id).scalar() or 0
    
    # Recent sales
    recent_sales = Purchase.query.join(Product).filter(
        Product.seller_id == user.id
    ).order_by(Purchase.purchase_date.desc()).limit(5).all()
    
    return render_template('seller/dashboard.html',
                         total_products=total_products,
                         total_sales=total_sales,
                         total_earnings=total_earnings,
                         recent_sales=recent_sales)

@app.route('/seller/products')
@verification_required
def seller_products():
    user = User.query.get(session['user_id'])
    if not user.can_sell():
        flash('You need to be a seller to access this page', 'danger')
        return redirect(url_for('index'))
    
    products = Product.query.filter_by(seller_id=user.id).order_by(Product.created_at.desc()).all()
    return render_template('seller/products.html', products=products)

@app.route('/seller/sales')
@verification_required
def seller_sales():
    user = User.query.get(session['user_id'])
    if not user.can_sell():
        flash('You need to be a seller to access this page', 'danger')
        return redirect(url_for('index'))
    
    sales = Purchase.query.join(Product).filter(
        Product.seller_id == user.id
    ).order_by(Purchase.purchase_date.desc()).all()
    
    return render_template('seller/sales.html', sales=sales)

# Route for user dashboard (requires verification)
@app.route('/dashboard', methods=['GET', 'POST'])  # Add POST method
@verification_required
def dashboard():
    user = User.query.get(session['user_id'])
    form = UserProfileForm(obj=user)  # Create form instance with user data
    
    # Handle form submission
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.phone = form.phone.data
        user.address = form.address.data
        user.bio = form.bio.data 
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('dashboard'))
    
    # Get user's listings if they can sell
    listings = []
    if user.can_sell():
        listings = Product.query.filter_by(seller_id=user.id).order_by(Product.created_at.desc()).all()
    
    # Get user's purchases if they can buy
    purchases = []
    if user.can_buy():
        purchases = Purchase.query.filter_by(user_id=user.id).order_by(Purchase.purchase_date.desc()).all()
    
    return render_template('dashboard.html', 
                         user=user,
                         form=form,  # Pass the form to template
                         listings=listings,
                         purchases=purchases)
@app.route('/rate-purchase/<int:purchase_id>', methods=['GET', 'POST'])
@verification_required
def rate_purchase(purchase_id):
    purchase = Purchase.query.get_or_404(purchase_id)
    
    # Check if current user is the buyer
    if purchase.user_id != session['user_id']:
        flash("You can only rate purchases you've made", 'danger')
        return redirect(url_for('purchases'))
    
    # Check if already rated
    existing_rating = Rating.query.filter_by(purchase_id=purchase_id).first()
    if existing_rating:
        flash("You've already rated this purchase", 'info')
        return redirect(url_for('purchases'))
    
    if request.method == 'POST':
        stars = int(request.form.get('stars', 0))
        comment = request.form.get('comment', '').strip()
        
        if not 1 <= stars <= 5:
            flash('Please select a rating between 1 and 5 stars', 'danger')
            return redirect(url_for('rate_purchase', purchase_id=purchase_id))
        
        new_rating = Rating(
            rater_id=session['user_id'],
            ratee_id=purchase.product.seller_id,
            product_id=purchase.product_id,
            purchase_id=purchase_id,
            stars=stars,
            comment=comment
        )
        
        db.session.add(new_rating)
        db.session.commit()
        
        flash('Thank you for your review!', 'success')
        return redirect(url_for('purchases'))
    
    return render_template('rate_purchase.html', purchase=purchase)

@app.route('/api/product/<int:product_id>/reviews')
def product_reviews(product_id):
    page = request.args.get('page', 1, type=int)
    per_page = 5
    
    reviews = Rating.query.filter_by(
        product_id=product_id,
        is_approved=True
    ).order_by(
        Rating.created_at.desc()
    ).paginate(page=page, per_page=per_page)
    
    reviews_data = [{
        'id': review.id,
        'rater_name': review.rater.username,
        'stars': review.stars,
        'comment': review.comment,
        'date': review.created_at.strftime('%B %d, %Y'),
        'humanized_date': human_readable_timedelta(review.created_at)
    } for review in reviews.items]
    
    return jsonify({
        'reviews': reviews_data,
        'has_next': reviews.has_next
    })

@app.route('/user/<int:user_id>/reviews')
def user_reviews(user_id):
    user = User.query.get_or_404(user_id)
    page = request.args.get('page', 1, type=int)
    per_page = 5
    
    reviews = Rating.query.filter_by(
        ratee_id=user_id,
        is_approved=True
    ).order_by(
        Rating.created_at.desc()
    ).paginate(page=page, per_page=per_page)
    
    return render_template('user_reviews.html', 
                         user=user, 
                         reviews=reviews,
                         calculate_average_rating=calculate_average_rating)
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)

    # Increment view count except seller viewing their own product
    if 'user_id' not in session or session['user_id'] != product.seller_id:
        product.view_count += 1
        db.session.commit()

    auction = None
    bids = []
    highest_bid = None
    time_remaining = None
    is_highest_bidder = False

    # Try to get auction info if auction product
    if product.is_auction:
        auction = Auction.query.filter_by(product_id=product.id).first()
        if auction:
            bids = Bid.query.filter_by(auction_id=auction.id).order_by(Bid.amount.desc()).all()
            highest_bid = bids[0] if bids else None
            if auction.end_time:
                time_remaining = auction.end_time - datetime.utcnow()

    if 'user_id' in session:
        user = User.query.get(session['user_id'])

        # Seller view for own product
        if user.id == product.seller_id:
            return render_template(
                'seller_product_view.html',
                product=product,
                auction=auction,
                bids=bids
            )
        
        # Buyer view for auction product
        if product.is_auction:
            if highest_bid and highest_bid.user_id == user.id:
                is_highest_bidder = True
            return render_template(
                'auction_detail.html',
                product=product,
                auction=auction,
                time_remaining=time_remaining,
                highest_bid=highest_bid,
                is_highest_bidder=is_highest_bidder
            )

    # For non-logged-in or non-seller, non-auction products, just render generic product view
    return render_template('product_detail.html', product=product)
    

@app.route('/api/search-suggestions')
def search_suggestions():
    query = request.args.get('q', '').strip()
    
    if len(query) < 2:
        return {'suggestions': []}
    
    # Get product title suggestions
    title_suggestions = db.session.query(Product.title).filter(
        Product.title.ilike(f'%{query}%'),
        Product.is_sold == False
    ).distinct().limit(5).all()
    
    # Get category suggestions
    category_suggestions = db.session.query(Category.name).filter(
        Category.name.ilike(f'%{query}%')
    ).distinct().limit(3).all()
    
    suggestions = []
    suggestions.extend([title[0] for title in title_suggestions])
    suggestions.extend([f"in {cat[0]}" for cat in category_suggestions])
    
    return {'suggestions': suggestions[:8]}

# Add route for saved searches (if you want to implement this feature)
@app.route('/save-search', methods=['POST'])
@verification_required
def save_search():
    """Save a search query for later use or alerts"""
    search_data = {
        'query': request.form.get('search', ''),
        'category': request.form.get('category', ''),
        'min_price': request.form.get('min_price', ''),
        'max_price': request.form.get('max_price', ''),
        'condition': request.form.get('condition', ''),
        'location': request.form.get('location', '')
    }
    
    # You can save this to a SavedSearch model or user session
    # For now, we'll just store in session
    if 'saved_searches' not in session:
        session['saved_searches'] = []
    
    session['saved_searches'].append(search_data)
    session.modified = True
    
    flash('Search saved successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/product/add', methods=['GET', 'POST'])
@verification_required
def add_product():
    form = ProductForm()
    
    # Example category choices — you can fetch these dynamically from DB if you want
    form.category.choices = [
        (1, 'Clothing'),
        (2, 'Electronics'),
        (3, 'Books'),
        (4, 'Furniture'),
        (5, 'Others')
    ]
    
    if form.validate_on_submit():
        product = Product(
            title=form.title.data,
            description=form.description.data,
            price=form.price.data,
            category_id=form.category.data,
            condition=form.condition.data,
            location=form.location.data,
        )
        
        # Handle image upload
        if form.image.data:
            image_file = form.image.data
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
            product.image = filename
        
        db.session.add(product)
        db.session.commit()
        
        flash('Product listed successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_product.html', form=form)





# Route for editing a product (requires verification)
@app.route('/product/edit/<int:product_id>', methods=['GET', 'POST'])
@verification_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    user = User.query.get(session['user_id'])
    
    # Only allow seller or admin to edit
    if product.seller_id != user.id and not user.is_admin():
        flash('You can only edit your own listings', 'danger')
        return redirect(url_for('index'))
    
    form = ProductForm(obj=product)
    form.category.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        product.title = form.title.data
        product.description = form.description.data
        product.price = form.price.data
        product.category_id = form.category.data
        
        # Handle image upload
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add timestamp to filename to avoid conflicts
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                image_filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                
                # Remove old image if it's not the placeholder
                if product.image != 'placeholder.png':
                    try:
                        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image)
                        if os.path.exists(old_image_path):
                            os.remove(old_image_path)
                    except Exception as e:
                        print(f"Error removing old image: {e}")
                
                product.image = image_filename
        
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_product.html', form=form, product=product)

# Route for deleting a product (requires verification)
@app.route('/product/delete/<int:product_id>', methods=['POST'])
@verification_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Check if current user is the seller
    if product.seller_id != session['user_id']:
        flash('You can only delete your own listings', 'danger')
        return redirect(url_for('dashboard'))
    
    # Remove product image if it's not the placeholder
    if product.image != 'placeholder.png':
        try:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image)
            if os.path.exists(image_path):
                os.remove(image_path)
        except Exception as e:
            print(f"Error removing image: {e}")
    
    db.session.delete(product)
    db.session.commit()
    
    flash('Product deleted successfully', 'success')
    return redirect(url_for('dashboard'))
@app.route('/wishlist')
def wishlist():
    # You'll need to implement user authentication
    wishlist_items = WishlistItem.query.filter_by(user_id=current_user.id).all()
    return render_template('wishlist.html', items=wishlist_items)

@app.route('/messages')
@verification_required
def messages():
    user_id = session['user_id']
    
    # Get all conversations for the current user
    conversations = Conversation.query.filter(
        or_(
            Conversation.user1_id == user_id,
            Conversation.user2_id == user_id
        )
    ).order_by(
        Conversation.last_updated.desc()
    ).all()
    
    # Add unread counts and last message to each conversation
    for conv in conversations:
        conv.unread_count = Message.query.filter(
            Message.conversation_id == conv.id,
            Message.sender_id != user_id,
            Message.is_read == False
        ).count()
        
        conv.last_message = Message.query.filter_by(
            conversation_id=conv.id
        ).order_by(
            Message.sent_at.desc()
        ).first()
    
    return render_template('messages/inbox.html', conversations=conversations)

@app.route('/messages/<int:conversation_id>')
@verification_required
def view_conversation(conversation_id):
    conversation = Conversation.query.get_or_404(conversation_id)
    user_id = session['user_id']
    
    # Verify user is part of conversation
    if user_id not in [conversation.user1_id, conversation.user2_id]:
        abort(403)
    
    # Mark messages as read
    Message.query.filter(
        Message.conversation_id == conversation_id,
        Message.sender_id != user_id,
        Message.is_read == False
    ).update({'is_read': True})
    db.session.commit()
    
    messages = Message.query.filter_by(
        conversation_id=conversation_id
    ).order_by(
        Message.sent_at.asc()
    ).all()
    
    other_user = conversation.get_other_user(user_id)
    
    return render_template('messages/conversation.html',
                         conversation=conversation,
                         messages=messages,
                         other_user=other_user)

@app.route('/messages/new/<int:recipient_id>', methods=['GET', 'POST'])
@verification_required
def new_conversation(recipient_id):
    user_id = session['user_id']
    recipient = User.query.get_or_404(recipient_id)
    
    if user_id == recipient_id:
        flash("You can't message yourself", 'danger')
        return redirect(url_for('messages'))
    
    # Check if conversation already exists
    conversation = Conversation.query.filter(
        or_(
            and_(Conversation.user1_id == user_id, Conversation.user2_id == recipient_id),
            and_(Conversation.user1_id == recipient_id, Conversation.user2_id == user_id)
        )
    ).first()
    
    if conversation:
        return redirect(url_for('view_conversation', conversation_id=conversation.id))
    
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        if not content:
            flash('Message cannot be empty', 'danger')
            return render_template('messages/new.html', recipient=recipient)
        
        # Create new conversation
        new_conv = Conversation(
            user1_id=user_id,
            user2_id=recipient_id
        )
        db.session.add(new_conv)
        db.session.commit()
        
        # Add first message
        new_message = Message(
            conversation_id=new_conv.id,
            sender_id=user_id,
            content=content
        )
        db.session.add(new_message)
        db.session.commit()
        
        flash('Message sent!', 'success')
        return redirect(url_for('view_conversation', conversation_id=new_conv.id))
    
    return render_template('messages/new.html', recipient=recipient)

@app.route('/messages/send/<int:conversation_id>', methods=['POST'])
@verification_required
def send_message(conversation_id):
    conversation = Conversation.query.get_or_404(conversation_id)
    user_id = session['user_id']
    
    # Verify user is part of conversation
    if user_id not in [conversation.user1_id, conversation.user2_id]:
        abort(403)
    
    content = request.form.get('content', '').strip()
    if not content:
        flash('Message cannot be empty', 'danger')
        return redirect(url_for('view_conversation', conversation_id=conversation_id))
    
    new_message = Message(
        conversation_id=conversation_id,
        sender_id=user_id,
        content=content
    )
    
    # Update conversation last_updated
    conversation.last_updated = datetime.utcnow()
    
    db.session.add(new_message)
    db.session.commit()
    
    return redirect(url_for('view_conversation', conversation_id=conversation_id))
@app.route('/contact-seller/<int:product_id>', methods=['GET', 'POST'])
@verification_required
def contact_seller(product_id):
    product = Product.query.get_or_404(product_id)
    seller = product.seller
    buyer_id = session['user_id']
    
    # Prevent sellers from messaging themselves
    if buyer_id == seller.id:
        flash("You can't message yourself", 'danger')
        return redirect(url_for('product_detail', product_id=product_id))
    
    # Check for existing conversation
    conversation = Conversation.query.filter(
        or_(
            and_(Conversation.user1_id == buyer_id, Conversation.user2_id == seller.id),
            and_(Conversation.user1_id == seller.id, Conversation.user2_id == buyer_id)
        )
    ).first()
    
    # If new conversation
    if not conversation:
        conversation = Conversation(
            user1_id=buyer_id,
            user2_id=seller.id
        )
        db.session.add(conversation)
        db.session.commit()
    
    # Handle message submission
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        if not content:
            flash('Message cannot be empty', 'danger')
        else:
            # Create message with product reference
            message = Message(
                conversation_id=conversation.id,
                sender_id=buyer_id,
                content=f"Regarding your product: {product.title}\n\n{content}",
                product_id=product_id
            )
            db.session.add(message)
            conversation.last_updated = datetime.utcnow()
            db.session.commit()
            flash('Message sent to seller!', 'success')
            return redirect(url_for('view_conversation', conversation_id=conversation.id))
    
    return render_template('messages/contact_seller.html',
                         product=product,
                         seller=seller,
                         conversation=conversation)
@app.route('/add_to_wishlist/<int:product_id>')
def add_to_wishlist(product_id):
    # Check if item already in wishlist
    existing = WishlistItem.query.filter_by(
        user_id=current_user.id,
        product_id=product_id
    ).first()
    
    if not existing:
        new_item = WishlistItem(user_id=current_user.id, product_id=product_id)
        db.session.add(new_item)
        db.session.commit()
        flash('Item added to wishlist!', 'success')
    else:
        flash('Item already in wishlist!', 'info')
    
    return redirect(url_for('product', product_id=product_id))  # or wherever you came from

@app.route('/remove_from_wishlist/<int:item_id>')
def remove_from_wishlist(item_id):
    item = WishlistItem.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Item removed from wishlist', 'success')
    return redirect(url_for('wishlist'))

# Route for adding a product to cart (requires verification)
@app.route('/cart/add/<int:product_id>', methods=['POST'])
@verification_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Check if product is already sold
    if product.is_sold:
        flash('This product is no longer available', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))
    
    # Check if product is not the user's own listing
    if product.seller_id == session['user_id']:
        flash('You cannot add your own product to cart', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))
    
    # Check if item is already in cart
    existing_item = CartItem.query.filter_by(
        user_id=session['user_id'], 
        product_id=product_id
    ).first()
    
    if existing_item:
        flash('Product already in cart', 'info')
    else:
        cart_item = CartItem(
            user_id=session['user_id'],
            product_id=product_id
        )
        db.session.add(cart_item)
        db.session.commit()
        flash('Product added to cart', 'success')
    
    return redirect(url_for('cart'))

# Route for removing a product from cart (requires verification)
@app.route('/cart/remove/<int:item_id>', methods=['POST'])
@verification_required
def remove_from_cart(item_id):
    cart_item = CartItem.query.get_or_404(item_id)
    
    # Check if item belongs to current user
    if cart_item.user_id != session['user_id']:
        flash('Invalid action', 'danger')
        return redirect(url_for('cart'))
    
    db.session.delete(cart_item)
    db.session.commit()
    
    flash('Product removed from cart', 'success')
    return redirect(url_for('cart'))

# Route for viewing cart (requires verification)
@app.route('/cart')
@verification_required
def cart():
    cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
    
    # Calculate total price
    total = sum(item.product.price for item in cart_items)
    
    return render_template('cart.html', cart_items=cart_items, total=total)

# Route for checkout/purchase (requires verification)
@app.route('/checkout', methods=['POST'])
@verification_required
def checkout():
    cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
    
    if not cart_items:
        flash('Your cart is empty', 'warning')
        return redirect(url_for('cart'))
    
    # Create purchase records and mark products as sold
    for item in cart_items:
        # Check if product is still available
        if item.product.is_sold:
            flash(f'Product "{item.product.title}" is no longer available', 'danger')
            continue
        
        # Mark as sold
        item.product.is_sold = True
        
        # Create purchase record
        purchase = Purchase(
            user_id=session['user_id'],
            product_id=item.product.id,
            price=item.product.price,
            purchase_date=datetime.now()
        )
        
        db.session.add(purchase)
        db.session.delete(item)  # Remove from cart
    
    db.session.commit()
    flash('Purchase completed successfully!', 'success')
    return redirect(url_for('purchases'))
@app.route('/api/cart/count')
@verification_required
def api_cart_count():
    if 'user_id' not in session:
        return jsonify({'count': 0})
    
    count = CartItem.query.filter_by(user_id=session['user_id']).count()
    return jsonify({'count': count})
# Route for viewing previous purchases (requires verification)
@app.route('/purchases')
@verification_required
def purchases():
    user_purchases = Purchase.query.filter_by(user_id=session['user_id']).order_by(Purchase.purchase_date.desc()).all()
    return render_template('purchases.html', purchases=user_purchases)

# Add these routes to your existing routes

@app.route('/auctions')
def auctions():
    """Show all active auctions"""
    active_auctions = Auction.query.filter(
        Auction.is_active == True,
        Auction.end_time > datetime.utcnow()
    ).order_by(Auction.end_time.asc()).all()
    
    return render_template('auctions.html', auctions=active_auctions)

@app.route('/auction/<int:auction_id>')
def auction_detail(auction_id):
    """Show details of a specific auction"""
    auction = Auction.query.get_or_404(auction_id)
    time_remaining = auction.end_time - datetime.utcnow()
    
    return render_template('auction_detail.html', 
                         auction=auction,
                         time_remaining=time_remaining)

@app.route('/auction/create', methods=['GET', 'POST'])
@verification_required
def create_auction():
    """Create a new auction listing"""
    user = User.query.get(session['user_id'])
    if not user.can_sell():
        flash('You need to be a seller to create auctions', 'danger')
        return redirect(url_for('index'))
    
    form = ProductForm()  # Reuse your existing product form
    
    if form.validate_on_submit():
        # First create the product
        image_filename = 'placeholder.png'
        
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                image_filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        
        # Create product with is_auction=True
        product = Product(
            title=form.title.data,
            description=form.description.data,
            price=0,  # Price will be determined by auction
            category_id=form.category.data,
            condition=request.form.get('condition', 'Used'),
            location=request.form.get('location', user.address or ''),
            image=image_filename,
            seller_id=session['user_id'],
            is_auction=True,
            is_sold=False
        )
        db.session.add(product)
        db.session.commit()
        
        # Parse duration from form (e.g., 1 day, 3 days, 1 week)
        duration = request.form.get('duration', '1')
        try:
            duration_days = int(duration)
        except ValueError:
            duration_days = 1
            
        # Create the auction
        auction = Auction(
            product_id=product.id,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow() + timedelta(days=duration_days),
            starting_price=float(request.form.get('starting_price', 0)),
            current_price=float(request.form.get('starting_price', 0)),
            is_active=True
        )
        db.session.add(auction)
        db.session.commit()
        
        flash('Auction created successfully!', 'success')
        return redirect(url_for('auction_detail', auction_id=auction.id))
    
    return render_template('create_auction.html', form=form)

@app.route('/auction/<int:auction_id>/bid', methods=['POST'])
@verification_required
def place_bid(auction_id):
    """Place a bid on an auction with proper validation"""
    try:
        # Start transaction
        with db.session.begin():
            # Lock auction row
            auction = db.session.execute(
                select(Auction)
                .where(Auction.id == auction_id)
                .with_for_update()
            ).scalar_one()

            user = User.query.get(session['user_id'])
            now = datetime.utcnow()

            # Validate auction
            if not auction.is_active or now > auction.end_time:
                auction.is_active = False
                db.session.commit()
                flash('This auction has ended', 'danger')
                return redirect(url_for('auction_detail', auction_id=auction_id))

            # Validate user
            if auction.product.seller_id == user.id:
                flash('You cannot bid on your own auction', 'danger')
                return redirect(url_for('auction_detail', auction_id=auction_id))

            # Validate bid amount
            try:
                bid_amount = float(request.form['bid_amount'])
            except (ValueError, KeyError):
                flash('Invalid bid amount', 'danger')
                return redirect(url_for('auction_detail', auction_id=auction_id))

            # Calculate minimum bid
            min_increment = 1.00
            min_bid = auction.current_price + min_increment
            if auction.bids.count() == 0:  # First bid
                min_bid = max(auction.starting_price, min_bid)

            if bid_amount < min_bid:
                flash(f'Bid must be at least ${min_bid:.2f}', 'danger')
                return redirect(url_for('auction_detail', auction_id=auction_id))

            # Create bid
            bid = Bid(
                auction_id=auction.id,
                user_id=user.id,
                amount=bid_amount
            )
            auction.current_price = bid_amount

            # Sniping protection
            if (auction.end_time - now) < timedelta(minutes=5):
                auction.end_time += timedelta(minutes=5)
                flash('Auction extended by 5 minutes!', 'info')

            db.session.add(bid)
            db.session.commit()

            flash(f'Bid of ${bid_amount:.2f} placed successfully!', 'success')
            return redirect(url_for('auction_detail', auction_id=auction_id))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Bid error: {str(e)}", exc_info=True)
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('auction_detail', auction_id=auction_id))

   
@app.route('/api/auction/<int:auction_id>/status')
def auction_status(auction_id):
    """API endpoint for checking auction status (for real-time updates)"""
    auction = Auction.query.get_or_404(auction_id)
    
    return jsonify({
        'current_price': auction.current_price,
        'is_active': auction.is_active and datetime.utcnow() < auction.end_time,
        'time_remaining': str(auction.end_time - datetime.utcnow()),
        'bid_count': auction.bids.count()
    })

# Scheduled task to check for ended auctions
def check_ended_auctions():
    """Check for auctions that have ended and process them"""
    with app.app_context():
        ended_auctions = Auction.query.filter(
            Auction.is_active == True,
            Auction.end_time <= datetime.now(UTC)
        ).all()
        
        for auction in ended_auctions:
            auction.is_active = False
            
            # Mark product as sold if there were bids
            if auction.bids.count() > 0:
                auction.product.is_sold = True
                
                # Get the winning bid
                winning_bid = auction.bids.order_by(Bid.amount.desc()).first()
                
                # Create purchase record
                purchase = Purchase(
                    user_id=winning_bid.user_id,
                    product_id=auction.product.id,
                    price=winning_bid.amount,
                    purchase_date=datetime.utcnow()
                )
                db.session.add(purchase)
                
                # TODO: Send notification to winner and seller
                
            db.session.commit()

# Add this to your app's startup or use a scheduler like APScheduler
# For example, to run every minute:
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()
scheduler.add_job(func=check_ended_auctions, trigger="interval", minutes=1)
scheduler.start()
# Cleanup task - run periodically to clean expired OTPs
@app.before_request
def cleanup_otps():
    """Clean up expired OTPs before each request (you might want to do this less frequently in production)"""
    if request.endpoint and request.endpoint not in ['static', 'favicon.ico']:
        cleanup_expired_otps()



if __name__ == '__main__':
    init_db()
    app.run(debug=True)