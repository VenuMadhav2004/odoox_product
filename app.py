from datetime import datetime
from forms import LoginForm, SignupForm, ProductForm, UserProfileForm
import secrets
from helpers import allowed_file
from flask import Flask, session, request, redirect, url_for, flash, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from extensions import db 
# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecofinds.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/images/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize the database
db.init_app(app)

# Import models after initializing db to avoid circular imports
from models import User, Product, Category, CartItem, Purchase

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
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Route for home page
@app.route('/')
def index():
    # Get search parameters
    search_query = request.args.get('search', '')
    category_id = request.args.get('category', None)
    
    # Build query
    query = Product.query.filter_by(is_sold=False)
    
    # Apply filters
    if search_query:
        query = query.filter(Product.title.contains(search_query))
    
    if category_id and category_id.isdigit():
        query = query.filter_by(category_id=int(category_id))
    
    # Get products
    products = query.order_by(Product.created_at.desc()).all()
    categories = Category.query.all()
    
    return render_template('index.html', 
                          products=products, 
                          categories=categories,
                          search_query=search_query,
                          category_id=category_id)

# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html', form=form)

# Route for signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    
    if form.validate_on_submit():
        # Check if email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered', 'danger')
            return render_template('signup.html', form=form)
            
        # Create new user
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html', form=form)

# Route for logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

# Route for user dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    form = UserProfileForm(obj=user)
    
    if request.method == 'POST' and form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.phone = form.phone.data
        user.address = form.address.data
        
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('dashboard'))
        
    # Get user's listings
    user_listings = Product.query.filter_by(seller_id=user.id).order_by(Product.created_at.desc()).all()
    
    return render_template('dashboard.html', 
                          user=user, 
                          form=form,
                          listings=user_listings)

# Route for viewing product details
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

# Route for adding a new product
@app.route('/product/add', methods=['GET', 'POST'])
@login_required
def add_product():
    form = ProductForm()
    form.category.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        # Handle image upload
        image_filename = 'placeholder.png'  # Default placeholder
        
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add timestamp to filename to avoid conflicts
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                image_filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        
        # Create new product
        new_product = Product(
            title=form.title.data,
            description=form.description.data,
            price=form.price.data,
            category_id=form.category.data,
            image=image_filename,
            seller_id=session['user_id']
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        flash('Product listed successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_product.html', form=form)

# Route for editing a product
@app.route('/product/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Check if current user is the seller
    if product.seller_id != session['user_id']:
        flash('You can only edit your own listings', 'danger')
        return redirect(url_for('dashboard'))
    
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

# Route for deleting a product
@app.route('/product/delete/<int:product_id>', methods=['POST'])
@login_required
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

# Route for adding a product to cart
@app.route('/cart/add/<int:product_id>', methods=['POST'])
@login_required
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

# Route for removing a product from cart
@app.route('/cart/remove/<int:item_id>', methods=['POST'])
@login_required
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

# Route for viewing cart
@app.route('/cart')
@login_required
def cart():
    cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
    
    # Calculate total price
    total = sum(item.product.price for item in cart_items)
    
    return render_template('cart.html', cart_items=cart_items, total=total)

# Route for checkout/purchase
@app.route('/checkout', methods=['POST'])
@login_required
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

# Route for viewing previous purchases
@app.route('/purchases')
@login_required
def purchases():
    user_purchases = Purchase.query.filter_by(user_id=session['user_id']).order_by(Purchase.purchase_date.desc()).all()
    return render_template('purchases.html', purchases=user_purchases)

# Error handlers


if __name__ == '__main__':
    
    init_db()
    app.run(debug=True)