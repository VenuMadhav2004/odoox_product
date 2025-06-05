from extensions import db  # Import the single shared instance
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    bio = db.Column(db.Text, nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    ROLES = [
        ('admin', 'Admin'),
        ('seller', 'Seller'),
        ('buyer', 'Buyer'),
        ('both', 'Buyer/Seller')
    ]
    
    role = db.Column(db.Enum(*[r[0] for r in ROLES], name='user_roles'), default='buyer')
    stripe_account_id = db.Column(db.String(100))  # For seller payments
    is_active = db.Column(db.Boolean, default=True)
    wishlist_items = db.relationship('WishlistItem', backref='user', lazy=True)

    
    # Relationships
    products = db.relationship('Product', backref='seller', lazy=True)
    cart_items = db.relationship('CartItem', backref='user', lazy=True)
    purchases = db.relationship('Purchase', backref='buyer', lazy=True)
    otp_records = db.relationship('OTPRecord', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_seller(self):
        return self.role == 'seller'
    
    def is_buyer(self):
        return self.role == 'buyer'
    
    def can_sell(self):
        return self.role in ['seller', 'both']
    
    def can_buy(self):
        return self.role in ['buyer', 'both']
    
    def can_moderate(self):
        return self.is_admin()
    def set_password(self, password):
        """Create hashed password."""
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        """Check hashed password."""
        return check_password_hash(self.password, password)
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class OTPRecord(db.Model):
    __tablename__ = 'otp_records'
    
    id = db.Column(db.Integer, primary_key=True)
    otp_code = db.Column(db.String(10), nullable=False)
    otp_type = db.Column(db.String(20), nullable=False)  # 'registration', 'login', 'password_reset'
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    # Foreign key
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def is_expired(self):
        return datetime.now() > self.expires_at
    
    def __repr__(self):
        return f'<OTPRecord {self.otp_code} for User {self.user_id}>'


class Category(db.Model):
    __tablename__ = 'categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    
    # Relationships
    products = db.relationship('Product', backref='category', lazy=True)
    
    def __repr__(self):
        return f'<Category {self.name}>'


class Product(db.Model):
    __tablename__ = 'products'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200), default='placeholder.png')
    is_sold = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    is_auction = db.Column(db.Boolean, default=False)
    

    # Foreign keys
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    
    # Relationships
    cart_items = db.relationship('CartItem', backref='product', lazy=True, cascade="all, delete-orphan")
    purchases = db.relationship('Purchase', backref='product', lazy=True)
    
    def __repr__(self):
        return f'<Product {self.title}>'


class CartItem(db.Model):
    __tablename__ = 'cart_items'
    
    id = db.Column(db.Integer, primary_key=True)
    added_at = db.Column(db.DateTime, default=datetime.now)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    
    def __repr__(self):
        return f'<CartItem {self.id}>'


class Purchase(db.Model):
    __tablename__ = 'purchases'
    
    id = db.Column(db.Integer, primary_key=True)
    price = db.Column(db.Float, nullable=False)  # Store price at time of purchase
    purchase_date = db.Column(db.DateTime, default=datetime.now)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    
    def __repr__(self):
        return f'<Purchase {self.id}>'
    
class Auction(db.Model):
    __tablename__ = 'auctions'
    
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False, unique=True)
    min_bid = db.Column(db.Float, nullable=False)
    reserve_price = db.Column(db.Float)
    start_time = db.Column(db.DateTime, default=datetime.now)
    end_time = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    #product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    
    
    # Relationships
    product = db.relationship('Product', backref='auction', uselist=False)
    bids = db.relationship('Bid', backref='auction', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Auction for Product {self.product_id}>'

class Bid(db.Model):
    __tablename__ = 'bids'
    
    id = db.Column(db.Integer, primary_key=True)
    auction_id = db.Column(db.Integer, db.ForeignKey('auctions.id'), nullable=False)  # was 'auction.id'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # was 'user.id'
    amount = db.Column(db.Float, nullable=False)
    bid_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    user = db.relationship('User', backref='user_bids') 
    
    def __repr__(self):
        return f'<Bid {self.amount} by User {self.user_id}>'
     

class Rating(db.Model):
    __tablename__ = 'ratings'
    
    id = db.Column(db.Integer, primary_key=True)
    rater_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ratee_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=True)
    purchase_id = db.Column(db.Integer, db.ForeignKey('purchases.id'), nullable=False)
    stars = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    is_approved = db.Column(db.Boolean, default=True)
    
    # Relationships - define backrefs only here
    rater = db.relationship('User', foreign_keys=[rater_id], 
                           backref=db.backref('given_ratings', lazy='dynamic'))
    ratee = db.relationship('User', foreign_keys=[ratee_id], 
                          backref=db.backref('received_ratings', lazy='dynamic'))
    product = db.relationship('Product', backref='product_ratings')
    purchase = db.relationship('Purchase', backref='purchase_rating')

    def __repr__(self):
        return f'<Rating {self.stars} stars by User {self.rater_id}>'
        #return f'<Rating {self.stars} stars by User {self.rater_id}>'

class Dispute(db.Model):
    __tablename__ = 'disputes'
    
    id = db.Column(db.Integer, primary_key=True)
    purchase_id = db.Column(db.Integer, db.ForeignKey('purchases.id'), nullable=False)
    complainant_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    accused_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='open')  # open, resolved, closed
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Admin actions, comments, evidence could be stored in separate tables or JSON
    
    complainant = db.relationship('User', foreign_keys=[complainant_id])
    accused = db.relationship('User', foreign_keys=[accused_id])
    purchase = db.relationship('Purchase', backref='disputes')

class SavedSearch(db.Model):
    __tablename__ = 'saved_searches'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    query = db.Column(db.String(200), nullable=False)
    filters = db.Column(db.JSON)  # store filters as JSON
    created_at = db.Column(db.DateTime, default=datetime.now)
    notify_via_email = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref='saved_searches')
class Conversation(db.Model):
    __tablename__ = 'conversations'
    
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])
    messages = db.relationship('Message', back_populates='conversation', cascade='all, delete-orphan')
    
    def get_other_user(self, current_user_id):
        return self.user2 if current_user_id == self.user1_id else self.user1

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    # Relationships
    conversation = db.relationship('Conversation', back_populates='messages')
    sender = db.relationship('User', foreign_keys=[sender_id])
    
    @property
    def is_recipient(self, user_id):
        return user_id != self.sender_id

class PriceAlert(db.Model):
    __tablename__ = 'price_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    target_price = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref='price_alerts')
    product = db.relationship('Product', backref='price_alerts')

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    notification_type = db.Column(db.String(50))  # e.g., 'bid', 'purchase', 'message'
    related_id = db.Column(db.Integer)  # ID of related entity
    
    user = db.relationship('User', backref='notifications')

class WishlistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Changed 'user.id' to 'users.id'
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    added_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    product = db.relationship('Product', backref='wishlist_items')
