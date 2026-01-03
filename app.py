from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, Regexp, NumberRange, Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from datetime import datetime, timezone
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os
import re
import logging
import secrets
from dotenv import load_dotenv

load_dotenv()

# Create Flask app
app = Flask(__name__)

# Logging configuration function
def configure_logging(flask_app):
    """Configure Flask's built-in logger for security events.
    
    This function should be called after the app is fully configured
    to ensure the TESTING and DEBUG flags are properly respected.
    
    Args:
        flask_app: The Flask application instance
    """
    # Set logging level based on current configuration
    if flask_app.config.get('TESTING') or flask_app.config.get('DEBUG'):
        flask_app.logger.setLevel(logging.DEBUG)
    else:
        flask_app.logger.setLevel(logging.WARNING)
    
    # Add console handler if not already present
    if not flask_app.logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        flask_app.logger.addHandler(console_handler)

# Handle both SQLite (dev) and PostgreSQL (production)
db_uri = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///readingnook.db')
# Convert old postgresql:// to postgresql+psycopg:// for psycopg3
if db_uri.startswith('postgresql://'):
    db_uri = db_uri.replace('postgresql://', 'postgresql+psycopg://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-production')

# Production Security Settings
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
app.config['TESTING'] = os.getenv('FLASK_ENV', '').lower() == 'testing'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 24 * 60 * 60  # 24 hours

# Configure logging after all configuration is set
configure_logging(app)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Argon2 password hasher configuration
# Parameters explicitly set for consistency and future tunability
# 
# Security rationale for a personal use application:
# - time_cost=3: Number of iterations. 3 is the minimum and still provides
#   good security (~100-200ms per hash). For personal use, this is acceptable.
#   For high-volume production, consider increasing to 4-5.
#
# - memory_cost=65536: Memory usage in KB (65 MB). High memory cost makes GPU
#   attacks impractical. 65 MB per hash is substantial and sufficient for this
#   application's threat model.
#
# - parallelism=4: Number of parallel threads. Matches typical multi-core CPUs.
#   Increases memory pressure during hashing, improving attack resistance.
#
# These parameters can be tuned as security requirements evolve:
# - Increase time_cost/memory_cost if GPUs become more common attackers
# - Decrease time_cost if performance becomes a bottleneck (e.g., high user load)
# - Adjust parallelism based on server CPU cores
#
# Reference: OWASP Password Storage Cheat Sheet recommends these parameter ranges
password_hasher = PasswordHasher(
    time_cost=3,          # iterations
    memory_cost=65536,    # 65 MB
    parallelism=4,        # threads
    hash_len=32,          # hash length in bytes
    salt_len=16,          # salt length in bytes
)

# Rate limiter for security (disabled in testing)
def limiter_enabled():
    """Check if rate limiting should be enabled."""
    return not (app.config.get('TESTING') or app.config.get('RATELIMIT_ENABLED') == False)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    enabled=limiter_enabled
)

# Token serializer for password reset tokens
# Uses app.config['SECRET_KEY'] for signing
# Tokens expire after 15 minutes (900 seconds)
serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY', 'dev-key-change-in-production'))
TOKEN_EXPIRATION_SECONDS = 15 * 60  # 15 minutes

def generate_reset_token(user_id, code_id):
    """Generate a cryptographically signed, time-limited password reset token.
    
    Args:
        user_id: User ID to include in token
        code_id: Recovery code ID to include in token
    
    Returns:
        Signed token string that expires in 15 minutes
        
    Security properties:
        - Token is signed with SECRET_KEY (cannot be forged)
        - Token is URL-safe
        - Token expires after 15 minutes
        - Token contains no sensitive data in URL (hashed IDs in token)
    """
    return serializer.dumps(
        {'user_id': user_id, 'code_id': code_id},
        salt='password-reset'
    )

def verify_reset_token(token):
    """Verify and extract data from a password reset token.
    
    Args:
        token: Token string to verify
    
    Returns:
        Dict with 'user_id' and 'code_id' if valid and not expired
        None if token is invalid or expired
    """
    try:
        data = serializer.loads(
            token,
            salt='password-reset',
            max_age=TOKEN_EXPIRATION_SECONDS
        )
        return data
    except (BadSignature, SignatureExpired):
        return None


# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    books = db.relationship('Book', backref='user', lazy=True, cascade='all, delete-orphan')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def set_password(self, password):
        """Hash password using Argon2 (memory-hard, GPU-resistant)"""
        self.password_hash = password_hasher.hash(password)
    
    def check_password(self, password):
        """Verify password against Argon2 hash
        
        Returns:
            True if password matches, False otherwise
            
        Handles:
            - VerifyMismatchError: Password doesn't match (expected during failed login)
            - InvalidHashError: Hash is malformed or from different algorithm (logs warning)
        """
        try:
            password_hasher.verify(self.password_hash, password)
            return True
        except VerifyMismatchError:
            # Expected: password doesn't match
            return False
        except InvalidHashError as e:
            # Unexpected: hash is corrupted or from different algorithm
            # Log generic message without exception details to avoid exposing
            # sensitive information about hash format or validation process
            app.logger.warning(f'Invalid password hash format for user {self.username}')
            return False
    
    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class RecoveryCode(db.Model):
    """Recovery codes for account password recovery (no email required)
    
    Each recovery code is single-use and hashed for security.
    Users can use any code during password recovery.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code_hash = db.Column(db.String(255), nullable=False)  # Argon2 hash
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    used_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<RecoveryCode user_id={self.user_id}>'

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(200), nullable=False)
    isbn = db.Column(db.String(20))
    genre = db.Column(db.String(100))
    format = db.Column(db.String(20), default='physical')  # 'physical' or 'ebook'
    date_read = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    rating = db.Column(db.Integer)  # 1-5 stars
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f'<Book {self.title}>'

# Custom Validators
class ISBNValidator:
    """Validates ISBN-10 or ISBN-13 format (with or without hyphens)"""
    def __init__(self, message='Invalid ISBN format. Use ISBN-10 or ISBN-13.'):
        self.message = message
    
    def __call__(self, form, field):
        if not field.data:
            return  # ISBN is optional
        
        # Remove hyphens for validation
        isbn_clean = field.data.replace('-', '').replace(' ', '')
        
        # Check if it's 10 or 13 digits
        if not (len(isbn_clean) == 10 or len(isbn_clean) == 13):
            raise ValidationError(self.message)
        
        # Check all characters are digits
        if not isbn_clean.isdigit():
            raise ValidationError(self.message)

def password_strength(form, field):
    """Validate password has minimum length and complexity"""
    password = field.data
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not re.search(r'[0-9]', password):
        raise ValidationError('Password must contain at least one number.')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError('Password must contain at least one special character (!@#$%^&*(),.?":{}|<>).')

def generate_recovery_codes(user_id, count=8):
    """Generate recovery codes for a user.
    
    Uses base32 encoding for better entropy and readability.
    Each code: 12 alphanumeric characters (A-Z, 2-7) formatted as XXX-XXX-XXX
    Entropy: 32^12 ≈ 1.2 * 10^18 combinations (exceeds NIST 2^50 minimum)
    
    Args:
        user_id: User ID to generate codes for
        count: Number of codes to generate (default 8)
    
    Returns:
        List of plain-text recovery codes for display to user
    """
    import base64
    plain_codes = []
    
    for _ in range(count):
        # Generate 9 bytes of random data = 12 base32 characters (32^12 entropy)
        # This exceeds NIST recommendation of 2^50 entropy for recovery codes
        random_bytes = secrets.token_bytes(9)
        # Use base32 (A-Z, 2-7) for better readability than base64
        base32_code = base64.b32encode(random_bytes).decode('utf-8').rstrip('=')
        # Format: XXX-XXX-XXX (12 chars in 3 groups of 4)
        plain_code = f"{base32_code[:4]}-{base32_code[4:8]}-{base32_code[8:12]}"
        
        # Hash the code for secure storage
        code_hash = password_hasher.hash(plain_code)
        
        recovery_code = RecoveryCode(user_id=user_id, code_hash=code_hash)
        db.session.add(recovery_code)
        plain_codes.append(plain_code)
    
    db.session.commit()
    return plain_codes

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=80, message='Username must be 3-80 characters.')
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        password_strength
    ])
    confirm_password = PasswordField('Confirm Password', 
                                    validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class BookForm(FlaskForm):
    title = StringField('Title', validators=[
        DataRequired(),
        Length(min=1, max=255, message='Title must be 1-255 characters.')
    ])
    author = StringField('Author', validators=[
        DataRequired(),
        Length(min=1, max=200, message='Author name must be 1-200 characters.')
    ])
    isbn = StringField('ISBN', validators=[ISBNValidator()])
    genre = StringField('Genre', validators=[
        Length(max=100, message='Genre must be 100 characters or less.')
    ])
    format = SelectField('Format', validators=[DataRequired()], choices=[
        ('physical', 'Physical Book'),
        ('ebook', 'E-book'),
        ('audiobook', 'Audiobook')
    ])
    rating = IntegerField('Rating', validators=[
        Optional(),
        NumberRange(min=1, max=5, message='Rating must be between 1 and 5.')
    ])
    notes = StringField('Notes', validators=[
        Length(max=5000, message='Notes must be 5000 characters or less.')
    ])
    date_read = StringField('Date Read')
    submit = SubmitField('Save Book')

class RecoverAccountForm(FlaskForm):
    """Form to initiate account recovery using email and recovery code"""
    email = StringField('Email', validators=[DataRequired(), Email()])
    recovery_code = StringField('Recovery Code', validators=[
        DataRequired(),
        Length(min=9, max=9, message='Recovery code must be in format: XXXX-XXXX')
    ])
    submit = SubmitField('Verify Code')

class ResetPasswordForm(FlaskForm):
    """Form to reset password after recovery code verification"""
    password = PasswordField('New Password', validators=[
        DataRequired(),
        password_strength
    ])
    confirm_password = PasswordField('Confirm Password', 
                                    validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        # Generate recovery codes for new user
        recovery_codes = generate_recovery_codes(user.id, count=8)
        
        # Store codes in session temporarily (will be displayed once then cleared)
        session['recovery_codes'] = recovery_codes
        session['recovery_user_id'] = user.id
        
        app.logger.info(f'New user account created: {user.username}')
        flash('Account created successfully! Save your recovery codes and then log in.', 'success')
        
        # Redirect to recovery codes display page
        return redirect(url_for('show_recovery_codes'))
    
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and user.check_password(form.password.data):
            login_user(user)
            app.logger.info(f'User logged in successfully: {user.username}')
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('index'))
        else:
            # Log failed attempt with email (no password) for security monitoring
            app.logger.warning(f'Failed login attempt for email: {form.email.data}')
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    app.logger.info(f'User logged out: {username}')
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/recovery-codes')
def show_recovery_codes():
    """Display recovery codes to user immediately after account creation.
    
    Security: This page is only accessible immediately after registration
    and the codes are stored in the session (temporary). User should save these codes now.
    Codes are cleared from session once displayed.
    """
    # Check if codes are in session (should only be there right after registration)
    if 'recovery_codes' not in session:
        flash('Recovery codes not found. Please log in.', 'info')
        return redirect(url_for('login'))
    
    codes = session.pop('recovery_codes')  # Remove from session after reading
    user_id = session.pop('recovery_user_id', None)
    
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    
    return render_template('recovery_codes.html', user=user, codes=codes)

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per 15 minutes")  # Prevent brute force attacks on recovery codes
def forgot_password():
    """Initiate password recovery using email and recovery code
    
    Rate limited: 5 attempts per 15 minutes per IP address
    This prevents brute force attacks on recovery codes even with high entropy.
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RecoverAccountForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if not user:
            # Don't reveal if email exists (security best practice)
            app.logger.warning(f'Recovery attempt for non-existent email: {form.email.data}')
            flash('If that email exists, a password reset link will be sent.', 'info')
            return redirect(url_for('login'))
        
        # Get all unused recovery codes for this user
        recovery_codes = RecoveryCode.query.filter_by(
            user_id=user.id,
            used=False
        ).all()
        
        if not recovery_codes:
            app.logger.warning(f'Recovery attempt with no available codes for user: {user.username}')
            flash('No available recovery codes. Please contact support.', 'error')
            return redirect(url_for('login'))
        
        # Check if provided code matches any unused code
        matching_code = None
        for recovery_code in recovery_codes:
            try:
                password_hasher.verify(recovery_code.code_hash, form.recovery_code.data)
                matching_code = recovery_code
                break
            except (VerifyMismatchError, InvalidHashError):
                continue
        
        if not matching_code:
            app.logger.warning(f'Invalid recovery code attempt for user: {user.username}')
            flash('Invalid recovery code.', 'error')
            return redirect(url_for('forgot_password'))
        
        # Generate time-limited, cryptographically signed token
        # Token contains user_id and code_id but is unguessable and expires in 15 minutes
        reset_token = generate_reset_token(user.id, matching_code.id)
        app.logger.info(f'User verified recovery code: {user.username}')
        
        # Redirect to reset password with token parameter (no exposed IDs in URL)
        return redirect(url_for('reset_password', token=reset_token))
    
    return render_template('forgot_password.html', form=form)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Reset password after recovery code verification
    
    Uses a time-limited, cryptographically signed token instead of exposing
    user_id and code_id in the URL. This prevents:
    - ID enumeration attacks
    - URL interception/logging issues
    - Indefinite password reset URLs
    """
    # Token can come from query string (GET) or form data (POST)
    token = request.args.get('token') or request.form.get('token')
    
    if not token:
        flash('Invalid or missing reset token.', 'error')
        return redirect(url_for('login'))
    
    # Verify token and extract user_id and code_id
    # Token is only valid for 15 minutes
    token_data = verify_reset_token(token)
    if not token_data:
        app.logger.warning(f'Invalid or expired reset token attempted')
        flash('Password reset link is invalid or has expired. Please try again.', 'error')
        return redirect(url_for('forgot_password'))
    
    user_id = token_data.get('user_id')
    code_id = token_data.get('code_id')
    
    user = db.session.get(User, user_id)
    recovery_code = db.session.get(RecoveryCode, code_id)
    if not user or not recovery_code:
        flash('Invalid reset link.', 'error')
        return redirect(url_for('login'))
    
    if recovery_code.user_id != user.id or recovery_code.used:
        flash('This recovery code has already been used.', 'error')
        return redirect(url_for('login'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        recovery_code.used = True
        recovery_code.used_at = datetime.now(timezone.utc)
        db.session.commit()
        
        app.logger.info(f'Password reset via recovery code: {user.username}')
        flash('Password reset successfully! Please log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    # Pass token as hidden form field instead of URL parameters
    return render_template('reset_password.html', form=form, user=user, token=token)

@app.route('/')
@login_required
def index():
    search_query = request.args.get('search', '').strip()
    
    if search_query:
        # Search across title, author, ISBN, and genre
        books = Book.query.filter_by(user_id=current_user.id).filter(
            db.or_(
                Book.title.ilike(f'%{search_query}%'),
                Book.author.ilike(f'%{search_query}%'),
                Book.isbn.ilike(f'%{search_query}%'),
                Book.genre.ilike(f'%{search_query}%')
            )
        ).order_by(Book.date_read.desc()).all()
    else:
        books = Book.query.filter_by(user_id=current_user.id).order_by(Book.date_read.desc()).all()
    
    return render_template('index.html', books=books, search_query=search_query)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_book():
    form = BookForm()
    if form.validate_on_submit():
        try:
            # Parse date_read if provided
            date_read = None
            if form.date_read.data:
                try:
                    date_read = datetime.strptime(form.date_read.data, '%Y-%m-%d')
                    date_read = date_read.replace(tzinfo=timezone.utc)
                except ValueError:
                    date_read = None
            
            book = Book(
                title=form.title.data,
                author=form.author.data,
                isbn=form.isbn.data or None,
                genre=form.genre.data or None,
                format=form.format.data,
                rating=form.rating.data or None,
                notes=form.notes.data or None,
                date_read=date_read,
                user_id=current_user.id
            )
            db.session.add(book)
            db.session.commit()
            flash(f'Book "{book.title}" added successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding book: {str(e)}', 'error')
    
    return render_template('add_book.html', form=form)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_book(id):
    book = db.get_or_404(Book, id)
    
    # Check if the book belongs to the current user
    if book.user_id != current_user.id:
        flash('You do not have permission to edit this book.', 'error')
        return redirect(url_for('index'))
    
    form = BookForm()
    if form.validate_on_submit():
        try:
            # Parse date_read if provided
            date_read = None
            if form.date_read.data:
                try:
                    date_read = datetime.strptime(form.date_read.data, '%Y-%m-%d')
                    date_read = date_read.replace(tzinfo=timezone.utc)
                except ValueError:
                    date_read = book.date_read  # Keep original if parsing fails
            
            book.title = form.title.data
            book.author = form.author.data
            book.isbn = form.isbn.data or None
            book.genre = form.genre.data or None
            book.format = form.format.data
            book.rating = form.rating.data or None
            book.notes = form.notes.data or None
            if date_read:
                book.date_read = date_read
            db.session.commit()
            flash(f'Book "{book.title}" updated successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating book: {str(e)}', 'error')
    elif request.method == 'GET':
        # Pre-populate form with book data
        form.title.data = book.title
        form.author.data = book.author
        form.isbn.data = book.isbn
        form.genre.data = book.genre
        form.format.data = book.format
        form.rating.data = book.rating
        form.notes.data = book.notes
        if book.date_read:
            form.date_read.data = book.date_read.strftime('%Y-%m-%d')
    
    return render_template('edit_book.html', form=form, book=book)

@app.route('/delete/<int:id>')
@login_required
def delete_book(id):
    book = db.get_or_404(Book, id)
    
    # Check if the book belongs to the current user
    if book.user_id != current_user.id:
        flash('You do not have permission to delete this book.', 'error')
        return redirect(url_for('index'))
    try:
        db.session.delete(book)
        db.session.commit()
        flash(f'Book "{book.title}" deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting book: {str(e)}', 'error')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Development only - use Gunicorn in production
    app.run(debug=app.config['DEBUG'])
