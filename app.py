from flask import Flask, render_template, request, redirect, url_for, flash
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
import os
import re
import logging
from dotenv import load_dotenv

load_dotenv()

# Create Flask app
app = Flask(__name__)

# Configure logging for security-related events
# Only configure if not already configured (to avoid duplicate handlers)
if not logging.root.handlers:
    logging.basicConfig(
        level=logging.WARNING,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),  # Output to console/stderr
        ]
    )

logger = logging.getLogger(__name__)

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

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Argon2 password hasher
password_hasher = PasswordHasher()

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
            logger.warning(f'Invalid password hash for user {self.username}: {str(e)}')
            return False
    
    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
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
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
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
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))
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
