import pytest
from app import app, db, User, Book
from datetime import datetime


@pytest.fixture
def client():
    """Create a test client for the app."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


@pytest.fixture
def auth_user(client):
    """Create a test user and return client with user logged in."""
    with app.app_context():
        user = User(username='testuser', email='test@example.com')
        user.set_password('testpassword123')
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    
    # Login the user
    response = client.post('/login', data={
        'email': 'test@example.com',
        'password': 'testpassword123'
    }, follow_redirects=True)
    
    with app.app_context():
        user = db.session.get(User, user_id)
    
    return client, user


class TestAuthentication:
    """Test user authentication routes."""
    
    def test_register_page_loads(self, client):
        """Test that registration page loads."""
        response = client.get('/register')
        assert response.status_code == 200
        assert b'Create Account' in response.data
    
    def test_register_new_user(self, client):
        """Test user registration with valid data."""
        response = client.post('/register', data={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'securepass123',
            'confirm_password': 'securepass123'
        }, follow_redirects=True)
        # Should redirect to login
        assert response.status_code == 200
        
        with app.app_context():
            user = User.query.filter_by(email='newuser@example.com').first()
            assert user is not None
            assert user.username == 'newuser'
    
    def test_register_duplicate_email(self, client):
        """Test registration fails with duplicate email."""
        with app.app_context():
            user = User(username='existing', email='existing@example.com')
            user.set_password('password')
            db.session.add(user)
            db.session.commit()
        
        response = client.post('/register', data={
            'username': 'newuser',
            'email': 'existing@example.com',
            'password': 'password',
            'confirm_password': 'password'
        })
        assert b'Email already registered' in response.data
    
    def test_register_duplicate_username(self, client):
        """Test registration fails with duplicate username."""
        with app.app_context():
            user = User(username='existing', email='existing@example.com')
            user.set_password('password')
            db.session.add(user)
            db.session.commit()
        
        response = client.post('/register', data={
            'username': 'existing',
            'email': 'different@example.com',
            'password': 'password',
            'confirm_password': 'password'
        })
        assert b'Username already exists' in response.data
    
    def test_login_page_loads(self, client):
        """Test that login page loads."""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'Log In' in response.data
    
    def test_login_successful(self, client):
        """Test successful login."""
        with app.app_context():
            user = User(username='testuser', email='test@example.com')
            user.set_password('password123')
            db.session.add(user)
            db.session.commit()
        
        response = client.post('/login', data={
            'email': 'test@example.com',
            'password': 'password123'
        }, follow_redirects=True)
        # Should redirect to index
        assert response.status_code == 200
        assert b'Reading Nook' in response.data
    
    def test_login_invalid_password(self, client):
        """Test login fails with wrong password."""
        with app.app_context():
            user = User(username='testuser', email='test@example.com')
            user.set_password('correctpassword')
            db.session.add(user)
            db.session.commit()
        
        response = client.post('/login', data={
            'email': 'test@example.com',
            'password': 'wrongpassword'
        })
        assert b'Invalid email or password' in response.data or response.status_code == 200
    
    def test_logout(self, auth_user):
        """Test user logout."""
        client, _ = auth_user
        response = client.get('/logout')
        assert response.status_code == 302


class TestBookRoutes:
    """Test book management routes."""
    
    def test_index_requires_login(self, client):
        """Test that index page requires login."""
        response = client.get('/')
        # Should redirect to login
        assert response.status_code == 302
    
    def test_index_page_loads(self, auth_user):
        """Test that home page loads for logged in user."""
        client, _ = auth_user
        response = client.get('/')
        assert response.status_code == 200
        assert b'Reading Nook' in response.data
    
    def test_add_book_page_loads(self, auth_user):
        """Test that add book page loads."""
        client, _ = auth_user
        response = client.get('/add')
        assert response.status_code == 200
        assert b'Add a New Book' in response.data
    
    def test_add_book_success(self, auth_user):
        """Test adding a new book."""
        client, user = auth_user
        response = client.post('/add', data={
            'title': 'Test Book',
            'author': 'Test Author',
            'isbn': '978-0-123456-78-9',
            'genre': 'Fiction',
            'format': 'physical',
            'date_read': '2025-12-30',
            'rating': '5',
            'notes': 'A great book!'
        }, follow_redirects=True)
        assert response.status_code == 200
        
        with app.app_context():
            book = Book.query.filter_by(title='Test Book').first()
            assert book is not None
            assert book.author == 'Test Author'
            assert book.isbn == '978-0-123456-78-9'
            assert book.genre == 'Fiction'
            assert book.format == 'physical'
            assert book.rating == 5
    
    def test_add_book_minimal(self, auth_user):
        """Test adding a book with only required fields."""
        client, user = auth_user
        response = client.post('/add', data={
            'title': 'Minimal Book',
            'author': 'Some Author',
            'date_read': '2025-12-30'
        }, follow_redirects=True)
        assert response.status_code == 200
        
        with app.app_context():
            book = Book.query.filter_by(title='Minimal Book').first()
            assert book is not None
            assert book.format == 'physical'  # default
    
    def test_edit_book_page_loads(self, auth_user):
        """Test that edit book page loads."""
        client, user = auth_user
        
        with app.app_context():
            book = Book(title='Test', author='Author', user_id=user.id)
            db.session.add(book)
            db.session.commit()
            book_id = book.id
        
        response = client.get(f'/edit/{book_id}')
        assert response.status_code == 200
        assert b'Edit Book' in response.data
    
    def test_edit_book_success(self, auth_user):
        """Test editing a book."""
        client, user = auth_user
        
        with app.app_context():
            book = Book(title='Original', author='Author', user_id=user.id)
            db.session.add(book)
            db.session.commit()
            book_id = book.id
        
        response = client.post(f'/edit/{book_id}', data={
            'title': 'Updated Title',
            'author': 'Updated Author',
            'genre': 'Mystery',
            'format': 'ebook',
            'date_read': '2025-12-30',
            'rating': '4'
        }, follow_redirects=True)
        assert response.status_code == 200
        
        with app.app_context():
            book = db.get_or_404(Book, book_id)
            assert book.title == 'Updated Title'
            assert book.author == 'Updated Author'
            assert book.genre == 'Mystery'
            assert book.format == 'ebook'
            assert book.rating == 4
    
    def test_delete_book(self, auth_user):
        """Test deleting a book."""
        client, user = auth_user
        
        with app.app_context():
            book = Book(title='To Delete', author='Author', user_id=user.id)
            db.session.add(book)
            db.session.commit()
            book_id = book.id
        
        response = client.get(f'/delete/{book_id}', follow_redirects=True)
        assert response.status_code == 200
        
        with app.app_context():
            book = db.session.get(Book, book_id)
            assert book is None
    
    def test_user_cannot_edit_other_users_book(self, client):
        """Test that a user cannot edit another user's book."""
        with app.app_context():
            user1 = User(username='user1', email='user1@example.com')
            user1.set_password('password')
            user2 = User(username='user2', email='user2@example.com')
            user2.set_password('password')
            db.session.add(user1)
            db.session.add(user2)
            db.session.commit()
            
            book = Book(title='User1 Book', author='Author', user_id=user1.id)
            db.session.add(book)
            db.session.commit()
            book_id = book.id
        
        # Login as user2
        client.post('/login', data={
            'email': 'user2@example.com',
            'password': 'password'
        }, follow_redirects=True)
        
        # Try to edit user1's book
        response = client.get(f'/edit/{book_id}')
        assert response.status_code == 302  # Redirected (permission denied)


class TestSearch:
    """Test search functionality."""
    
    def test_search_by_title(self, auth_user):
        """Test searching for books by title."""
        client, user = auth_user
        
        with app.app_context():
            book1 = Book(title='The Great Gatsby', author='F. Scott Fitzgerald', user_id=user.id)
            book2 = Book(title='1984', author='George Orwell', user_id=user.id)
            db.session.add_all([book1, book2])
            db.session.commit()
        
        response = client.get('/?search=Gatsby')
        assert response.status_code == 200
        assert b'The Great Gatsby' in response.data
    
    def test_search_by_author(self, auth_user):
        """Test searching for books by author."""
        client, user = auth_user
        
        with app.app_context():
            book1 = Book(title='The Great Gatsby', author='F. Scott Fitzgerald', user_id=user.id)
            book2 = Book(title='1984', author='George Orwell', user_id=user.id)
            db.session.add_all([book1, book2])
            db.session.commit()
        
        response = client.get('/?search=Orwell')
        assert response.status_code == 200
        assert b'1984' in response.data
        assert b'Great Gatsby' not in response.data
    
    def test_search_by_genre(self, auth_user):
        """Test searching for books by genre."""
        client, user = auth_user
        
        with app.app_context():
            book1 = Book(title='Book 1', author='Author 1', genre='Mystery', user_id=user.id)
            book2 = Book(title='Book 2', author='Author 2', genre='Fiction', user_id=user.id)
            db.session.add_all([book1, book2])
            db.session.commit()
        
        response = client.get('/?search=Mystery')
        assert response.status_code == 200
        assert b'Book 1' in response.data
        assert b'Book 2' not in response.data
    
    def test_search_by_isbn(self, auth_user):
        """Test searching for books by ISBN."""
        client, user = auth_user
        
        with app.app_context():
            book1 = Book(title='Book 1', author='Author 1', isbn='978-0-111111-11-1', user_id=user.id)
            book2 = Book(title='Book 2', author='Author 2', isbn='978-0-222222-22-2', user_id=user.id)
            db.session.add_all([book1, book2])
            db.session.commit()
        
        response = client.get('/?search=978-0-111111-11-1')
        assert response.status_code == 200
        assert b'Book 1' in response.data
        assert b'Book 2' not in response.data
    
    def test_search_case_insensitive(self, auth_user):
        """Test that search is case-insensitive."""
        client, user = auth_user
        
        with app.app_context():
            book = Book(title='The Great Gatsby', author='Author', user_id=user.id)
            db.session.add(book)
            db.session.commit()
        
        response = client.get('/?search=GATSBY')
        assert response.status_code == 200
        assert b'The Great Gatsby' in response.data
    
    def test_search_no_results(self, auth_user):
        """Test search with no results."""
        client, user = auth_user
        
        with app.app_context():
            book = Book(title='The Great Gatsby', author='Author', user_id=user.id)
            db.session.add(book)
            db.session.commit()
        
        response = client.get('/?search=nonexistent')
        assert response.status_code == 200
        assert b'No books found' in response.data


class TestPasswordSecurity:
    """Test password hashing and security."""
    
    def test_password_is_hashed(self):
        """Test that passwords are hashed, not stored in plain text."""
        user = User(username='testuser', email='test@example.com')
        user.set_password('mypassword123')
        
        # Password should not equal the hash
        assert user.password_hash != 'mypassword123'
        # Hash should not be empty
        assert user.password_hash
    
    def test_password_check(self):
        """Test password verification."""
        user = User(username='testuser', email='test@example.com')
        user.set_password('correctpassword')
        
        assert user.check_password('correctpassword') is True
        assert user.check_password('wrongpassword') is False
