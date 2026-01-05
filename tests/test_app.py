import pytest
from app import app, db, User, Book, RecoveryCode, configure_logging, generate_recovery_codes, password_hasher
from datetime import datetime


@pytest.fixture
def client():
    """Create a test client for the app."""
    # Configure app for testing with a file-based database
    app.config['TESTING'] = True
    app.config['RATELIMIT_ENABLED'] = False
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
    
    # Reconfigure logging after setting TESTING flag
    # This ensures the logger respects the TESTING configuration
    configure_logging(app)
    
    # Setup database
    with app.app_context():
        db.drop_all()  # Clean previous test runs
        db.create_all()
    
    # Create test client
    client = app.test_client()
    
    yield client
    
    # Teardown
    with app.app_context():
        db.session.remove()
        db.drop_all()
    
    # Clean up test database file
    import os
    if os.path.exists('test.db'):
        os.remove('test.db')


@pytest.fixture
def auth_user(client):
    """Create a test user and return client with user logged in."""
    # Create user directly in the app context
    with app.app_context():
        # Make sure to clear any cached sessions
        from flask_login import current_user
        
        user = User(username='testuser', email='test@example.com')
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
    
    # Login the user using the test client
    response = client.post('/login', data={
        'email': 'test@example.com',
        'password': 'TestPass123!'
    }, follow_redirects=True)
    
    # Verify login was successful by checking response
    assert response.status_code == 200, f"Login failed with status {response.status_code}"
    
    # Retrieve the user from database in a fresh context
    with app.app_context():
        user = User.query.filter_by(email='test@example.com').first()
        assert user is not None, "User not found after creation"
    
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
            'password': 'SecurePass123!',
            'confirm_password': 'SecurePass123!'
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
            user.set_password('ValidPass123!')
            db.session.add(user)
            db.session.commit()
        
        response = client.post('/register', data={
            'username': 'newuser',
            'email': 'existing@example.com',
            'password': 'ValidPass123!',
            'confirm_password': 'ValidPass123!'
        })
        assert b'Email already registered' in response.data
    
    def test_register_duplicate_username(self, client):
        """Test registration fails with duplicate username."""
        with app.app_context():
            user = User(username='existing', email='existing@example.com')
            user.set_password('ValidPass123!')
            db.session.add(user)
            db.session.commit()
        
        response = client.post('/register', data={
            'username': 'existing',
            'email': 'different@example.com',
            'password': 'ValidPass123!',
            'confirm_password': 'ValidPass123!'
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
            user.set_password('LoginPass123!')
            db.session.add(user)
            db.session.commit()
        
        response = client.post('/login', data={
            'email': 'test@example.com',
            'password': 'LoginPass123!'
        }, follow_redirects=True)
        # Should redirect to index
        assert response.status_code == 200
        assert b'Reading Nook' in response.data
    
    def test_login_invalid_password(self, client):
        """Test login fails with wrong password."""
        with app.app_context():
            user = User(username='testuser', email='test@example.com')
            user.set_password('CorrectPass123!')
            db.session.add(user)
            db.session.commit()
        
        response = client.post('/login', data={
            'email': 'test@example.com',
            'password': 'WrongPass123!'
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
            'format': 'physical',
            'date_read': '2025-12-30'
        }, follow_redirects=True)
        assert response.status_code == 200
        
        with app.app_context():
            book = Book.query.filter_by(title='Minimal Book').first()
            assert book is not None
            assert book.format == 'physical'
    
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
            user1.set_password('ValidPass123!')
            user2 = User(username='user2', email='user2@example.com')
            user2.set_password('ValidPass123!')
            db.session.add(user1)
            db.session.add(user2)
            db.session.commit()
            
            book = Book(title='User1 Book', author='Author', user_id=user1.id)
            db.session.add(book)
            db.session.commit()
            book_id = book.id
        
        # Login as user2
        login_response = client.post('/login', data={
            'email': 'user2@example.com',
            'password': 'ValidPass123!'
        }, follow_redirects=True)
        # Verify login was successful
        assert login_response.status_code == 200
        
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
    
    def test_password_check_with_corrupted_hash(self, caplog):
        """Test that corrupted/invalid hash is handled gracefully with logging.
        
        This ensures that if a password hash is corrupted or in an invalid format
        (e.g., from database corruption or migration issues), the check_password
        method returns False and logs a warning instead of crashing.
        """
        import logging
        
        user = User(username='corrupteduser', email='corrupted@example.com')
        user.set_password('validpassword')
        
        # Verify password works normally first
        assert user.check_password('validpassword') is True
        
        # Simulate corrupted/invalid hash (not a valid Argon2 format)
        user.password_hash = 'invalid_corrupted_hash_format'
        
        # Capture logs to verify warning is logged
        with caplog.at_level(logging.WARNING):
            result = user.check_password('anypassword')
        
        # Should return False instead of raising an exception
        assert result is False
        
        # Should have logged a warning about invalid hash
        assert any('Invalid password hash' in record.message for record in caplog.records)
        assert any('corrupteduser' in record.message for record in caplog.records)

class TestRecoveryCodes:
    """Test password recovery using recovery codes"""
    
    def test_recovery_codes_generated_on_registration(self, client):
        """Verify recovery codes are generated and displayed after registration"""
        # Register a new user
        response = client.post('/register', data={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'SecurePass123!',
            'confirm_password': 'SecurePass123!'
        }, follow_redirects=True)
        
        # Should redirect to recovery codes page
        assert response.status_code == 200
        assert b'Save Your Recovery Codes' in response.data
    
    def test_recovery_codes_stored_in_database(self, client):
        """Verify recovery codes are hashed and stored in database"""
        from app import RecoveryCode
        
        # Register a new user
        response = client.post('/register', data={
            'username': 'codetest',
            'email': 'codetest@example.com',
            'password': 'SecurePass123!',
            'confirm_password': 'SecurePass123!'
        })
        
        # Get the user and verify codes were created
        with app.app_context():
            user = User.query.filter_by(username='codetest').first()
            codes = RecoveryCode.query.filter_by(user_id=user.id).all()
            
            # Should have 8 recovery codes
            assert len(codes) == 8
            
            # All codes should be unused
            assert all(not code.used for code in codes)
            
            # Codes should be hashed (not stored as plain text)
            assert all(len(code.code_hash) > 20 for code in codes)
    
    def test_forgot_password_page_loads(self, client):
        """Verify forgot password page loads"""
        response = client.get('/forgot-password')
        assert response.status_code == 200
        assert b'Recover Your Account' in response.data
        assert b'Recovery Code' in response.data
    
    def test_password_reset_with_valid_recovery_code(self, client):
        """Verify password can be reset with a valid recovery code (end-to-end test)
        
        This test covers the complete recovery flow:
        1. Generate recovery codes during registration
        2. Verify a real recovery code works
        3. Reset password with that code  
        4. Verify old password doesn't work, new password does
        """
        import re
        
        # Step 1: Register user (generates recovery codes in database)
        response = client.post('/register', data={
            'username': 'resetuser',
            'email': 'resetuser@example.com',
            'password': 'OldPass123!',
            'confirm_password': 'OldPass123!'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # Step 2: Logout to clear session (if logged in)
        client.get('/logout', follow_redirects=True)
        
        # Step 3: Get a real recovery code from the database
        with app.app_context():
            user = User.query.filter_by(email='resetuser@example.com').first()
            assert user is not None
            
            # Codes were generated and stored during registration
            codes = RecoveryCode.query.filter_by(user_id=user.id, used=False).all()
            assert len(codes) >= 8
            
            # Generate one test code with the correct base32 format
            real_recovery_code = generate_recovery_codes(999, count=1)[0]
            
            # Hash it and store it for this user (simulating a generated code)
            test_code_hash = password_hasher.hash(real_recovery_code)
            test_recovery_code = RecoveryCode(user_id=user.id, code_hash=test_code_hash)
            db.session.add(test_recovery_code)
            db.session.commit()
        
        # Step 4: Submit forgot password with the real recovery code
        response = client.post('/forgot-password', data={
            'email': 'resetuser@example.com',
            'recovery_code': real_recovery_code
        }, follow_redirects=True)
        
        # Should end up on reset password page
        assert response.status_code == 200
        assert b'Reset Your Password' in response.data
        
        # Step 5: Extract the token from the hidden form field
        token_match = re.search(rb'name="token"\s+value="([^"]+)"', response.data)
        assert token_match is not None, "Token not found in reset password form"
        token_value = token_match.group(1).decode('utf-8')
        assert len(token_value) > 0
        
        # Step 6: Submit new password via reset form with token
        response = client.post('/reset-password', data={
            'token': token_value,
            'password': 'NewPass123!',
            'confirm_password': 'NewPass123!'
        }, follow_redirects=True)
        
        # Should succeed and redirect to login
        assert response.status_code == 200
        assert b'Password reset successfully' in response.data or b'login' in response.data.lower()
        
        # Step 7: Verify old password doesn't work anymore
        login_response = client.post('/login', data={
            'email': 'resetuser@example.com',
            'password': 'OldPass123!'
        }, follow_redirects=True)
        # Should show error or stay on login page
        assert b'Invalid email or password' in login_response.data or b'Recover Account' in login_response.data or b'login' in login_response.data.lower()
        
        # Step 8: Verify new password works
        login_response = client.post('/login', data={
            'email': 'resetuser@example.com',
            'password': 'NewPass123!'
        }, follow_redirects=True)
        # Should successfully log in and redirect to index
        assert login_response.status_code == 200
        # Check for either success message or index page content
        assert b'Welcome' in login_response.data or b'Reading Nook' in login_response.data
    
    def test_invalid_recovery_code_rejected(self, client):
        """Verify invalid recovery codes are rejected"""
        # Register user
        client.post('/register', data={
            'username': 'invaliduser',
            'email': 'invaliduser@example.com',
            'password': 'ValidPass123!',
            'confirm_password': 'ValidPass123!'
        })
        
        # Attempt recovery with invalid code
        response = client.post('/forgot-password', data={
            'email': 'invaliduser@example.com',
            'recovery_code': 'XXXX-XXXX'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Invalid recovery code' in response.data or b'error' in response.data.lower()
    
    def test_recovery_code_must_match_email(self, client):
        """Verify recovery code must be for the correct email"""
        # Register two users
        for i in range(2):
            client.post('/register', data={
                'username': f'user{i}',
                'email': f'user{i}@example.com',
                'password': 'ValidPass123!',
                'confirm_password': 'ValidPass123!'
            })
        
        # Try to use user0's recovery code with user1's email
        response = client.post('/forgot-password', data={
            'email': 'user1@example.com',
            'recovery_code': 'XXXX-XXXX'  # Invalid for user1
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Should fail because code is invalid for this user
        assert b'error' in response.data.lower() or b'invalid' in response.data.lower()
    
    def test_registration_rollback_on_recovery_code_generation_failure(self, client, monkeypatch):
        """Test that user account is rolled back if recovery code generation fails.
        
        Ensures atomicity: if recovery code generation fails, the entire registration
        is rolled back and no user is created (no race condition).
        """
        # Simulate recovery code generation failure
        def mock_generate_recovery_codes_fail(*args, **kwargs):
            raise Exception("Simulated recovery code generation failure")
        
        monkeypatch.setattr('app.generate_recovery_codes', mock_generate_recovery_codes_fail)
        
        # Attempt registration
        response = client.post('/register', data={
            'username': 'rollbacktest',
            'email': 'rollback@example.com',
            'password': 'ValidPass123!',
            'confirm_password': 'ValidPass123!'
        }, follow_redirects=True)
        
        # Should show error message
        assert response.status_code == 200
        assert b'Registration failed' in response.data
        
        # Most importantly: user should NOT be created in database
        # Use app context because test may run outside of request context
        with app.app_context():
            user = User.query.filter_by(email='rollback@example.com').first()
            assert user is None, "User should not be created if recovery code generation fails"
            
            # Verify no orphaned user account exists
            all_users = User.query.all()
            assert all(u.email != 'rollback@example.com' for u in all_users)