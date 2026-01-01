[![Tests](https://github.com/pagyP/readingnook/actions/workflows/python-app.yml/badge.svg)](https://github.com/pagyP/readingnook/actions/workflows/python-app.yml)

# Reading Nook 📚

A simple Flask web application to track and record the books you've read.

## Features

- ✅ Add books you've read with title, author, and date
- ⭐ Rate books on a 1-5 star scale
- 📝 Add personal notes and thoughts about each book
- ✏️ Edit book entries
- 🗑️ Delete books from your collection
- 📊 View all your books in a beautiful grid layout

## Installation

1. **Clone or create the project:**
   ```bash
   git clonehttps://github.com/pagyP/readingnook.git
   cd readingnook
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and set a strong `SECRET_KEY` for production. You can generate one with:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

## Running the Application

1. **Activate the virtual environment** (if not already active):
   ```bash
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Start the Flask app:**
   ```bash
   python3 app.py
   ```

3. **Open your browser** and navigate to:
   ```
   http://localhost:5000
   ```

4. **Create an account** or log in with existing credentials

## Security Features

✅ **User Authentication** - Create accounts with secure password hashing  
✅ **Password Security** - Passwords hashed using Werkzeug's PBKDF2  
✅ **Session Management** - Secure session handling with Flask-Login  
✅ **CSRF Protection** - All forms protected with CSRF tokens via Flask-WTF  
✅ **Data Isolation** - Users can only see and edit their own books  
✅ **Environment Variables** - Secret key stored in .env (not committed to git)  
✅ **Form Validation** - Email format and password confirmation validation

## Project Structure

```
readingnook/
├── app.py              # Main Flask application and routes
├── requirements.txt    # Python dependencies
├── README.md          # This file
├── .gitignore         # Git ignore rules
└── templates/         # HTML templates
    ├── base.html      # Base template with styling
    ├── index.html     # Home page (list of books)
    ├── add_book.html  # Form to add a new book
    └── edit_book.html # Form to edit a book
```

## Usage

### Creating an Account
1. Click "Sign Up" in the top navigation
2. Enter a username, email, and password
3. Confirm your password and submit
4. You'll be redirected to log in with your new account

### Logging In
1. Click "Log In" on the home page
2. Enter your email and password
3. You'll be logged in and can start adding books

### Adding a Book
1. Click "+ Add Book" in the navigation
2. Fill in the book details (title and author are required)
3. Select the date you finished reading
4. Optionally add a rating and notes
5. Click "Save Book"

### Editing a Book
1. On the home page, click "Edit" on any book card
2. Modify the details as needed
3. Click "Update Book"

### Deleting a Book
1. On the home page, click "Delete" on any book card
2. Confirm the deletion

### Logging Out
1. Click "Logout" in the top right navigation

## Future Enhancements

Consider adding:
- Book covers/images
- Genre/categories
- Reading progress tracking
- Search and filter functionality
- Statistics and reading goals
- User authentication for multiple readers
- Export to CSV/PDF

## Technologies Used

- **Backend:** Flask (Python web framework)
- **Database:** SQLite with SQLAlchemy ORM
- **Frontend:** HTML5, CSS3
- **Architecture:** Simple MVC pattern

## License

Feel free to use and modify this project!

## Screenhots
![Home Page](images/login-screen.png)
![Book List](images/book-list.png)