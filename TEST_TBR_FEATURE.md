# Testing the TBR (To Be Read) Feature

## What's New

The app now includes a "To Be Read" (TBR) feature that lets you track books in three statuses:

- **📚 To Read** - Books you want to read
- **📖 Currently Reading** - Books you're actively reading
- **✓ Read** - Books you've already finished reading

## Changes Made

### Database Model (`app.py`)
- Added `status` field to the `Book` model with three possible values: `'to_read'`, `'currently_reading'`, `'read'`
- Default status is `'read'` for backward compatibility with existing books

### Forms (`app.py`)
- Updated `BookForm` to include a `status` SelectField with the three options

### Routes (`app.py`)
- Updated `/` (index) route to support filtering by status via `?status=to_read|currently_reading|read|all`
- Updated `/add` route to save the selected status when creating a book
- Updated `/edit/<id>` route to handle status updates and pre-populate the status field

### Templates
- **index.html**:
  - Added status filter dropdown in the search container (All Books, To Read, Currently Reading, Read)
  - Added status badges to book cards showing the current status with color coding
  - Updated stats text to reflect the current filter (e.g., "📚 3 books to read")
  
- **add_book.html**:
  - Added status select field after the format field
  
- **edit_book.html**:
  - Added status select field after the format field

## How to Use

### Add a New Book to Your TBR List
1. Click "Add Book"
2. Fill in title, author, and other details
3. Select **"To Read"** in the Status dropdown
4. Click "Save Book"

### Change a Book's Status
1. Click "Edit" on any book card
2. Change the status from the Status dropdown
3. Click "Save Book"

### Filter Your Books by Status
1. Use the status filter dropdown on the home page
2. Select: "All Books", "📚 To Read", "📖 Currently Reading", or "✓ Read"
3. The page will show only books with that status
4. The stats will update to show you how many books are in each category

### Search Combined with Status
- You can search for books AND filter by status at the same time
- For example: search for "fiction" in your "To Read" list

## Database Migration

When you first run the updated app:
1. The database schema will be automatically updated with the new `status` column
2. All existing books will have `status = 'read'` by default
3. No data will be lost

## API Endpoint

The search/filter endpoint is:
```
GET /?search=query&status=to_read|currently_reading|read|all
```

Examples:
- `/?status=to_read` - Show all books to read
- `/?status=currently_reading` - Show currently reading
- `/?search=fiction&status=to_read` - Search for "fiction" in To Read list
- `/?status=all` or `/?` - Show all books (default)

## Color Coding on Book Cards

- **Yellow badge**: 📚 To Read
- **Light blue badge**: 📖 Currently Reading  
- **Light green badge**: ✓ Read

## Design Notes

The implementation follows your existing app patterns:
- Uses Flask-WTF forms for validation
- Integrates with the existing Book model
- Maintains responsive design on mobile/tablet/desktop
- Status is required when creating/editing books
- Uses emojis for visual clarity (consistent with existing UI)
- Backward compatible - existing books default to "read" status
