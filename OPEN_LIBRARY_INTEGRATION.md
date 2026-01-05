# Open Library API Integration

## Overview

Reading Nook now integrates with the **Open Library API** to automatically fetch book information when you enter an ISBN. This eliminates tedious manual data entry and ensures consistent book metadata.

## How It Works

### Adding a Book with ISBN

1. Go to **"Add a New Book"** page
2. Enter a valid ISBN-10 or ISBN-13 in the **ISBN** field
3. Click the **🔍 Lookup** button (or press Enter)
4. The form automatically fills in:
   - ✅ Book title
   - ✅ Author name(s)
   - ✅ Genre/subjects

### Editing a Book with ISBN

The same ISBN lookup feature is available on the **"Edit Book"** page, so you can quickly update book information.

## Supported ISBN Formats

- **ISBN-13**: 13-digit format (e.g., `9780743273565`)
- **ISBN-10**: 10-digit format (e.g., `0743273565`)
- Both formats work **with or without hyphens** (e.g., `978-0-7432-7356-5`)

## Technical Details

### API Endpoint

**POST** `/api/book-lookup`

```json
Request:
{
  "isbn": "9780743273565"
}

Response (Success - 200):
{
  "title": "The Great Gatsby",
  "author": "F. Scott Fitzgerald",
  "genre": "American fiction, Psychological fiction, Bildungsromans",
  "cover_url": "https://covers.openlibrary.org/b/id/10590366-M.jpg"
}

Response (Not Found - 404):
{
  "error": "Book not found in Open Library"
}
```

### Data Extraction

The implementation queries the Open Library **Search API** endpoint and extracts:

| Field | Source | Notes |
|-------|--------|-------|
| **Title** | `docs[0].title` | Primary book title |
| **Author** | `docs[0].author_name` | First 3 authors (comma-separated) |
| **Genre** | `docs[0].subject` | First 3 subjects/genres |
| **Cover URL** | `docs[0].cover_i` | Image ID from Open Library CDN |

### Error Handling

The lookup gracefully handles:

- ✅ Network timeouts (3-second limit per request)
- ✅ API errors (4xx, 5xx responses)
- ✅ ISBN not found
- ✅ Malformed API responses
- ✅ Missing or incomplete data

**User Experience**: Instead of blocking the form, failed lookups show a friendly error message and allow manual entry.

### Logging

All API interactions are logged:

```
INFO:  Successfully fetched book from Open Library: The Great Gatsby
WARNING: Open Library API timeout for ISBN 9780743273565
WARNING: ISBN 9780743273565 not found in Open Library
ERROR: Open Library API request error: <details>
```

## Dependencies

- **requests** (v2.32.3): HTTP library for API calls
- No external API keys required (Open Library is free and public)

## Privacy & Security

- ✅ No personal data is sent to Open Library (only ISBN)
- ✅ API calls are read-only (no modifications)
- ✅ Response data is public book metadata (no sensitive information)
- ✅ Request timeout prevents resource exhaustion
- ✅ All errors are handled gracefully

## Limitations

- Open Library's coverage is excellent but not 100% complete
  - Older or very niche books may not be found
  - Some regional editions may not have metadata
- Subject/genre categorization is Open Library's classification (may differ from user preference)
- Cover image availability depends on Open Library's cover archive

## Future Enhancements

Possible improvements:

1. **Cover Display**: Show fetched book cover in the form preview
2. **Multiple Results**: If multiple editions found, let user select which one
3. **Rating Integration**: Fetch average rating from Open Library  
4. **Description/Summary**: Auto-populate book description/synopsis
5. **Publish Date**: Extract publication date automatically
6. **Publisher**: Add publisher information

## References

- [Open Library API Documentation](https://openlibrary.org/dev/docs/api/search)
- [Open Library Search API](https://openlibrary.org/dev/docs/api/search)
- [Book Cover API](https://openlibrary.org/dev/docs/api/covers)
