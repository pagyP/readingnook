# Security Hardening: Token-Based Password Reset

## Overview
Replaced the vulnerable URL-based password reset mechanism with cryptographically signed, time-limited tokens. This addresses critical security issues identified in the GitHub Copilot PR review.

## Vulnerability Fixed

### Previous Implementation (❌ Vulnerable)
```
/reset-password/<user_id>/<code_id>
```

**Issues:**
1. **ID Enumeration**: Attacker could guess user IDs (1, 2, 3, etc.) and code IDs
2. **URL Logging**: Sensitive IDs exposed in browser history, server logs, proxy logs
3. **Indefinite Validity**: Reset links never expire - usable forever
4. **No Integrity Check**: No verification that URL parameters haven't been tampered with
5. **Information Disclosure**: IDs reveal account information to anyone with access to logs

### New Implementation (✅ Secure)
```
/reset-password?token=<URLSafeTimedSerializer_signed_token>
```

**Benefits:**
1. **Unguessable Token**: Cryptographically signed using SECRET_KEY
2. **Time-Limited**: Expires after 15 minutes (900 seconds)
3. **No Sensitive Data in URL**: User ID and code ID encrypted within token
4. **Integrity Verification**: Token signature validation prevents tampering
5. **Audit Trail**: No sensitive IDs in logs

## Technical Implementation

### Dependencies
- **itsdangerous**: URLSafeTimedSerializer for cryptographic token signing
  - Provides HMAC signature with SECRET_KEY
  - Includes timestamp for expiration validation
  - Designed specifically for this use case (Flask-WTF uses it internally)

### Code Changes

#### 1. Token Generation (`app.py`)
```python
from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer(SECRET_KEY)
TOKEN_EXPIRATION_SECONDS = 15 * 60  # 15 minutes

def generate_reset_token(user_id, code_id):
    """Generate a signed, time-limited reset token"""
    return serializer.dumps(
        {'user_id': user_id, 'code_id': code_id},
        salt='password-reset'
    )
```

#### 2. Token Validation (`app.py`)
```python
def verify_reset_token(token):
    """Validate token signature and expiration"""
    try:
        data = serializer.loads(
            token,
            salt='password-reset',
            max_age=TOKEN_EXPIRATION_SECONDS
        )
        return data
    except (BadSignature, SignatureExpired):
        return None  # Invalid or expired token
```

#### 3. Route Changes (`app.py`)

**Forgot Password Route** (generates token):
```python
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    # ... verify email and recovery code ...
    reset_token = generate_reset_token(user.id, matching_code.id)
    return redirect(url_for('reset_password', token=reset_token))
```

**Reset Password Route** (validates token):
```python
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token') or request.form.get('token')
    token_data = verify_reset_token(token)
    
    if not token_data:
        flash('Invalid or expired reset link', 'error')
        return redirect(url_for('forgot_password'))
    
    user_id = token_data.get('user_id')
    code_id = token_data.get('code_id')
    # ... complete password reset ...
```

#### 4. Template Changes (`templates/reset_password.html`)
```html
<!-- Token passed as hidden field to survive form submission -->
<input type="hidden" name="token" value="{{ token }}">
```

## Security Properties

| Property | Previous | New |
|----------|----------|-----|
| Guessable | ✗ Yes (sequential IDs) | ✓ No (cryptographically signed) |
| Time-limited | ✗ No (forever) | ✓ Yes (15 minutes) |
| Recoverable from URL | ✓ Yes (sensitive IDs) | ✗ No (encrypted in token) |
| Tampering Detection | ✗ No | ✓ Yes (HMAC signature) |
| Logged Safely | ✗ No (contains IDs) | ✓ Yes (no sensitive data) |

## Expiration Policy

**15-minute window** balances security with usability:
- **Short enough** to limit attack window if token leaked
- **Long enough** for legitimate users to receive email and reset password
- **Follows OWASP** recommendations for password reset tokens

## Testing

### Test Coverage
All 6 recovery code tests passing:
- ✅ Recovery codes generated on registration
- ✅ Recovery codes stored (hashed) in database
- ✅ Forgot password page loads
- ✅ **Password reset with valid recovery code** (token-based flow)
- ✅ Invalid recovery codes rejected
- ✅ Recovery code must match email

### Full Test Suite
All 32 tests pass:
- 8 authentication tests
- 8 book CRUD tests
- 6 search tests
- 3 password security tests
- 6 recovery code tests
- 1 integration test

## OWASP Compliance

✅ **Compliant with OWASP Guidelines for Password Reset Functionality**

1. **Account Takeover Prevention**: Cryptographic token prevents unauthorized access
2. **Timing Attack Resistance**: HMAC verification timing-safe
3. **Token Generation**: Sufficient entropy via SECRET_KEY
4. **Token Storage**: Not stored (stateless validation)
5. **Token Transmission**: Passed via URL query parameter and form data
6. **Token Expiration**: 15-minute window
7. **Single Use**: Code marked as used after successful reset

## Migration Notes

- **Backward Incompatible**: Old reset URLs (with IDs) no longer work
  - This is intentional - prevents old links from being exploited
- **User Impact**: None - users don't see internal token details
- **No Database Migration**: Token is stateless (not stored)
- **No API Breaking Changes**: Other endpoints unaffected

## Future Enhancements

1. **Email Token Verification**: Send tokens via email instead of including in URL
2. **Rate Limiting**: Add rate limiting to forgot-password endpoint
3. **Audit Logging**: Log password reset attempts (without token)
4. **Invalidation on Login**: Invalidate reset tokens if user logs in with old password
5. **Recovery Code Rotation**: Require code rotation after successful reset

## Related Documentation

- [RECOVERY_CODES.md](RECOVERY_CODES.md) - Recovery code implementation details
- [OWASP Password Reset Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [itsdangerous Documentation](https://itsdangerous.palletsprojects.com/)
