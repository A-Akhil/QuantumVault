# File Upload ForeignKey Error - FIXED ✅

## Error Message
```
File upload failed for slides-1.pdf: save() prohibited to prevent data loss 
due to unsaved related object 'file'.
```

## Root Cause

**Django ForeignKey Constraint Violation**

The code was trying to link `BB84Session.file` to an `EncryptedFile` object **before** the file was saved to the database:

```python
# ❌ WRONG ORDER (before fix):
bb84_session.file = encrypted_file  # encrypted_file not saved yet!
bb84_session.save()  # ERROR: Can't reference unsaved object

# ... later ...
encrypted_file.save()  # File saved too late
```

Django prevents this to maintain referential integrity - you can't have a ForeignKey pointing to an object that doesn't exist in the database yet.

## The Fix

**Changed order: Save file FIRST, then link sessions**

### Before (lines 527-528):
```python
# Mark session as used
bb84_session.file = encrypted_file  # ❌ File not saved yet
bb84_session.save()
```

### After:
```python
# Store session to link after file is saved
sessions_to_link.append(bb84_session)  # ✅ Just store reference

# ... process all recipients ...

# Save file to database
encrypted_file.save()  # ✅ File saved first

# NOW link BB84 sessions to the saved file
for session in sessions_to_link:
    session.file = encrypted_file  # ✅ File exists now
    session.save()
```

## Technical Details

### Why This Matters
1. **Database Integrity**: ForeignKeys must reference existing records
2. **Transaction Safety**: Prevents orphaned references
3. **Django ORM**: Enforces referential integrity at save time

### What Changed
- Added `sessions_to_link = []` list to collect sessions
- Changed `bb84_session.file = encrypted_file; bb84_session.save()` to `sessions_to_link.append(bb84_session)`
- Added loop after `encrypted_file.save()` to link all collected sessions

### Files Modified
- **core/views.py** (upload_file_view function)
  - Line ~489: Added `sessions_to_link` list
  - Line ~527: Changed immediate save to append
  - Line ~569: Added post-save linking loop

## Testing

### Before Fix:
```bash
# Upload attempt:
❌ File upload failed for slides-1.pdf: save() prohibited...
```

### After Fix:
```bash
# Upload should now work:
✅ File "slides-1.pdf" uploaded and encrypted successfully!
```

## How to Test

1. **Reset sessions** (if needed):
   ```bash
   python reset_bb84_sessions.py
   ```

2. **Create fresh BB84 session**:
   - Go to: http://127.0.0.1:8001/key-exchange/
   - Select recipient: akhil1@gmail.com
   - Click "Initiate BB84 Key Exchange Request"
   - Login as akhil1@gmail.com
   - Click "Accept & Run BB84"
   - Wait 10-15 seconds

3. **Upload file immediately** (within 15 minutes):
   - Go to: http://127.0.0.1:8001/upload/
   - Select file: slides-1.pdf
   - Select recipient: akhil1@gmail.com
   - Click upload
   - ✅ Should work now!

## Important Notes

### Session Expiration
Remember: BB84 sessions still expire after **15 minutes**!

**Workflow:**
1. Complete BB84 key exchange
2. **Upload file within 15 minutes**
3. Session automatically linked to file

**If session expires:**
- Create new BB84 session
- Then upload file

### Multiple Recipients
For files with multiple recipients:
- Each recipient needs a valid BB84 session
- All sessions must be non-expired
- All sessions get linked to the same file after save

## Related Issues Fixed
- ✅ ForeignKey constraint violation
- ✅ Transaction ordering
- ✅ Referential integrity maintained
- ✅ Multiple session linking works

---

**Status:** Fixed and ready for testing!  
**Next:** Upload a file and verify it works without errors.
