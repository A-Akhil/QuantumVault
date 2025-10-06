# Bidirectional Recipient Lookup Fix

## Issue Reported

**User**: Account A (sender) can see B in "Select Recipients", but Account B (receiver) cannot see A

**Scenario**:
```
User A → BB84 Session → User B (completed)
A goes to upload form: ✅ Sees B in dropdown
B goes to upload form: ❌ Does NOT see A in dropdown
```

## Root Cause

The upload form (GET request handler) was using **one-way lookup** to find available recipients:

```python
# OLD CODE (BROKEN)
completed_sessions = BB84Session.objects.filter(
    sender=request.user,  # ❌ Only finds sessions where user is sender
    status='completed'
)
receiver_ids = completed_sessions.values_list('receiver_id', flat=True)
available_users = QuantumUser.objects.filter(id__in=receiver_ids)
```

**Problem**: This only finds sessions where `request.user` is the **sender**, so:
- User A (sender) → finds sessions → sees B (receiver) ✅
- User B (receiver) → finds NO sessions → sees nobody ❌

## Solution

Changed to **bidirectional lookup** using Q objects:

```python
# NEW CODE (FIXED)
completed_sessions = BB84Session.objects.filter(
    Q(sender=request.user) | Q(receiver=request.user),  # ✅ Both directions
    status='completed'
).select_related('sender', 'receiver')

# Extract the OTHER user from each session
user_ids = set()
for session in completed_sessions:
    if session.sender == request.user:
        user_ids.add(session.receiver_id)  # User is sender → add receiver
    else:
        user_ids.add(session.sender_id)    # User is receiver → add sender

available_users = QuantumUser.objects.filter(id__in=user_ids)
```

**Result**: Now finds sessions in **both directions**:
- User A → finds A→B session → sees B ✅
- User B → finds A→B session (where B is receiver) → sees A ✅

## Files Changed

- **File**: `core/views.py`
- **Function**: `upload_file_view` (GET request handler)
- **Lines**: ~642-657

## Testing

### Before Fix:
```
Session: A (sender) ←→ B (receiver)
A uploads to: [B] ✅
B uploads to: [ ] ❌ (empty!)
```

### After Fix:
```
Session: A (sender) ←→ B (receiver)
A uploads to: [B] ✅
B uploads to: [A] ✅ (BIDIRECTIONAL!)
```

## Related Changes

This fix is part of the larger "Permanent Bidirectional Keys" feature:

1. ✅ Model: Disabled session expiration
2. ✅ Views: Bidirectional validation in upload handler
3. ✅ Views: Bidirectional session linking
4. ✅ Views: **Bidirectional recipient lookup** ← THIS FIX
5. ✅ Template: Updated UI messaging

See `PERMANENT_BIDIRECTIONAL_KEYS.md` for full details.

## Verification

To test:
1. Log in as User A
2. Initiate BB84 session with User B
3. Wait for session to complete
4. Log in as User A → Go to upload → Should see B ✅
5. Log in as User B → Go to upload → Should see A ✅ (FIXED)
6. Both users can now upload files to each other using the same session

**Status**: ✅ Fixed and tested
**Date**: 2025-10-06
