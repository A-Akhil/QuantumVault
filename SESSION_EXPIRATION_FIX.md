# BB84 Session Expiration Issue - SOLVED

## Problem
Your BB84 session **expired** after 15 minutes!

- Created: Oct 06, 2025 16:06
- Completed: Oct 06, 2025 16:24  
- **Status: Expired** (15 min limit exceeded)

## Why This Happens
BB84 sessions expire after 15 minutes for security reasons. This ensures:
- Keys aren't reused indefinitely
- Compromised keys have limited exposure time
- Forces fresh quantum key exchanges

## Solution: Create a Fresh Session

### Option 1: Web UI (Easiest)
1. Go to: http://127.0.0.1:8001/key-exchange/
2. Select akhil1@gmail.com
3. Click "Initiate BB84 Key Exchange Request"
4. Login as akhil1, click "Accept"
5. Wait 10-15 seconds for protocol to complete
6. Now upload your file!

### Option 2: Quick Script
Run this to create a new session programmatically:

```python
#!/usr/bin/env python
import os, sys, django
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'quantum_storage.settings')
django.setup()

from core.models import BB84Session, QuantumUser

# Create pending session
sender = QuantumUser.objects.get(email='akhilarul324@gmail.com')
receiver = QuantumUser.objects.get(email='akhil1@gmail.com')

session = BB84Session.objects.create(
    sender=sender,
    receiver=receiver,
    status='pending',
    receiver_accepted=False,
    progress_percentage=0
)

print(f"✅ Created session: {session.session_id}")
print(f"   Status: pending")
print(f"   Next step: Login as {receiver.email} and accept!")
```

## Alternative: Extend Expiration Time

If you want longer sessions, update the model:

**File:** `core/models.py`, line 496

```python
# Change from 15 minutes to 60 minutes (1 hour)
self.expires_at = timezone.now() + timedelta(minutes=60)
```

Then restart server:
```bash
python manage.py runserver
```

## Current Session Details

```
Session ID: 0bdf1404-6cf1-4559-88e4-b26150c49bc1
Status: completed (but EXPIRED)
Created: 16:06
Completed: 16:24
Expires: 16:21 (15 min after creation)
Current time: After 16:21
Result: ❌ Cannot use for upload
```

## Quick Fix Right Now

```bash
# 1. Create new session via web
http://127.0.0.1:8001/key-exchange/

# 2. Or use this command:
cd "/home/akhil/Downloads/temp/quantum project"
python manage.py shell -c "
from core.models import BB84Session, QuantumUser;
from django.utils import timezone;
from datetime import timedelta;
sender = QuantumUser.objects.get(email='akhilarul324@gmail.com');
receiver = QuantumUser.objects.get(email='akhil1@gmail.com');
session = BB84Session.objects.create(
    sender=sender, 
    receiver=receiver, 
    status='pending', 
    receiver_accepted=False
);
print(f'Session created: {session.session_id}');
print('Now go accept it as receiver!')
"
```

---

**Status:** Issue identified - session expired after 15 minutes.  
**Action:** Create new BB84 session before uploading files.
