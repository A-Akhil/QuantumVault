# Session Terminology - Clarification

## Two Different Types of "Sessions" in This System

### 1. **Login Session** (Django Session) 🔐
**What you're thinking of**: Traditional web session

- **Purpose**: Keep user logged in across multiple page visits
- **Created**: When user logs in with username/password
- **Duration**: Until user logs out or browser closes
- **Technology**: Django's session framework (stored in database/cookies)
- **Scope**: Authentication and user state

**Example**:
```
User logs in → Login Session created
User browses dashboard → Still logged in (same session)
User uploads file → Still logged in (same session)
User closes browser → Login session ends
```

---

### 2. **BB84 Session** (Quantum Key Exchange Session) 🔑
**What I'm referring to in the code**: Quantum cryptographic key establishment

- **Purpose**: Establish a shared quantum-safe encryption key between TWO users
- **Created**: When User A initiates BB84 protocol with User B
- **Duration**: NOW PERMANENT (after our changes - previously expired after 15 minutes)
- **Technology**: BB84 quantum key distribution protocol simulation
- **Scope**: Secure communication between two specific users

**Example**:
```
User A clicks "Initiate BB84 with User B"
↓
BB84Session created (status='pending')
↓
User B accepts the request
↓
BB84 protocol runs (quantum key exchange simulation)
↓
BB84Session completed (status='completed', shared_key generated)
↓
NOW: Both users can encrypt files to each other FOREVER using this key
```

---

## Comparison Table

| Aspect | Login Session 🔐 | BB84 Session 🔑 |
|--------|------------------|-----------------|
| **Between** | User ↔ Server | User A ↔ User B |
| **Purpose** | Authentication | Encryption Key |
| **Creates** | Access to system | Shared secret key |
| **Lasts** | Until logout | PERMANENT (now) |
| **Multiple?** | One per user | Many per user pair |
| **Table** | `django_session` | `core_bb84session` |

---

## Real-World Analogy

### Login Session (Django):
```
Like showing your ID card to enter a building
- You show ID once → Get access badge
- Badge works all day (one session)
- Next day → Show ID again → New badge (new session)
```

### BB84 Session (Quantum Key):
```
Like exchanging a secret handshake with a friend
- You and Friend create unique handshake (BB84 protocol)
- Handshake is YOUR special way to communicate
- You can use it FOREVER (permanent now)
- Each friend pair has their own unique handshake
```

---

## In the Code Context

When I say **"session"** in the BB84 implementation, I mean:

```python
class BB84Session(models.Model):
    """
    Represents ONE quantum key exchange between TWO users.
    NOT related to login/authentication sessions!
    """
    session_id = models.UUIDField(...)
    sender = models.ForeignKey(...)      # User who initiated
    receiver = models.ForeignKey(...)    # User who accepted
    shared_key = models.BinaryField(...) # The quantum-derived key
    status = models.CharField(...)       # pending/completed/failed
    created_at = models.DateTimeField(...)
```

**Each BB84Session**:
- Links TWO specific users (A ↔ B)
- Stores ONE shared quantum key
- Is INDEPENDENT of login sessions
- Can be reused for MULTIPLE file uploads (after our fix)

---

## User Journey Example

### Scenario: Alice and Bob

**Login Sessions** (Authentication):
```
Day 1:
  Alice logs in → Login Session #1 created
  Alice logs out → Login Session #1 ends

Day 2:
  Alice logs in → Login Session #2 created (new)
  Alice logs out → Login Session #2 ends
```

**BB84 Sessions** (Encryption Keys):
```
Day 1:
  Alice initiates BB84 with Bob → BB84Session #1 created
  Bob accepts → BB84Session #1 completes
  Alice uploads file.pdf to Bob → Uses BB84Session #1 key ✅

Day 2:
  Alice logs in (NEW login session)
  Alice uploads photo.jpg to Bob → Uses SAME BB84Session #1 key ✅
  
Day 100:
  Alice uploads video.mp4 to Bob → STILL uses BB84Session #1 key ✅
  Bob uploads report.doc to Alice → STILL uses BB84Session #1 key ✅
  
  (PERMANENT - no need to re-run BB84 protocol!)
```

---

## Why We Have BB84Sessions

**Problem**: How do two users securely exchange files?

**Solution**:
1. **First**: Run BB84 quantum key exchange ONCE
   - Creates `BB84Session` with `shared_key`
   - This key is quantum-safe (eavesdropper detection)

2. **Then**: Use that key to wrap file encryption keys
   - Every file upload uses AES-256 encryption
   - AES key is wrapped with the BB84 shared key
   - No need to run BB84 again!

---

## In Database

You can see the difference:

```bash
# Login sessions (Django default)
sqlite3 db.sqlite3 "SELECT * FROM django_session LIMIT 5;"
# Shows: session_key, session_data, expire_date

# BB84 sessions (Our quantum keys)
sqlite3 db.sqlite3 "SELECT session_id, sender_id, receiver_id, status FROM core_bb84session;"
# Shows: UUID, which users, completion status
```

---

## Summary

**Login Session** = "Am I allowed in the system?"
- One per user
- Temporary (until logout)
- For authentication

**BB84 Session** = "What key do we use to encrypt files between us?"
- One per user PAIR
- PERMANENT (after our changes)
- For encryption

When I talk about "bidirectional sessions", I mean:
> **BB84Session between A↔B works in BOTH directions**
> - A can encrypt files to B using it ✅
> - B can encrypt files to A using it ✅
> - Same quantum key, both directions, forever

**Does this clear up the confusion?** 🤔

The term "session" is overloaded in web development - it can mean login sessions OR protocol sessions. In our quantum storage system, we have BOTH, but they're completely separate concepts!
