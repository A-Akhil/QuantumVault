# Context-Aware BB84 Sessions - Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         USER A (Alice)                                   │
│                                                                           │
│  Personal Context:                                                        │
│    ┌──────────────────────┐                                              │
│    │  BB84Session         │                                              │
│    │  sender: Alice       │                                              │
│    │  receiver: Bob       │                                              │
│    │  context_type: personal                                             │
│    │  group: NULL         │                                              │
│    │  shared_key: 0x1234  │ ─────► Used for personal file uploads       │
│    └──────────────────────┘                                              │
│                                                                           │
│  Work Group Context:                                                      │
│    ┌──────────────────────┐                                              │
│    │  BB84Session         │                                              │
│    │  sender: Alice       │                                              │
│    │  receiver: Bob       │                                              │
│    │  context_type: group │                                              │
│    │  group: "Team"       │                                              │
│    │  shared_key: 0xABCD  │ ─────► Used for Team group file uploads     │
│    └──────────────────────┘                                              │
│                                                                           │
│  Family Group Context:                                                    │
│    ┌──────────────────────┐                                              │
│    │  BB84Session         │                                              │
│    │  sender: Alice       │                                              │
│    │  receiver: Bob       │                                              │
│    │  context_type: group │                                              │
│    │  group: "Family"     │                                              │
│    │  shared_key: 0x9876  │ ─────► Used for Family group file uploads   │
│    └──────────────────────┘                                              │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘

                                    ↕
                                    
┌─────────────────────────────────────────────────────────────────────────┐
│                         USER B (Bob)                                     │
│                                                                           │
│  (Bob has matching sessions from his perspective)                        │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Upload Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         FILE UPLOAD PROCESS                               │
└──────────────────────────────────────────────────────────────────────────┘

User selects upload destination
         │
         ├─── Group Selected? (e.g., "Team")
         │         │
         │         ├─ YES ──► context_type = 'group'
         │         │           group = Team
         │         │
         │         └─ NO ───► context_type = 'personal'
         │                    group = NULL
         │
         ↓
    Validate BB84 Sessions
         │
         ├─── For each recipient:
         │    │
         │    ├─ Query: BB84Session.filter(
         │    │           sender=User, receiver=Recipient,
         │    │           context_type=DETECTED_CONTEXT,
         │    │           group=SELECTED_GROUP_OR_NULL,
         │    │           status='completed'
         │    │         )
         │    │
         │    ├─ Found? ──► Use this session's shared_key
         │    │
         │    └─ Not Found? ──► Redirect to establish keys
         │
         ↓
    Encrypt File with AES-256-GCM
         │
         ↓
    Wrap AES key for each recipient
    (using their context-appropriate BB84 shared key)
         │
         ↓
    Store encrypted file + wrapped keys
         │
         ↓
    SUCCESS ✅
```

---

## Database Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│                        BB84Session Table                             │
├──────────────────┬──────────────┬───────────────┬──────────────────┤
│ session_id       │ sender_id    │ receiver_id   │ context_type     │
│ (UUID)           │ (FK User)    │ (FK User)     │ (VARCHAR)        │
├──────────────────┼──────────────┼───────────────┼──────────────────┤
│ abc-123-...      │ Alice (1)    │ Bob (2)       │ 'personal'       │
│ def-456-...      │ Alice (1)    │ Bob (2)       │ 'group'          │
│ ghi-789-...      │ Alice (1)    │ Bob (2)       │ 'group'          │
└──────────────────┴──────────────┴───────────────┴──────────────────┘
         ↓                                                  ↓
┌──────────────────┬──────────────┬───────────────────────────────────┐
│ group_id         │ status       │ shared_key                        │
│ (FK Group)       │ (VARCHAR)    │ (BINARY)                          │
├──────────────────┼──────────────┼───────────────────────────────────┤
│ NULL             │ 'completed'  │ 0x1234... (32 bytes)             │
│ Team (10)        │ 'completed'  │ 0xABCD... (32 bytes)             │
│ Family (11)      │ 'completed'  │ 0x9876... (32 bytes)             │
└──────────────────┴──────────────┴───────────────────────────────────┘

Unique Constraint: (sender_id, receiver_id, context_type, group_id)
                    ↑
                    Allows multiple sessions per user pair!
```

---

## Security Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SECURITY COMPARTMENTALIZATION                     │
└─────────────────────────────────────────────────────────────────────┘

Scenario: Attacker compromises Team group key (0xABCD)

┌─────────────────────────────────────────────────────────────────────┐
│  Team Group Files                                                    │
│  ├─ team_report.pdf         [Encrypted with 0xABCD]                 │
│  ├─ quarterly_results.xlsx  [Encrypted with 0xABCD]                 │
│  └─ meeting_notes.docx      [Encrypted with 0xABCD]                 │
│                                                                       │
│  Status: ❌ COMPROMISED - Attacker can decrypt                       │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  Personal Files                                                      │
│  ├─ personal_project.doc    [Encrypted with 0x1234]                 │
│  ├─ resume.pdf              [Encrypted with 0x1234]                 │
│  └─ bank_statement.pdf      [Encrypted with 0x1234]                 │
│                                                                       │
│  Status: ✅ SAFE - Different key, still secure                       │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  Family Group Files                                                  │
│  ├─ vacation_photos.zip     [Encrypted with 0x9876]                 │
│  ├─ family_tree.pdf         [Encrypted with 0x9876]                 │
│  └─ holiday_video.mp4       [Encrypted with 0x9876]                 │
│                                                                       │
│  Status: ✅ SAFE - Different key, still secure                       │
└─────────────────────────────────────────────────────────────────────┘

                    DAMAGE CONTAINED ✅
     Only Team group files affected, rest remain secure!
```

---

## User Journey

```
┌────────────────────────────────────────────────────────────────┐
│  STEP 1: Create Group                                          │
├────────────────────────────────────────────────────────────────┤
│  User clicks: "Create Group"                                   │
│  Enters: Name = "Team", Members = [Bob, Carol, Dave]          │
│  Clicks: "Create"                                              │
│                                                                 │
│  System:                                                        │
│    ✅ Creates UserGroup record                                 │
│    ✅ Creates 3 pending BB84Sessions (context='group'):        │
│       - Alice → Bob (Team)                                     │
│       - Alice → Carol (Team)                                   │
│       - Alice → Dave (Team)                                    │
│    ✅ Redirects to: "Establish Group Keys"                     │
└────────────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────────────┐
│  STEP 2: Establish Group Keys                                  │
├────────────────────────────────────────────────────────────────┤
│  Page shows:                                                    │
│    📊 Progress: 0 of 3 members have keys                       │
│    ⏳ Pending: Bob, Carol, Dave                                │
│                                                                 │
│  User actions:                                                  │
│    1. Bob accepts → Runs BB84 → Key established ✅             │
│    2. Carol accepts → Runs BB84 → Key established ✅           │
│    3. Dave accepts → Runs BB84 → Key established ✅            │
│                                                                 │
│  Result:                                                        │
│    📊 Progress: 3 of 3 members have keys ✅                    │
│    ✅ All group keys established                               │
└────────────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────────────┐
│  STEP 3: Upload to Group                                       │
├────────────────────────────────────────────────────────────────┤
│  User:                                                          │
│    - Navigates to Upload page                                  │
│    - Selects group: "Team" from dropdown                       │
│    - Uploads file: team_report.pdf                            │
│    - Clicks: "Upload"                                          │
│                                                                 │
│  System:                                                        │
│    ✅ Detects: context_type = 'group', group = Team           │
│    ✅ Validates: All group keys exist (Bob, Carol, Dave)      │
│    ✅ Encrypts file with AES-256-GCM                           │
│    ✅ Wraps AES key with each member's GROUP key              │
│       - Uses Bob's Team key (not personal key!)               │
│       - Uses Carol's Team key                                  │
│       - Uses Dave's Team key                                   │
│    ✅ Stores encrypted file                                    │
│                                                                 │
│  Result: File uploaded successfully with group keys ✅         │
└────────────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────────────┐
│  STEP 4: Upload to Individual (Personal)                       │
├────────────────────────────────────────────────────────────────┤
│  User:                                                          │
│    - Navigates to Upload page                                  │
│    - Does NOT select group                                     │
│    - Selects individual: Bob                                   │
│    - Uploads file: personal_project.doc                        │
│    - Clicks: "Upload"                                          │
│                                                                 │
│  System:                                                        │
│    ✅ Detects: context_type = 'personal', group = NULL        │
│    ✅ Validates: Personal key exists (Alice ↔ Bob personal)   │
│    ✅ Encrypts file with AES-256-GCM                           │
│    ✅ Wraps AES key with Bob's PERSONAL key                   │
│       - Uses Bob's personal key (not group key!)              │
│    ✅ Stores encrypted file                                    │
│                                                                 │
│  Result: File uploaded successfully with personal key ✅       │
└────────────────────────────────────────────────────────────────┘

KEY OBSERVATION:
  Bob received two files from Alice:
    1. team_report.pdf → Encrypted with Team group key
    2. personal_project.doc → Encrypted with personal key
    
  These are SEPARATE keys! Different contexts, different security.
```

---

## Code Flow Example

```python
# Scenario: Alice uploads file to "Team" group (includes Bob, Carol, Dave)

# 1. Upload view detects context
selected_group_id = request.POST.get('group')  # "10" (Team ID)
selected_group = UserGroup.objects.get(id=10, created_by=Alice)
context_type = 'group'

# 2. Validate BB84 sessions
for recipient in [Bob, Carol, Dave]:
    session = BB84Session.objects.filter(
        Q(sender=Alice, receiver=recipient) | 
        Q(sender=recipient, receiver=Alice),
        status='completed',
        context_type='group',      # ← Must be group!
        group=selected_group       # ← Must be Team!
    ).first()
    
    if not session:
        # Missing group key!
        redirect('establish_group_keys', group_id=10)

# 3. Encrypt file
aes_key, nonce, ciphertext = aes_encrypt_file(file_data)

# 4. Wrap AES key for each recipient (using GROUP keys)
for recipient in [Bob, Carol, Dave]:
    # Get group-context session
    session = BB84Session.objects.filter(
        Q(sender=Alice, receiver=recipient) | 
        Q(sender=recipient, receiver=Alice),
        status='completed',
        context_type='group',
        group=selected_group
    ).first()
    
    # Use GROUP shared key (not personal!)
    shared_key = session.shared_key  # e.g., 0xABCD for Bob
    wrapped_key = wrap_aes_key(aes_key, shared_key)
    
    # Store wrapped key
    encrypted_file.add_wrapped_key_for_user(
        recipient.email,
        wrapped_key,
        key_nonce
    )

# 5. Save encrypted file
encrypted_file.save()
```

---

*Architecture Document*
*Version: 1.0*
*Date: 2025-10-07*
