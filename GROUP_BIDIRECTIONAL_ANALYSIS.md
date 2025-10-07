# Group Key Management - Thought Process & Design Decision

## Your Question
> "Does group need bidirection? As group is managed by each user for themself, so A cannot see B's group even if the account is in a group."

## ⚠️ UPDATED REQUIREMENT
> "When we make a group to share with, make sure the key is shared for group. So it should be for group User A has group 'Team' with members [B, C, D]: A->B(group key), A->C(group key), A->D(group key). This group bb84 key does not overlap with the normal A ↔ B sessions."

**Key Insight**: User wants **SEPARATE BB84 sessions for group context vs. individual context**!

```
Individual Sessions (one-on-one):
  A ↔ B (personal)     Used when: A sends file to B individually
  A ↔ C (personal)     Used when: A sends file to C individually
  A ↔ D (personal)     Used when: A sends file to D individually

Group Sessions (group context):
  A ↔ B (Team group)   Used when: A sends file to "Team" group (includes B)
  A ↔ C (Team group)   Used when: A sends file to "Team" group (includes C)
  A ↔ D (Team group)   Used when: A sends file to "Team" group (includes D)

Security Benefit: Compromise of group key doesn't affect personal communications!
```

## Current Group Implementation Analysis

### How Groups Work Now:

```python
class UserGroup(models.Model):
    created_by = ForeignKey(QuantumUser)  # Who owns this group
    members = ManyToManyField(QuantumUser)  # Who's in the group
```

**Key Points**:
1. **Groups are PRIVATE** - Only the creator can see/edit their own groups
2. **Groups are just SHORTCUTS** - When you upload to a group, the system expands it to individual users
3. **No "Group Keys"** exist - Files are encrypted individually for each member

### Example Scenario:

```
User A creates group "Team":
  - Members: [B, C, D]
  - Only A can see this group
  - A's groups: ["Team"]

User B creates group "Friends":
  - Members: [A, C]
  - Only B can see this group
  - B's groups: ["Friends"]

User A uploads file.pdf to group "Team":
  - System expands: recipients = [B, C, D]
  - System encrypts file with AES
  - System wraps AES key separately for B, C, and D
  - Three individual encryptions, not one group key
```

---

## The Bidirectional Question for Groups

### Scenario: Does bidirectional matter?

**Setup**:
```
User A has group "Team" with members [B, C, D]

UPDATED REQUIREMENT - Two Types of Sessions:

1. Individual Sessions (bidirectional):
   A ↔ B (personal)
   A ↔ C (personal)
   A ↔ D (personal)
   Used for: One-on-one file sharing

2. Group Sessions (NEW - context-specific):
   A ↔ B (Team group context)
   A ↔ C (Team group context)
   A ↔ D (Team group context)
   Used for: Files shared via "Team" group
```

**Question**: Should User B be able to upload to User A using A's group?

### Answer: **NO - Groups Should NOT Be Bidirectional**

**But groups DO need separate keys!**

Here's why:

---

## My POV (Point of View) - Three Arguments

### 1️⃣ **Semantic Argument: Groups Are Personal Contact Lists**

**Groups = Address Book**:
```
User A's "Team" group = A's personal label for [B, C, D]
  ↓
This is A's organizational system
  ↓
B doesn't know A calls them "Team"
  ↓
B has their own groups for their own purposes
```

**Real-world analogy**:
- Your phone's contact group "Work" is YOUR label
- Your coworker doesn't see your "Work" group
- They have their own "Work" group with different people
- You don't upload files to "their group" - you upload to individual people

**Verdict**: Groups are **user-specific shortcuts**, not **shared entities**

---

### 2️⃣ **Security Argument: Avoid Permission Confusion**

**Current (correct) flow**:
```
User A uploads to group "Team" [B, C, D]
  ↓
System checks: Does A have BB84 session with B? ✅
System checks: Does A have BB84 session with C? ✅
System checks: Does A have BB84 session with D? ✅
  ↓
All clear → Encrypt separately for each user
```

**If we made groups bidirectional (WRONG)**:
```
User B tries to upload using A's "Team" group
  ↓
Problem 1: How does B know A's group exists?
Problem 2: Should B be able to use A's group membership list?
Problem 3: What if A's group includes user E who hasn't exchanged keys with B?
  ↓
Security nightmare: B trying to send to E without B↔E session
```

**Verdict**: Bidirectional groups would **break permission model**

---

### 3️⃣ **Implementation Argument: Groups Are Just UI Sugar**

**Under the hood, groups DON'T exist in encryption**:
```python
# When A uploads to group "Team":
group = UserGroup.objects.get(name="Team", created_by=A)
members = group.members.all()  # [B, C, D]

# System immediately converts to individual recipients:
for member in members:
    # Check A ↔ member session (BIDIRECTIONAL here is correct!)
    session = BB84Session.objects.filter(
        Q(sender=A, receiver=member) | Q(sender=member, receiver=A),
        status='completed'
    )
    
    # Encrypt for THIS specific user
    wrap_key_for_user(member)
```

**What groups ARE**:
- UI convenience feature
- Batch recipient selector
- Personal organization tool

**What groups ARE NOT**:
- Shared entities
- Permission groups
- Encryption containers

**Verdict**: Groups **expand to individuals**, so bidirectionality applies to **USER sessions**, not group objects

---

## The Correct Fix

### What DOES need bidirectional support:

✅ **Individual BB84 Sessions** (already fixed):
```
A ↔ B (personal) session works both ways:
  - A can upload to B ✅
  - B can upload to A ✅
```

### What ALSO needs implementation (NEW REQUIREMENT):

✅ **Group-Specific BB84 Sessions** (TO BE IMPLEMENTED):
```
A creates group "Team" [B, C, D]:
  - Establish A ↔ B (Team context) session
  - Establish A ↔ C (Team context) session
  - Establish A ↔ D (Team context) session

These are SEPARATE from personal sessions!

Example:
  Personal: A sends file to B individually → Uses A ↔ B (personal)
  Group:    A sends file to "Team" group   → Uses A ↔ B (Team group)
  
Same users, different encryption keys, different contexts!
```

### What does NOT need bidirectional support:

❌ **Group objects themselves**:
```
A's group "Team" [B, C, D]:
  - A can upload to this group ✅
  - B CANNOT upload "to A's group" ❌ (doesn't make sense)
  - B can upload to A individually ✅ (using A↔B personal session)
```

---

## Why Separate Group Keys? (Security Benefits)

### Compartmentalization:
```
Scenario: A shares files with B in two contexts

Context 1 - Personal:
  A → B (personal project.doc)
  Uses: A ↔ B (personal) key
  
Context 2 - Team Group:
  A → Team (team_report.pdf, includes B)
  Uses: A ↔ B (Team group) key

Security Benefit:
  If Team group key is compromised → Personal communications safe ✅
  If Personal key is compromised → Team communications safe ✅
  
Separate keys = Damage containment!
```

### Real-World Analogy:
```
Think of it like different chat rooms:

Personal DM:        Uses password #1
Team Group Chat:    Uses password #2
Family Group Chat:  Uses password #3

Same people, different encryption contexts!
```

---

## Practical Example

### Scenario:
```
User A creates group "Family": [Mom, Dad, Sister]
User B (Mom) creates group "Kids": [A, Sister]

A uploads photo.jpg to "Family":
  ✅ System sends to Mom, Dad, Sister individually
  ✅ Uses A↔Mom, A↔Dad, A↔Sister sessions

Mom uploads recipe.pdf to "Kids":
  ✅ System sends to A, Sister individually
  ✅ Uses Mom↔A, Mom↔Sister sessions
  ✅ Mom does NOT need access to A's "Family" group
```

**Each person manages their own groups for their own uploads**

---

## What ACTUALLY Needs Fixing?

### The Real Issue (UPDATED):

When User A uploads to their group "Team" [B, C, D], the system needs to:

1. ✅ Check if **A has BB84 sessions** with B, C, D (individually) in **group context**
2. ✅ Sessions should be **bidirectional** (A↔B works both ways)
3. ✅ Sessions should be **permanent** (already fixed)
4. ✅ Sessions should be **reusable** (already fixed)
5. ⚠️ **NEW**: Sessions should be **context-aware** (group vs. personal)

### Implementation Requirements:

#### 1. **Modify BB84Session Model**
Add a `context` field to distinguish session types:

```python
class BB84Session(models.Model):
    # Existing fields...
    session_id = models.UUIDField(...)
    sender = models.ForeignKey(...)
    receiver = models.ForeignKey(...)
    shared_key = models.BinaryField(...)
    status = models.CharField(...)
    
    # NEW: Context field
    context_type = models.CharField(
        max_length=20,
        choices=[
            ('personal', 'Personal (one-on-one)'),
            ('group', 'Group Context')
        ],
        default='personal',
        help_text="Whether this session is for personal or group communication"
    )
    
    # NEW: Optional group reference (null for personal sessions)
    group = models.ForeignKey(
        UserGroup,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        help_text="Group this session belongs to (null for personal sessions)"
    )
    
    class Meta:
        # Ensure unique session per user pair per context
        unique_together = [
            ['sender', 'receiver', 'context_type', 'group']
        ]
```

#### 2. **Group Creation Workflow**
When user creates a group, automatically establish group-context sessions:

```python
def create_group_with_sessions(creator, name, members):
    # Step 1: Create the group
    group = UserGroup.objects.create(
        name=name,
        created_by=creator
    )
    group.members.set(members)
    
    # Step 2: Establish BB84 sessions for each member (group context)
    for member in members:
        if member != creator:
            # Create pending session
            session = BB84Session.objects.create(
                sender=creator,
                receiver=member,
                status='pending',
                context_type='group',  # Group context!
                group=group             # Link to group
            )
            # User must accept and run BB84 protocol
    
    return group
```

#### 3. **Upload Validation (Updated)**
Check for group-context sessions when uploading to groups:

```python
# In upload_file_view:
if uploading_to_group:
    group = UserGroup.objects.get(id=group_id, created_by=request.user)
    
    for member in group.members.all():
        # Check for GROUP-CONTEXT session (not personal!)
        valid_session = BB84Session.objects.filter(
            Q(sender=request.user, receiver=member) |
            Q(sender=member, receiver=request.user),
            status='completed',
            context_type='group',    # Must be group context!
            group=group              # Must be for THIS group!
        ).exists()
        
        if not valid_session:
            # Redirect to establish group keys
            messages.error(f"Establish group keys with {member.email}")
            return redirect('establish_group_keys', group_id=group.id)

else:
    # Personal upload - use personal sessions
    for recipient in recipients:
        valid_session = BB84Session.objects.filter(
            Q(sender=request.user, receiver=recipient) |
            Q(sender=recipient, receiver=request.user),
            status='completed',
            context_type='personal'  # Personal context!
        ).exists()
```

#### 4. **Key Wrapping (Updated)**
Use the correct context key when encrypting:

```python
if upload_context == 'group':
    # Use group-specific key
    session = BB84Session.objects.get(
        Q(sender=request.user, receiver=recipient) |
        Q(sender=recipient, receiver=request.user),
        status='completed',
        context_type='group',
        group=selected_group
    )
else:
    # Use personal key
    session = BB84Session.objects.get(
        Q(sender=request.user, receiver=recipient) |
        Q(sender=recipient, receiver=request.user),
        status='completed',
        context_type='personal'
    )

shared_key = session.shared_key
wrapped_key = wrap_aes_key(aes_key, shared_key)
```

---

## Updated Architecture

### Database Schema Changes:

```sql
-- BB84Session table (modified)
CREATE TABLE bb84_sessions (
    session_id UUID PRIMARY KEY,
    sender_id INT REFERENCES users(id),
    receiver_id INT REFERENCES users(id),
    shared_key BYTEA,
    status VARCHAR(20),
    context_type VARCHAR(20) DEFAULT 'personal',  -- NEW
    group_id INT REFERENCES user_groups(id),      -- NEW (nullable)
    created_at TIMESTAMP,
    -- Unique constraint
    UNIQUE(sender_id, receiver_id, context_type, group_id)
);
```

### Session Types:

```
Type 1: Personal Sessions
  sender: A
  receiver: B
  context_type: 'personal'
  group: NULL
  
Type 2: Group Sessions
  sender: A
  receiver: B
  context_type: 'group'
  group: Team (ID=5)
  
Both can exist simultaneously for same user pair!
```

---

## Example Scenarios

### Scenario 1: User A has both session types with User B

```python
# Personal session
BB84Session.objects.create(
    sender=A,
    receiver=B,
    status='completed',
    context_type='personal',
    group=None,
    shared_key=b'personal_key_xyz'
)

# Group session (Team)
BB84Session.objects.create(
    sender=A,
    receiver=B,
    status='completed',
    context_type='group',
    group=team_group,
    shared_key=b'team_group_key_abc'
)

# Group session (Family)
BB84Session.objects.create(
    sender=A,
    receiver=B,
    status='completed',
    context_type='group',
    group=family_group,
    shared_key=b'family_group_key_def'
)
```

### Scenario 2: File Upload Contexts

```python
# Upload 1: Personal file to B
A selects: [B] (individual)
System uses: personal session (personal_key_xyz)

# Upload 2: Team file (includes B)
A selects: "Team" group
System uses: group session for Team (team_group_key_abc)

# Upload 3: Family photo (includes B)
A selects: "Family" group
System uses: group session for Family (family_group_key_def)

Same recipient, three different keys!
```

---

## Current Code Status vs. Required Changes

### ✅ Already Implemented:
1. Bidirectional session lookup
2. Permanent (no expiration) keys
3. Reusable keys (multiple files)
4. Upload recipient lookup (bidirectional)

### ⚠️ Needs Implementation:
1. `context_type` field in BB84Session model
2. `group` foreign key in BB84Session model
3. Group creation workflow (auto-establish group keys)
4. Upload validation (check group-context sessions)
5. Key wrapping (use correct context key)
6. UI for "Establish Group Keys" flow
7. Migration script to mark existing sessions as 'personal'

---

## What ACTUALLY Needs Fixing?

### Code Changes Required:

```python
# In upload_file_view (lines 395-450)
for recipient in recipient_users:
    valid_session = BB84Session.objects.filter(
        Q(sender=request.user, receiver=recipient) |
        Q(sender=recipient, receiver=request.user),  # ✅ Already bidirectional!
        status='completed'
    ).order_by('-created_at').first()
```

**This code ALREADY supports groups correctly**:
- When you select a group, it expands to individual users
- For each user, it checks bidirectional sessions
- No special "group key" logic needed

---

## Design Decision Summary

### ✅ Updated Design:

1. **Groups remain private** - Only creator sees them
2. **Groups are UI shortcuts** - Expand to individual recipients
3. **BB84 sessions are bidirectional** - A↔B works both ways
4. **BB84 sessions are context-aware** - Personal vs. Group (NEW!)
5. **Multiple contexts supported** - Same users, different keys per group

### ✅ Implementation Needed:

1. **Database Changes**:
   - Add `context_type` field to BB84Session
   - Add `group` foreign key to BB84Session
   - Add unique constraint on (sender, receiver, context_type, group)
   - Migration to mark existing sessions as 'personal'

2. **Backend Logic**:
   - Group creation triggers BB84 session establishment
   - Upload validation checks correct context
   - Key wrapping uses context-appropriate session

3. **UI Changes**:
   - "Establish Group Keys" workflow
   - Show group key status (pending/complete)
   - Distinguish personal vs. group sessions in session list

### ❌ Do NOT implement:

1. ~~Shared groups~~ - Would break privacy model
2. ~~Bidirectional group access~~ - Semantically incorrect

---

## Code Changes Needed: **MAJOR IMPLEMENTATION REQUIRED**

**Previous Assessment**: No changes needed
**Updated Assessment**: Significant changes needed for context-aware sessions

### Required Changes:

#### 1. Model Changes (core/models.py)
```python
class BB84Session(models.Model):
    # Add new fields
    context_type = models.CharField(max_length=20, choices=..., default='personal')
    group = models.ForeignKey(UserGroup, null=True, blank=True, on_delete=models.CASCADE)
    
    class Meta:
        unique_together = [['sender', 'receiver', 'context_type', 'group']]
```

#### 2. Migration Script
```python
# migrations/xxxx_add_session_context.py
def migrate_existing_sessions(apps, schema_editor):
    BB84Session = apps.get_model('core', 'BB84Session')
    # Mark all existing sessions as 'personal'
    BB84Session.objects.all().update(context_type='personal')
```

#### 3. Group Creation View (core/views.py)
```python
@login_required
def create_group_view(request):
    if request.method == 'POST':
        # Create group
        group = UserGroup.objects.create(...)
        
        # Establish pending BB84 sessions for each member
        for member in group.members.all():
            BB84Session.objects.create(
                sender=request.user,
                receiver=member,
                status='pending',
                context_type='group',
                group=group
            )
        
        messages.info("Group created. Establish keys with members.")
        return redirect('establish_group_keys', group.id)
```

#### 4. Upload Validation (core/views.py)
```python
# Check context-appropriate sessions
if uploading_to_group:
    context_type = 'group'
    group_obj = selected_group
else:
    context_type = 'personal'
    group_obj = None

valid_session = BB84Session.objects.filter(
    Q(sender=request.user, receiver=recipient) |
    Q(sender=recipient, receiver=request.user),
    status='completed',
    context_type=context_type,
    group=group_obj  # NULL for personal, group ID for group uploads
).exists()
```

---

## Testing Scenario (Updated)

### Test Case: Group Upload with Context-Specific Sessions

**Setup**:
```
User A creates group "Test Group": [B, C]
System creates pending group-context sessions:
  - A ↔ B (group: Test Group, status: pending)
  - A ↔ C (group: Test Group, status: pending)

User B accepts and completes BB84:
  - A ↔ B (group: Test Group, status: completed) ✅
  
User C accepts and completes BB84:
  - A ↔ C (group: Test Group, status: completed) ✅

Separately, A also has personal sessions:
  - A ↔ B (personal, status: completed) ✅
  - A ↔ C (personal, status: completed) ✅
```

**Test 1: Upload to Group**:
```
User A uploads file.pdf to "Test Group"
System checks: context_type='group', group=Test Group
Finds: A ↔ B (group), A ↔ C (group)
Result: ✅ Success, uses GROUP keys
```

**Test 2: Upload to Individual**:
```
User A uploads photo.jpg to B individually
System checks: context_type='personal', group=NULL
Finds: A ↔ B (personal)
Result: ✅ Success, uses PERSONAL key
```

**Expected Result**:
```
✅ Two files encrypted for B with DIFFERENT keys
✅ file.pdf uses group key (Team context)
✅ photo.jpg uses personal key (individual context)
✅ Key compromise in one context doesn't affect other
```

---

## Final Recommendation

### DO: **Implement Context-Aware Sessions** ✅

The NEW requirement changes everything:
- Groups need separate encryption keys from personal communications
- BB84 sessions must track context (personal vs. group)
- Upload validation must check appropriate context
- Security benefit: Compartmentalization (key compromise contained)

### Implementation Priority:

1. **Phase 1: Database (Critical)**
   - Add `context_type` and `group` fields to BB84Session
   - Create migration script
   - Update unique constraints

2. **Phase 2: Backend Logic (Critical)**
   - Modify group creation to establish group keys
   - Update upload validation for context checking
   - Update key wrapping to use correct context

3. **Phase 3: UI (Important)**
   - Add "Establish Group Keys" workflow
   - Show group key status in group management
   - Distinguish session types in key exchange page

4. **Phase 4: Testing (Critical)**
   - Test personal vs. group key separation
   - Test bidirectional + context combinations
   - Test key reuse within same context

### DON'T: Create bidirectional group access ❌

Groups remain private to creator - only the session context changes.

---

## TL;DR

**Original intuition**: Groups don't need special handling
**UPDATED requirement**: Groups NEED separate keys for security compartmentalization!

### What Changed:

**Before (Old Understanding)**:
```
Personal: A → B (key_1)
Group:    A → "Team" (includes B, uses same key_1)

One key per user pair.
```

**After (NEW Requirement)**:
```
Personal: A → B (personal_key)
Group:    A → "Team" group (uses team_group_key with B)

Multiple keys per user pair based on context!
```

### Benefits:

1. ✅ **Security Compartmentalization**: Compromise of group key doesn't leak to personal chats
2. ✅ **Audit Trail**: Can track which files were group vs. personal
3. ✅ **Granular Control**: Can revoke group access without affecting personal
4. ✅ **Future-Proof**: Supports multiple groups with same members

### Implementation Required:

- **Database schema changes** (add context fields)
- **Migration script** (mark existing as personal)
- **Backend logic** (context-aware validation)
- **UI updates** (establish group keys workflow)
- **Testing** (verify separation works)

---

## Next Steps

**Question for you**: Should we proceed with implementing context-aware BB84 sessions? This is a significant change that requires:

1. Database migration (adds new fields)
2. Backend refactoring (context-aware logic)
3. UI additions (group key establishment)
4. Thorough testing (personal vs. group separation)

**Estimated effort**: 
- Development: 4-6 hours
- Testing: 2-3 hours
- Total: ~1 full day

**Do you want me to proceed with this implementation?** 🚀
