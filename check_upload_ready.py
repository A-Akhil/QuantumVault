#!/usr/bin/env python
"""Check BB84 session availability for file upload"""
import os, sys, django

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'quantum_storage.settings')
django.setup()

from core.models import BB84Session, QuantumUser
from django.utils import timezone

sender = QuantumUser.objects.get(email='akhilarul324@gmail.com')
receiver = QuantumUser.objects.get(email='akhil1@gmail.com')

print("="*70)
print("BB84 SESSION AVAILABILITY CHECK")
print("="*70)

print(f"\nSender: {sender.email}")
print(f"Receiver: {receiver.email}")

# Get all sessions
all_sessions = BB84Session.objects.filter(
    sender=sender,
    receiver=receiver
).order_by('-created_at')

print(f"\n📊 Total sessions: {all_sessions.count()}")

for session in all_sessions:
    print(f"\n{'='*70}")
    print(f"Session ID: {session.session_id}")
    print(f"Status: {session.status}")
    print(f"Created: {session.created_at}")
    print(f"Completed: {session.completed_at}")
    print(f"File linked: {'YES - ' + str(session.file.filename) if session.file else 'NO (available for upload)'}")
    print(f"Expired: {session.is_expired()}")
    print(f"Sifted bits: {session.sifted_key_length}")
    print(f"Error rate: {session.error_rate}")
    
    # Check if usable for file upload
    is_usable = (
        session.status == 'completed' and
        session.file is None and
        not session.is_expired()
    )
    print(f"✅ Usable for file upload: {'YES' if is_usable else 'NO'}")

# Now check what the upload view would find
print(f"\n{'='*70}")
print("WHAT UPLOAD VIEW SEES:")
print("="*70)

valid_session = BB84Session.objects.filter(
    sender=sender,
    receiver=receiver,
    status='completed',
    file__isnull=True
).order_by('-created_at').first()

if valid_session:
    print(f"✅ Found valid session: {valid_session.session_id}")
    print(f"   Status: {valid_session.status}")
    print(f"   Expired: {valid_session.is_expired()}")
    print(f"   Can upload: {'YES' if not valid_session.is_expired() else 'NO (expired)'}")
else:
    print("❌ No valid session found!")
    print("   Reason: No completed sessions without file link")
    print("\n💡 SOLUTION: Complete a new BB84 key exchange!")
