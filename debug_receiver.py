#!/usr/bin/env python
"""Debug receiver sessions view"""
import os, sys, django

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'quantum_storage.settings')
django.setup()

from core.models import BB84Session, QuantumUser

# Get the receiver
receiver = QuantumUser.objects.get(email='akhil1@gmail.com')
print(f"Receiver: {receiver.username} ({receiver.email}) [ID: {receiver.id}]")

# Query exactly like the view does
received_sessions = BB84Session.objects.filter(
    receiver=receiver
).select_related('sender', 'file').order_by('-created_at')

print(f"\nReceived sessions count: {received_sessions.count()}")

for session in received_sessions:
    print(f"\nSession: {session.session_id}")
    print(f"  From: {session.sender.email}")
    print(f"  Status: {session.status}")
    print(f"  Receiver Accepted: {session.receiver_accepted}")
    print(f"  Should show Accept button: {session.status == 'pending' and not session.receiver_accepted}")
