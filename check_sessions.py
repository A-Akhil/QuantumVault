#!/usr/bin/env python
"""Check BB84 session visibility"""
import os, sys, django

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'quantum_storage.settings')
django.setup()

from core.models import BB84Session, QuantumUser

# Find users
users = QuantumUser.objects.all()
print(f"Total users: {users.count()}")
for u in users:
    print(f"  - {u.username} ({u.email})")

print("\n" + "="*70)
print("BB84 Sessions:")
print("="*70)

sessions = BB84Session.objects.all()
if not sessions:
    print("No sessions found!")
else:
    for s in sessions:
        print(f"\nSession ID: {s.session_id}")
        print(f"  Sender: {s.sender.username} ({s.sender.email})")
        print(f"  Receiver: {s.receiver.username} ({s.receiver.email})")
        print(f"  Status: {s.status}")
        print(f"  Receiver Accepted: {s.receiver_accepted}")
        print(f"  Created: {s.created_at}")
