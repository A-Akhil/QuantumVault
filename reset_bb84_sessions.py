#!/usr/bin/env python
"""
Reset BB84 Session Data Script
===============================

This script clears all BB84 Key Exchange Sessions and Active Eavesdroppers
from the database, allowing for clean testing of the BB84 workflow.

Usage:
    python reset_bb84_sessions.py [--all]

Options:
    --all    Also delete all audit logs related to BB84 sessions
"""

import os
import sys
import django

# Setup Django environment
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'quantum_storage.settings')
django.setup()

from core.models import BB84Session, ActiveEavesdropper, AuditLog
from django.db import transaction


def print_banner():
    """Print script banner"""
    print("=" * 70)
    print("BB84 Session Data Reset Utility")
    print("=" * 70)
    print()


def print_current_stats():
    """Display current database statistics"""
    bb84_count = BB84Session.objects.count()
    eve_count = ActiveEavesdropper.objects.count()
    active_eve = ActiveEavesdropper.get_active()
    bb84_audit_count = AuditLog.objects.filter(action__icontains='bb84').count()
    
    print("📊 Current Database Statistics:")
    print(f"   • BB84 Sessions: {bb84_count}")
    print(f"   • Active Eavesdroppers: {eve_count}")
    print(f"   • Currently Active Eve: {'YES' if active_eve else 'NO'}")
    print(f"   • BB84 Audit Logs: {bb84_audit_count}")
    print()
    
    return bb84_count, eve_count, bb84_audit_count


def show_bb84_sessions():
    """Show detailed BB84 session breakdown"""
    sessions = BB84Session.objects.all()
    
    if not sessions:
        print("   No BB84 sessions found.")
        return
    
    print("   BB84 Sessions Breakdown:")
    status_counts = {}
    for session in sessions:
        status_counts[session.status] = status_counts.get(session.status, 0) + 1
    
    for status, count in sorted(status_counts.items()):
        print(f"      - {status}: {count}")
    
    # Show intercepted sessions
    intercepted = sessions.filter(eavesdropper_present=True).count()
    detected = sessions.filter(eavesdropper_present=True, error_rate__gt=0.15).count()
    
    print(f"      - Intercepted by Eve: {intercepted}")
    print(f"      - Detections: {detected}")
    print()


def show_eavesdroppers():
    """Show active eavesdropper details"""
    eavesdroppers = ActiveEavesdropper.objects.all()
    
    if not eavesdroppers:
        print("   No eavesdroppers found.")
        return
    
    print("   Eavesdropper Details:")
    for eve in eavesdroppers:
        status_icon = "🔴" if eve.is_active else "⚪"
        print(f"      {status_icon} ID: {eve.eavesdropper_id}")
        print(f"         Injected by: {eve.injected_by}")
        print(f"         Active: {eve.is_active}")
        print(f"         Sessions Intercepted: {eve.sessions_intercepted}")
        print(f"         Qubits Intercepted: {eve.total_qubits_intercepted}")
        print(f"         Detections: {eve.detections_count}")
        print()


def reset_bb84_sessions(delete_audit=False):
    """
    Reset all BB84 session data
    
    Args:
        delete_audit: If True, also delete audit logs
    """
    print("🗑️  Resetting BB84 Session Data...")
    print()
    
    with transaction.atomic():
        # Delete BB84 sessions
        bb84_deleted = BB84Session.objects.all().delete()
        print(f"   ✓ Deleted {bb84_deleted[0]} BB84 sessions")
        
        # Delete active eavesdroppers
        eve_deleted = ActiveEavesdropper.objects.all().delete()
        print(f"   ✓ Deleted {eve_deleted[0]} eavesdroppers")
        
        # Optionally delete audit logs
        if delete_audit:
            audit_deleted = AuditLog.objects.filter(action__icontains='bb84').delete()
            print(f"   ✓ Deleted {audit_deleted[0]} BB84 audit logs")
        
        print()
        print("✅ Database reset complete!")


def main():
    """Main script execution"""
    print_banner()
    
    # Check command line arguments
    delete_audit = '--all' in sys.argv
    
    if delete_audit:
        print("⚠️  Running in FULL RESET mode (including audit logs)")
        print()
    
    # Show current statistics
    print_current_stats()
    show_bb84_sessions()
    show_eavesdroppers()
    
    # Confirm deletion
    print("⚠️  WARNING: This will delete all BB84 session data!")
    if delete_audit:
        print("⚠️  This includes all BB84 audit logs!")
    print()
    
    response = input("Are you sure you want to continue? (yes/no): ").strip().lower()
    
    if response not in ['yes', 'y']:
        print("\n❌ Reset cancelled.")
        sys.exit(0)
    
    print()
    
    # Perform reset
    reset_bb84_sessions(delete_audit=delete_audit)
    
    # Show new statistics
    print()
    print("📊 After Reset:")
    print_current_stats()
    
    print()
    print("=" * 70)
    print("🎉 Ready for fresh testing!")
    print("=" * 70)
    print()
    print("Next Steps:")
    print("   1. Start Django server: python manage.py runserver")
    print("   2. Inject eavesdropper: curl -X POST http://localhost:8000/api/eavesdropper/inject/ \\")
    print("      -H 'Content-Type: application/json' \\")
    print("      -d '{\"injected_by\":\"test\",\"intercept_probability\":0.5}'")
    print("   3. Run BB84 sessions from web UI")
    print("   4. View dashboard: http://localhost:8000/eavesdropper/dashboard/")
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Reset cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
